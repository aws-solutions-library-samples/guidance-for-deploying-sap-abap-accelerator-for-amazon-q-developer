"""
Authentication session manager with fallback support
"""

import asyncio
import logging
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
import uuid

from .types import UserAuthSession, AuthenticationType
from .providers.basic_auth import BasicAuthProvider
from .providers.saml_sso import SAMLSSOAuthProvider
from .providers.certificate_auth import CertificateAuthProvider
from server.tool_handlers import ToolHandlers
from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)


class AuthenticationSessionManager:
    """
    Manages user authentication sessions with support for multiple auth types
    Includes fallback to legacy authentication for backward compatibility
    """
    
    def __init__(self):
        self.user_sessions: Dict[str, Dict[str, UserAuthSession]] = {}  # mcp_session_id -> {session_name -> UserAuthSession}
        self.providers = {}
        self.cleanup_task = None
        self.session_duration_hours = 9
        
        # Initialize authentication providers
        self._initialize_providers()
        
        # Don't start cleanup task in __init__ - will be started when needed
    
    def _initialize_providers(self):
        """Initialize all authentication providers"""
        try:
            self.providers[AuthenticationType.BASIC] = BasicAuthProvider()
            self.providers[AuthenticationType.SAML_SSO] = SAMLSSOAuthProvider()
            self.providers[AuthenticationType.CERTIFICATE] = CertificateAuthProvider()
            
            # Import and register reentrance ticket provider
            from .providers.reentrance_ticket_auth import ReentranceTicketAuthProvider
            self.providers[AuthenticationType.REENTRANCE_TICKET] = ReentranceTicketAuthProvider()
            
            logger.info(f"Initialized {len(self.providers)} authentication providers")
            
        except Exception as e:
            logger.error(f"Failed to initialize authentication providers: {e}")
    
    def get_supported_auth_types(self) -> List[Dict[str, Any]]:
        """Get list of supported authentication types and their requirements"""
        auth_types = []
        
        for auth_type, provider in self.providers.items():
            try:
                auth_info = {
                    'type': auth_type.value,
                    'display_name': provider.get_display_name(),
                    'supports_refresh': provider.supports_refresh(),
                    'session_duration_hours': provider.get_session_duration_hours(),
                    'required_credentials': []
                }
                
                # Convert CredentialInfo objects to dictionaries
                for cred_info in provider.get_required_credentials():
                    auth_info['required_credentials'].append({
                        'field_name': cred_info.field_name,
                        'description': cred_info.description,
                        'required': cred_info.required,
                        'sensitive': cred_info.sensitive,
                        'example': cred_info.example
                    })
                
                auth_types.append(auth_info)
                
            except Exception as e:
                logger.error(f"Error getting info for auth type {auth_type}: {e}")
        
        return auth_types
    
    async def authenticate_user(self, mcp_session_id: str, auth_type: str, 
                              credentials: Dict[str, Any], session_name: str = "default") -> tuple[bool, str]:
        """
        Authenticate user using specified authentication type
        
        Args:
            mcp_session_id: MCP session identifier
            auth_type: Authentication type (basic, saml_sso, certificate)
            credentials: Authentication credentials
            session_name: Name for this authentication session
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Validate auth type
            try:
                auth_enum = AuthenticationType(auth_type)
            except ValueError:
                return False, f"Unsupported authentication type: {auth_type}"
            
            # Get provider
            provider = self.providers.get(auth_enum)
            if not provider:
                return False, f"Authentication provider not available for type: {auth_type}"
            
            # Authenticate with provider
            result = await provider.authenticate(credentials)
            
            if not result.success:
                logger.warning(f"Authentication failed for {auth_type}: {result.error_message}")
                return False, result.error_message
            
            # Create user session
            session_success = await self._create_user_session(
                mcp_session_id, session_name, result, auth_enum
            )
            
            if session_success:
                user_info = result.user_info or {}
                username = user_info.get('username', 'user')
                sap_host = user_info.get('sap_host', 'unknown')
                
                logger.info(f"Successfully authenticated {username}@{sap_host} using {auth_type}")
                return True, f"✅ Authenticated as {username}@{sap_host} using {auth_type}. Session expires in {self.session_duration_hours} hours."
            else:
                return False, "Failed to create user session"
            
        except Exception as e:
            logger.error(f"Authentication error: {sanitize_for_logging(str(e))}")
            return False, f"Authentication failed: {str(e)}"
    
    async def _create_user_session(self, mcp_session_id: str, session_name: str, 
                                 auth_result, auth_type: AuthenticationType) -> bool:
        """Create user authentication session"""
        try:
            if not auth_result.user_info or 'sap_tokens' not in auth_result.user_info:
                logger.error("Authentication result missing SAP tokens")
                return False
            
            # Generate session ID
            session_id = str(uuid.uuid4())
            now = datetime.now()
            
            # Create session with tokens instead of credentials
            user_session = UserAuthSession(
                session_id=session_id,
                mcp_session_id=mcp_session_id,
                session_name=session_name,
                auth_type=auth_type,
                user_info=auth_result.user_info,
                sap_tokens=auth_result.user_info.get('sap_tokens', {}),
                keychain_identifier=auth_result.user_info.get('keychain_identifier'),
                created_at=now,
                last_used=now,
                expires_at=now + timedelta(hours=self.session_duration_hours)
            )
            
            # Store session
            if mcp_session_id not in self.user_sessions:
                self.user_sessions[mcp_session_id] = {}
            
            self.user_sessions[mcp_session_id][session_name] = user_session
            
            logger.info(f"Created user session {session_id} for {session_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create user session: {sanitize_for_logging(str(e))}")
            return False
    
    def get_user_session(self, mcp_session_id: str, session_name: str = "default") -> Optional[UserAuthSession]:
        """
        Get user authentication session
        
        Args:
            mcp_session_id: MCP session identifier
            session_name: Session name
            
        Returns:
            UserAuthSession or None if not found/expired
        """
        try:
            if mcp_session_id not in self.user_sessions:
                return None
            
            session = self.user_sessions[mcp_session_id].get(session_name)
            if not session:
                return None
            
            # Check if expired
            if session.is_expired():
                logger.info(f"Session {session.session_id} expired, cleaning up")
                # Schedule cleanup for later (can't await in sync method)
                asyncio.create_task(self._cleanup_session(mcp_session_id, session_name))
                return None
            
            # Update last used
            session.refresh_usage()
            return session
            
        except Exception as e:
            logger.error(f"Error getting user session: {sanitize_for_logging(str(e))}")
            return None
    
    async def _cleanup_session(self, mcp_session_id: str, session_name: str):
        """Clean up a specific session"""
        try:
            if mcp_session_id in self.user_sessions and session_name in self.user_sessions[mcp_session_id]:
                session = self.user_sessions[mcp_session_id][session_name]
                
                # Close SAP client connection
                if hasattr(session.sap_client, 'close'):
                    await session.sap_client.close()
                
                # Remove session
                del self.user_sessions[mcp_session_id][session_name]
                
                # Remove MCP session if no more sessions
                if not self.user_sessions[mcp_session_id]:
                    del self.user_sessions[mcp_session_id]
                
                logger.info(f"Cleaned up session {session.session_id}")
                
        except Exception as e:
            logger.error(f"Error cleaning up session: {sanitize_for_logging(str(e))}")
    
    def get_session_info(self, mcp_session_id: str) -> Dict[str, Any]:
        """Get information about user's sessions"""
        try:
            if mcp_session_id not in self.user_sessions:
                return {"sessions": [], "total": 0}
            
            sessions_info = []
            for session_name, session in self.user_sessions[mcp_session_id].items():
                user_info = session.user_info or {}
                
                sessions_info.append({
                    "name": session_name,
                    "auth_type": session.auth_type.value,
                    "username": user_info.get('username', 'unknown'),
                    "sap_host": user_info.get('sap_host', 'unknown'),
                    "sap_client": user_info.get('sap_client', 'unknown'),
                    "created_at": session.created_at.isoformat(),
                    "expires_at": session.expires_at.isoformat(),
                    "time_remaining": str(session.expires_at - datetime.now()),
                    "is_expired": session.is_expired()
                })
            
            return {
                "sessions": sessions_info,
                "total": len(sessions_info)
            }
            
        except Exception as e:
            logger.error(f"Error getting session info: {sanitize_for_logging(str(e))}")
            return {"sessions": [], "total": 0, "error": str(e)}
    
    async def cleanup_expired_sessions(self):
        """Clean up expired sessions periodically"""
        while True:
            try:
                expired_sessions = []
                
                # Find expired sessions
                for mcp_session_id, sessions in self.user_sessions.items():
                    for session_name, session in sessions.items():
                        if session.is_expired():
                            expired_sessions.append((mcp_session_id, session_name))
                
                # Clean up expired sessions
                for mcp_session_id, session_name in expired_sessions:
                    await self._cleanup_session(mcp_session_id, session_name)
                
                if expired_sessions:
                    logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
                
                # Clean up expired SSO requests
                for provider in self.providers.values():
                    if hasattr(provider, 'cleanup_expired_requests'):
                        provider.cleanup_expired_requests()
                
                # Sleep for 30 minutes before next cleanup
                await asyncio.sleep(1800)
                
            except Exception as e:
                logger.error(f"Error in session cleanup: {sanitize_for_logging(str(e))}")
                await asyncio.sleep(300)  # Retry in 5 minutes
    
    def start_cleanup_task(self):
        """Start the cleanup task"""
        if self.cleanup_task is None:
            try:
                self.cleanup_task = asyncio.create_task(self.cleanup_expired_sessions())
                logger.info("Started session cleanup task")
            except RuntimeError:
                # No event loop running - cleanup task will be started later
                logger.info("No event loop running - cleanup task will be started when needed")
                pass
    
    async def stop_cleanup_task(self):
        """Stop the cleanup task"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
            self.cleanup_task = None
            logger.info("Stopped session cleanup task")
    
    # Fallback methods for backward compatibility
    async def authenticate_user_legacy(self, mcp_session_id: str, sap_host: str, sap_client: str,
                                     sap_username: str, sap_password: str, sap_language: str = "EN",
                                     session_name: str = "default") -> tuple[bool, str]:
        """
        Legacy authentication method for backward compatibility
        Uses basic authentication with direct credentials
        """
        logger.info("Using legacy authentication method")
        
        credentials = {
            'sap_host': sap_host,
            'sap_client': sap_client,
            'sap_username': sap_username,
            'sap_password': sap_password,
            'sap_language': sap_language
        }
        
        return await self.authenticate_user(mcp_session_id, 'basic', credentials, session_name)
    
    def get_user_client_legacy(self, mcp_session_id: str, session_name: str = "default"):
        """Legacy method to get SAP client - for backward compatibility"""
        session = self.get_user_session(mcp_session_id, session_name)
        return session.sap_client if session else None


# Global authentication session manager
auth_session_manager = AuthenticationSessionManager()