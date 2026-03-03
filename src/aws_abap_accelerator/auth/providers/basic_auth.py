"""
Basic authentication provider with OS Keychain integration
"""

import os
import uuid
import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta

from .base import AuthenticationProvider
from ..types import AuthenticationResult, AuthenticationType, CredentialInfo
from ..keychain_manager import keychain_manager
from sap_types.sap_types import SAPConnection, AuthType
from sap.sap_client import SAPADTClient
from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)


class BasicAuthProvider(AuthenticationProvider):
    """Basic username/password authentication with OS Keychain integration"""
    
    def __init__(self):
        self.name = "Basic Authentication"
        self.description = "Username/password authentication with secure OS keychain storage"
    
    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate using basic username/password with keychain integration
        
        Supports two modes:
        1. Keychain identifier (keychain_identifier) - retrieves from OS keychain
        2. Direct credentials (sap_username, sap_password) - for fallback
        """
        try:
            # Mode 1: Using keychain identifier (preferred)
            if 'keychain_identifier' in credentials:
                return await self._authenticate_with_keychain_identifier(credentials)
            
            # Mode 2: Direct credentials (fallback)
            elif all(key in credentials for key in ['sap_username', 'sap_password']):
                return await self._authenticate_with_direct_credentials(credentials)
            
            else:
                return AuthenticationResult(
                    success=False,
                    error_message="Either 'keychain_identifier' or 'sap_username'+'sap_password' required",
                    auth_type=self.get_auth_type()
                )
                
        except Exception as e:
            logger.error(f"Basic authentication error: {sanitize_for_logging(str(e))}")
            return AuthenticationResult(
                success=False,
                error_message=f"Authentication failed: {str(e)}",
                auth_type=self.get_auth_type()
            )
    
    async def _authenticate_with_keychain_identifier(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """Authenticate using keychain identifier"""
        keychain_identifier = credentials['keychain_identifier']
        
        # Retrieve credentials from keychain using identifier
        stored_credentials = keychain_manager.get_sap_credentials_by_identifier(keychain_identifier)
        if not stored_credentials:
            return AuthenticationResult(
                success=False,
                error_message=f"No credentials found for identifier '{keychain_identifier}'. Please store your SAP credentials in OS keychain first.",
                auth_type=self.get_auth_type()
            )
        
        # Use stored credentials for authentication
        return await self._perform_sap_authentication(stored_credentials, keychain_identifier)
    
    async def _authenticate_with_direct_credentials(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """Authenticate with direct credentials (fallback mode)"""
        
        # Extract required fields
        required_fields = ['sap_host', 'sap_client', 'sap_username', 'sap_password']
        for field in required_fields:
            if field not in credentials:
                return AuthenticationResult(
                    success=False,
                    error_message=f"Missing required field: {field}",
                    auth_type=self.get_auth_type()
                )
        
        # Perform authentication
        return await self._perform_sap_authentication(credentials)
    
    async def _perform_sap_authentication(self, credentials: Dict[str, Any], 
                                        keychain_identifier: str = None) -> AuthenticationResult:
        """Perform actual SAP system authentication"""
        try:
            # Create SAP connection
            sap_connection = SAPConnection(
                host=credentials['sap_host'],
                client=credentials['sap_client'],
                username=credentials['sap_username'],
                password=credentials['sap_password'],
                language=credentials.get('sap_language', 'EN'),
                secure=True,
                auth_type=AuthType.BASIC
            )
            
            # Test connection
            sap_client = SAPADTClient(sap_connection)
            connected = await sap_client.connect()
            
            if not connected:
                # If basic auth fails, try reentrance ticket authentication for modern SAP systems
                logger.info(f"Basic authentication failed for {credentials['sap_host']}, trying reentrance ticket authentication")
                
                try:
                    from .reentrance_ticket_auth import ReentranceTicketAuthProvider
                    
                    ticket_provider = ReentranceTicketAuthProvider()
                    ticket_result = await ticket_provider.authenticate({
                        'sap_host': credentials['sap_host'],
                        'sap_client': credentials['sap_client'],
                        'sap_username': credentials['sap_username'],
                        'sap_password': credentials['sap_password']
                    })
                    
                    if ticket_result.success:
                        logger.info(f"Successfully authenticated {credentials['sap_username']} using reentrance ticket fallback")
                        # Return the ticket authentication result
                        return ticket_result
                    else:
                        logger.warning(f"Reentrance ticket fallback also failed: {ticket_result.error_message}")
                        
                except Exception as e:
                    logger.warning(f"Reentrance ticket fallback failed: {e}")
                
                return AuthenticationResult(
                    success=False,
                    error_message="Failed to connect to SAP system. Check credentials and network connectivity. Tried both basic and reentrance ticket authentication.",
                    auth_type=self.get_auth_type()
                )
            
            # Extract SAP session tokens (CSRF token and cookies)
            sap_tokens = {
                'csrf_token': sap_client.csrf_token,
                'cookies': sap_client.cookies,
                'base_url': sap_client.base_url,
                'sap_host': credentials['sap_host'],
                'sap_client': credentials['sap_client'],
                'sap_username': credentials['sap_username'],
                'sap_password': credentials['sap_password'],  # Include password for re-authentication
                'sap_language': credentials.get('sap_language', 'EN')
            }
            
            # Add Playwright session cookies if available
            if 'session_cookies' in credentials:
                sap_tokens['session_cookies'] = credentials['session_cookies']
                logger.info(f"Added {len(credentials['session_cookies'])} Playwright cookies to tokens")
            
            # Add CSRF token from Playwright if available (override the basic auth one)
            if 'csrf_token' in credentials and credentials['csrf_token']:
                sap_tokens['csrf_token'] = credentials['csrf_token']
                logger.info(f"Using CSRF token from Playwright: {credentials['csrf_token']}")
            
            # Add authentication method info
            if 'authentication_method' in credentials:
                sap_tokens['authentication_method'] = credentials['authentication_method']
            
            # Close the temporary client (we'll create fresh ones with tokens)
            if hasattr(sap_client, 'session') and sap_client.session:
                await sap_client.session.close()
            
            # Generate session token
            session_token = str(uuid.uuid4())
            
            # Prepare user info with tokens (no passwords stored)
            user_info = {
                'username': credentials['sap_username'],
                'sap_host': credentials['sap_host'],
                'sap_client': credentials['sap_client'],
                'sap_language': credentials.get('sap_language', 'EN'),
                'auth_type': self.get_auth_type().value,
                'sap_tokens': sap_tokens,  # Store tokens for fresh client creation
                'authenticated_at': datetime.now().isoformat()
            }
            
            if keychain_identifier:
                user_info['keychain_identifier'] = keychain_identifier
                user_info['using_keychain'] = True
            
            logger.info(f"Successfully authenticated {credentials['sap_username']}@{credentials['sap_host']} using basic auth")
            
            return AuthenticationResult(
                success=True,
                session_token=session_token,
                user_info=user_info,
                auth_type=self.get_auth_type()
            )
            
        except Exception as e:
            logger.error(f"SAP authentication failed: {sanitize_for_logging(str(e))}")
            return AuthenticationResult(
                success=False,
                error_message=f"SAP authentication failed: {str(e)}",
                auth_type=self.get_auth_type()
            )
    
    async def validate_session(self, session_token: str) -> bool:
        """Validate session token (basic implementation)"""
        # For basic auth, we rely on session manager for validation
        # This could be enhanced with token validation logic
        return len(session_token) > 0
    
    async def refresh_session(self, session_token: str) -> str:
        """Refresh session token (not supported for basic auth)"""
        return None
    
    def get_required_credentials(self) -> List[CredentialInfo]:
        """Get required credential fields for basic authentication"""
        return [
            # Mode 1: Using keychain identifier (preferred)
            CredentialInfo(
                field_name="keychain_identifier",
                description="Identifier for stored keychain credentials (e.g., 'my-sap-dev', 'sap-prod')",
                required=False,
                example="my-sap-dev"
            ),
            
            # Mode 2: Direct credentials (fallback)
            CredentialInfo(
                field_name="sap_host",
                description="SAP system hostname or IP address (fallback if no keychain)",
                required=False,
                example="sap.company.com"
            ),
            CredentialInfo(
                field_name="sap_client",
                description="SAP client number (fallback if no keychain)",
                required=False,
                example="100"
            ),
            CredentialInfo(
                field_name="sap_username",
                description="SAP username (fallback if no keychain)",
                required=False,
                sensitive=True,
                example="DEVELOPER001"
            ),
            CredentialInfo(
                field_name="sap_password",
                description="SAP password (fallback if no keychain)",
                required=False,
                sensitive=True,
                example="********"
            ),
            CredentialInfo(
                field_name="sap_language",
                description="SAP language code (optional)",
                required=False,
                example="EN"
            )
        ]
    
    def get_auth_type(self) -> AuthenticationType:
        """Get authentication type"""
        return AuthenticationType.BASIC
    
    def get_display_name(self) -> str:
        """Get display name"""
        return "Basic Authentication (Username/Password)"
    
    def supports_refresh(self) -> bool:
        """Basic auth doesn't support refresh"""
        return False