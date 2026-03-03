"""
MCP tools for authentication functionality
These tools are segregated to avoid impacting existing functionality
"""

import os
import logging
from typing import Dict, Any, Optional

from mcp.server.fastmcp import Context
from .session_manager import auth_session_manager
from .keychain_manager import keychain_manager
from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)


def get_mcp_session_id(ctx: Context = None) -> str:
    """
    Get MCP session ID from context or use a global session ID for HTTP MCP servers
    This ensures proper session isolation between different MCP clients
    """
    # Try to get session ID from MCP context if available
    if ctx and ctx.request_context and hasattr(ctx.request_context, 'request'):
        request = ctx.request_context.request
        if hasattr(request, 'headers'):
            session_id = request.headers.get("mcp-session-id")
            if session_id:
                logger.info(f"Found MCP session ID in headers: {session_id}")
                return session_id
    
    # Fallback to global session for HTTP MCP servers
    return "global_http_session"


def get_keychain_identifier_from_headers(ctx: Context = None):
    """
    Get keychain identifier from HTTP headers if available
    This allows auto-authentication without manual tool calls
    """
    # First try to get from MCP request context if available
    if ctx and ctx.request_context and hasattr(ctx.request_context, 'request'):
        request = ctx.request_context.request
        if hasattr(request, 'headers'):
            # Debug: log all headers
            logger.info(f"Available headers: {list(request.headers.keys())}")
            
            keychain_id = request.headers.get("X-SAP-Keychain-Identifier")
            if keychain_id:
                logger.info(f"Found keychain identifier in request headers: {sanitize_for_logging(keychain_id)}")
                return keychain_id
            else:
                logger.info("X-SAP-Keychain-Identifier header not found in request")
    else:
        logger.info("No request context available for header processing")
    
    # Fallback to environment variable (can be set by Q Developer via headers)
    env_keychain = os.getenv('X_SAP_KEYCHAIN_IDENTIFIER')
    if env_keychain:
        logger.info(f"Using keychain identifier from environment: {sanitize_for_logging(env_keychain)}")
    else:
        logger.info("No keychain identifier found in environment variables")
    
    return env_keychain


def get_authentication_type_from_headers(ctx: Context = None):
    """
    Get preferred authentication type from HTTP headers if available
    This allows Q Developer to specify which auth method to use
    """
    # First try to get from MCP request context if available
    if ctx and ctx.request_context and hasattr(ctx.request_context, 'request'):
        request = ctx.request_context.request
        if hasattr(request, 'headers'):
            auth_type = request.headers.get("X-SAP-Authentication-Type")
            if auth_type:
                # Normalize the auth type
                auth_type = auth_type.lower().strip()
                if auth_type in ['basic', 'playwright', 'browser', 'reentrance_ticket', 'ticket']:
                    logger.info(f"Found authentication type in request headers: {auth_type}")
                    return auth_type
    
    # Fallback to environment variable (can be set by Q Developer via headers)
    auth_type = os.getenv('X_SAP_AUTHENTICATION_TYPE')
    if auth_type:
        # Normalize the auth type
        auth_type = auth_type.lower().strip()
        if auth_type in ['basic', 'playwright', 'browser', 'reentrance_ticket', 'ticket']:
            return auth_type
    return None


def set_auth_preferences_from_call(keychain_identifier: str = None, authentication_type: str = None):
    """
    Set authentication preferences from a tool call (simulates header behavior)
    This is a workaround for when headers aren't automatically processed
    """
    import os
    
    if keychain_identifier:
        os.environ['X_SAP_KEYCHAIN_IDENTIFIER'] = keychain_identifier
        logger.info(f"Set keychain identifier via tool call: {sanitize_for_logging(keychain_identifier)}")
    
    if authentication_type:
        auth_type = authentication_type.lower().strip()
        if auth_type in ['basic', 'playwright', 'browser', 'reentrance_ticket', 'ticket']:
            os.environ['X_SAP_AUTHENTICATION_TYPE'] = auth_type
            logger.info(f"Set authentication type via tool call: {auth_type}")
        else:
            logger.warning(f"Invalid authentication type: {authentication_type}")
    
    return keychain_identifier, authentication_type


# Authentication Tools

async def handle_get_supported_auth_types() -> Dict[str, Any]:
    """Get list of supported authentication types"""
    try:
        auth_types = auth_session_manager.get_supported_auth_types()
        
        return {
            "supported_auth_types": auth_types,
            "total_types": len(auth_types),
            "message": "Choose an authentication type and provide the required credentials",
            "keychain_info": keychain_manager.get_storage_info()
        }
        
    except Exception as e:
        logger.error(f"Error getting supported auth types: {sanitize_for_logging(str(e))}")
        return {
            "error": f"Failed to get supported auth types: {str(e)}",
            "supported_auth_types": [],
            "total_types": 0
        }


async def handle_authenticate_user(auth_type: str, credentials: Dict[str, Any], 
                                 session_name: str = "default", ctx: Context = None) -> str:
    """Universal authentication method supporting all auth types"""
    try:
        mcp_session_id = get_mcp_session_id(ctx)
        
        # Check if keychain identifier is provided via headers (Q Developer integration)
        header_keychain_id = get_keychain_identifier_from_headers(ctx)
        if header_keychain_id and not credentials.get('keychain_identifier'):
            logger.info(f"Using keychain identifier from headers: {sanitize_for_logging(header_keychain_id)}")
            credentials = credentials.copy()  # Don't modify original
            credentials['keychain_identifier'] = header_keychain_id
        
        success, message = await auth_session_manager.authenticate_user(
            mcp_session_id, auth_type, credentials, session_name
        )
        
        return message
        
    except Exception as e:
        logger.error(f"Authentication error: {sanitize_for_logging(str(e))}")
        return f"❌ Authentication failed: {str(e)}"


async def handle_list_auth_sessions(ctx: Context = None) -> str:
    """List active authentication sessions for current user"""
    try:
        mcp_session_id = get_mcp_session_id(ctx)
        session_info = auth_session_manager.get_session_info(mcp_session_id)
        
        if session_info["total"] == 0:
            return "No active authentication sessions. Use authenticate_user to authenticate with SAP."
        
        result = f"Active Authentication Sessions ({session_info['total']}):\n\n"
        
        for session in session_info["sessions"]:
            result += f"📋 Session: {session['name']}\n"
            result += f"   Auth Type: {session['auth_type']}\n"
            result += f"   User: {session['username']}@{session['sap_host']} (Client: {session['sap_client']})\n"
            result += f"   Created: {session['created_at']}\n"
            result += f"   Expires: {session['time_remaining']} remaining\n"
            result += f"   Status: {'🔴 Expired' if session['is_expired'] else '🟢 Active'}\n\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing auth sessions: {sanitize_for_logging(str(e))}")
        return f"❌ Error listing sessions: {str(e)}"


# Keychain Management Tools - REMOVED
# Users will manage keychain entries manually using OS tools


# SSO-specific Tools

async def handle_initiate_sso_authentication(sap_host: str, ctx: Context = None) -> Dict[str, str]:
    """Initiate SAML/SSO authentication flow"""
    try:
        mcp_session_id = get_mcp_session_id(ctx)
        
        # Get SSO provider
        sso_provider = auth_session_manager.providers.get(auth_session_manager.AuthenticationType.SAML_SSO)
        if not sso_provider:
            return {
                "error": "SAML/SSO authentication not configured",
                "message": "SSO provider is not available"
            }
        
        # Initiate SSO flow
        sso_info = await sso_provider.initiate_sso_flow(sap_host, mcp_session_id)
        
        return {
            **sso_info,
            "next_step": "Complete authentication in your browser, then call authenticate_user with the SAML response"
        }
        
    except Exception as e:
        logger.error(f"Error initiating SSO authentication: {sanitize_for_logging(str(e))}")
        return {
            "error": f"Failed to initiate SSO: {str(e)}",
            "message": "SSO initiation failed"
        }


# Utility Tools

async def handle_get_keychain_info() -> Dict[str, Any]:
    """Get information about keychain storage capabilities"""
    try:
        return keychain_manager.get_storage_info()
        
    except Exception as e:
        logger.error(f"Error getting keychain info: {sanitize_for_logging(str(e))}")
        return {
            "error": f"Failed to get keychain info: {str(e)}",
            "keyring_available": False
        }


# Fallback function for existing tools
async def get_authenticated_sap_client(mcp_session_id: str = None, session_name: str = "default", ctx: Context = None):
    """
    Get fresh SAP client using cached tokens
    Creates a new client for each request with cached session tokens
    """
    try:
        if not mcp_session_id:
            mcp_session_id = get_mcp_session_id(ctx)
        
        # Check if we have an active session with tokens
        session = auth_session_manager.get_user_session(mcp_session_id, session_name)
        if session and session.sap_tokens:
            username = session.user_info.get('username', 'unknown')
            logger.info(f"Creating fresh SAP client with tokens for {username}")
            
            # Create fresh SAP client using cached tokens
            from .sap_client_factory import SAPClientFactory
            
            sap_client = await SAPClientFactory.create_client_with_tokens(session.sap_tokens)
            
            if sap_client:
                logger.info(f"Fresh SAP client created successfully for {username}")
                return sap_client
            else:
                # Token might be expired, try to refresh if we have keychain identifier
                if session.keychain_identifier:
                    logger.info(f"Tokens failed, attempting refresh from keychain for {username}")
                    
                    new_tokens = await SAPClientFactory.refresh_tokens_from_keychain(
                        session.keychain_identifier, 
                        session.sap_tokens
                    )
                    
                    if new_tokens:
                        # Update session with new tokens
                        session.sap_tokens = new_tokens
                        session.refresh_usage()
                        
                        # Try creating client again with new tokens
                        sap_client = await SAPClientFactory.create_client_with_tokens(new_tokens)
                        if sap_client:
                            logger.info(f"Fresh SAP client created with refreshed tokens for {username}")
                            return sap_client
                
                logger.error(f"Failed to create SAP client with tokens for {username}")
                return None
        
        # Auto-authenticate if keychain identifier is provided via headers
        keychain_identifier = get_keychain_identifier_from_headers()
        if keychain_identifier:
            logger.info(f"Auto-authenticating with keychain identifier from headers: {keychain_identifier}")
            
            # Perform auto-authentication
            success, message = await auth_session_manager.authenticate_user(
                mcp_session_id=mcp_session_id,
                auth_type="basic",
                credentials={'keychain_identifier': keychain_identifier},
                session_name=session_name
            )
            
            if success:
                logger.info(f"Auto-authentication successful: {message}")
                # Recursively call to get the fresh client
                return await get_authenticated_sap_client(mcp_session_id, session_name, ctx)
            else:
                logger.error(f"Auto-authentication failed: {message}")
        
        # No session and no auto-auth available
        return None
        
    except Exception as e:
        logger.error(f"Error getting authenticated SAP client: {sanitize_for_logging(str(e))}")
        return None