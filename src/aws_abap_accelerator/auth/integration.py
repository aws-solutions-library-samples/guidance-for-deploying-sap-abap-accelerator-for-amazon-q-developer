"""
Integration module for adding authentication tools to existing MCP server
This module provides a non-breaking way to add authentication functionality
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List

from .mcp_tools import (
    handle_get_supported_auth_types,
    handle_authenticate_user,
    handle_list_auth_sessions,
    handle_initiate_sso_authentication,
    handle_get_keychain_info,
    get_authenticated_sap_client
)

logger = logging.getLogger(__name__)


def register_auth_tools(mcp_server):
    """
    Register authentication tools with the MCP server
    
    Args:
        mcp_server: FastMCP server instance
    """
    try:
        # Authentication Management Tools
        
        @mcp_server.tool()
        async def aws_abap_cb_get_supported_auth_types() -> Dict[str, Any]:
            """Get list of supported authentication types and their requirements"""
            return await handle_get_supported_auth_types()
        
        @mcp_server.tool()
        async def aws_abap_cb_authenticate_user(
            auth_type: str,
            credentials: Dict[str, Any],
            session_name: Optional[str] = "default"
        ) -> str:
            """
            Authenticate user with SAP system using specified authentication type
            
            Supported auth types:
            - basic: Username/password with optional keychain storage
            - saml_sso: SAML/SSO authentication
            - certificate: X.509 certificate authentication
            """
            return await handle_authenticate_user(auth_type, credentials, session_name)
        
        @mcp_server.tool()
        async def aws_abap_cb_list_auth_sessions() -> str:
            """List active authentication sessions for current user"""
            return await handle_list_auth_sessions()
        
        # Keychain Management Tools - REMOVED
        # Users manage keychain entries manually using OS tools
        
        # SSO-specific Tools
        
        @mcp_server.tool()
        async def aws_abap_cb_initiate_sso_authentication(sap_host: str) -> Dict[str, str]:
            """Initiate SAML/SSO authentication flow"""
            return await handle_initiate_sso_authentication(sap_host)
        
        # Utility Tools
        
        @mcp_server.tool()
        async def aws_abap_cb_get_keychain_info() -> Dict[str, Any]:
            """Get information about OS keychain storage capabilities"""
            return await handle_get_keychain_info()
        
        logger.info("Successfully registered authentication tools with MCP server")
        
    except Exception as e:
        # Use warning level when re-raising - caller handles the error
        logger.warning(f"Failed to register authentication tools: {e}")
        raise


def enhance_existing_tools(tool_handlers_class):
    """
    Enhance existing tool handlers to support authentication
    This provides a fallback mechanism for existing functionality
    """
    
    # Store original _ensure_connected method
    original_ensure_connected = getattr(tool_handlers_class, '_ensure_connected', None)
    
    async def enhanced_ensure_connected(self) -> bool:
        """Enhanced _ensure_connected that tries authentication first"""
        try:
            # First, try to get authenticated SAP client from auth system
            auth_client = await get_authenticated_sap_client()
            if auth_client:
                # Use authenticated client
                self.sap_client = auth_client
                logger.info("Using authenticated SAP client from auth system")
                return True
            
            # Fallback to original method if available
            if original_ensure_connected:
                return await original_ensure_connected(self)
            
            # Last resort: check if sap_client is already connected
            if hasattr(self, 'sap_client') and self.sap_client:
                if hasattr(self.sap_client, 'session') and self.sap_client.session:
                    return True
            
            logger.warning("No authenticated SAP client available and no fallback method")
            return False
            
        except Exception as e:
            # Use warning level when re-raising - caller handles the error
            logger.warning(f"Enhanced _ensure_connected failed: {e}")
            
            # Fallback to original method
            if original_ensure_connected:
                return await original_ensure_connected(self)
            
            return False
    
    # Replace the method
    tool_handlers_class._ensure_connected = enhanced_ensure_connected
    
    logger.info("Enhanced existing tool handlers with authentication support")


def create_auth_aware_tool_wrapper(original_tool_func):
    """
    Create a wrapper for existing tools that checks authentication
    """
    async def auth_aware_wrapper(*args, **kwargs):
        try:
            # Check if we have an authenticated session
            auth_client = await get_authenticated_sap_client()
            if not auth_client:
                return "❌ No active authentication session. Please authenticate first using aws_abap_cb_authenticate_user."
            
            # Call original tool function
            return await original_tool_func(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"Auth-aware tool wrapper error: {e}")
            return f"❌ Tool execution failed: {str(e)}"
    
    return auth_aware_wrapper


class AuthenticationIntegration:
    """
    Main integration class for adding authentication to existing MCP server
    """
    
    def __init__(self, mcp_server, tool_handlers_class=None):
        self.mcp_server = mcp_server
        self.tool_handlers_class = tool_handlers_class
        self.integration_enabled = False
    
    def enable_authentication(self):
        """Enable authentication integration"""
        try:
            # Register new authentication tools
            register_auth_tools(self.mcp_server)
            
            # Enhance existing tool handlers if provided
            if self.tool_handlers_class:
                enhance_existing_tools(self.tool_handlers_class)
            
            self.integration_enabled = True
            logger.info("Authentication integration enabled successfully")
            
        except Exception as e:
            # Use warning level when re-raising - caller handles the error
            logger.warning(f"Failed to enable authentication integration: {e}")
            raise
    
    def is_enabled(self) -> bool:
        """Check if authentication integration is enabled"""
        return self.integration_enabled
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get status of authentication integration"""
        return {
            "enabled": self.integration_enabled,
            "auth_tools_registered": self.integration_enabled,
            "enhanced_tool_handlers": self.tool_handlers_class is not None,
            "message": "Authentication integration active" if self.integration_enabled else "Authentication integration disabled"
        }