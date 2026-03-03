"""
OAuth Helper Functions for MCP Tools
Provides OAuth challenge functionality for tool handlers
"""

import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class MCPAuthenticationRequired(Exception):
    """
    Exception raised when authentication is required.
    MCP clients (like Q Developer) will catch this and initiate OAuth flow.
    """
    
    def __init__(self, message: str, auth_challenge: Dict[str, Any]):
        self.message = message
        self.auth_challenge = auth_challenge
        super().__init__(message)
    
    def to_mcp_error(self) -> Dict[str, Any]:
        """Convert to MCP error format"""
        return {
            "code": -32001,  # Custom error code for authentication required
            "message": self.message,
            "data": self.auth_challenge
        }


def check_authentication_and_challenge(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Check if user is authenticated and return OAuth challenge if not.
    
    This function is called by tool handlers to check authentication.
    If OAuth is enabled and user is not authenticated, returns challenge data.
    
    Args:
        user_id: Extracted user ID from request headers
    
    Returns:
        OAuth challenge dict if authentication required, None otherwise
    
    Usage in tool handlers:
        user_id = extract_user_from_headers(ctx)
        auth_challenge = check_authentication_and_challenge(user_id)
        if auth_challenge:
            raise MCPAuthenticationRequired(
                "Authentication required",
                auth_challenge
            )
    """
    try:
        from .oauth_manager import oauth_manager
        
        # Check if OAuth challenge should be returned
        if oauth_manager.should_challenge(user_id):
            challenge = oauth_manager.create_auth_challenge()
            if challenge:
                logger.info(f"OAuth: Returning authentication challenge for user '{user_id}'")
                return challenge
        
        # No challenge needed
        return None
        
    except Exception as e:
        logger.error(f"OAuth: Error checking authentication: {e}")
        return None


def is_oauth_enabled() -> bool:
    """
    Check if OAuth flow is enabled.
    
    Returns:
        bool: True if OAuth is enabled and initialized
    """
    try:
        from .oauth_manager import oauth_manager
        return oauth_manager.is_enabled()
    except Exception:
        return False
