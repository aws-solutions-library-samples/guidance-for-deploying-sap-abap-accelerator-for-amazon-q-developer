"""
OAuth Manager - Manages OAuth flow state and configuration
Feature-flagged implementation that doesn't break existing functionality
"""

import os
import logging
from typing import Optional, Dict
from .oidc_discovery import OAuthHandler

logger = logging.getLogger(__name__)


class OAuthManager:
    """
    Manages OAuth configuration and state for MCP server.
    
    Feature-flagged: Only active when ENABLE_OAUTH_FLOW=true
    """
    
    def __init__(self):
        self.enabled = os.getenv('ENABLE_OAUTH_FLOW', 'false').lower() == 'true'
        self.oauth_handler: Optional[OAuthHandler] = None
        self._initialized = False
        
        if self.enabled:
            logger.info("OAuth: OAuth flow ENABLED")
        else:
            logger.info("OAuth: OAuth flow DISABLED (set ENABLE_OAUTH_FLOW=true to enable)")
    
    async def initialize(self) -> bool:
        """
        Initialize OAuth manager with configuration from environment.
        
        Required environment variables (only if ENABLE_OAUTH_FLOW=true):
        - OAUTH_ISSUER: OIDC issuer URL
        - OAUTH_CLIENT_ID: OAuth client ID
        - OAUTH_REDIRECT_URI: OAuth redirect URI (optional, defaults to server URL)
        - OAUTH_CLIENT_SECRET: OAuth client secret (optional)
        
        Returns:
            bool: True if initialization successful (or disabled)
        """
        if not self.enabled:
            logger.debug("OAuth: Skipping initialization (disabled)")
            return True  # Not an error, just disabled
        
        try:
            # Get OAuth configuration from environment
            issuer = os.getenv('OAUTH_ISSUER')
            client_id = os.getenv('OAUTH_CLIENT_ID')
            redirect_uri = os.getenv('OAUTH_REDIRECT_URI')
            client_secret = os.getenv('OAUTH_CLIENT_SECRET')  # Optional
            
            # Validate required configuration
            if not issuer:
                logger.error("OAuth: OAUTH_ISSUER not set. OAuth flow will not work.")
                self.enabled = False
                return False
            
            if not client_id:
                logger.error("OAuth: OAUTH_CLIENT_ID not set. OAuth flow will not work.")
                self.enabled = False
                return False
            
            # Default redirect URI if not provided
            if not redirect_uri:
                # nosec B104 - Binding to 0.0.0.0 is intentional for containerized deployments (ECS/Docker/Kubernetes)
                server_host = os.getenv('SERVER_HOST', '0.0.0.0')
                server_port = os.getenv('SERVER_PORT', '8000')
                redirect_uri = f"http://{server_host}:{server_port}/oauth/callback"
                logger.info(f"OAuth: Using default redirect URI: {redirect_uri}")
            
            # Create OAuth handler
            self.oauth_handler = OAuthHandler(
                issuer=issuer,
                client_id=client_id,
                redirect_uri=redirect_uri,
                client_secret=client_secret
            )
            
            # Initialize (discover OIDC configuration)
            success = await self.oauth_handler.initialize()
            
            if success:
                self._initialized = True
                logger.info(f"OAuth: Successfully initialized with issuer: {issuer}")
                logger.info(f"OAuth: Client ID: {client_id}")
                logger.info(f"OAuth: Redirect URI: {redirect_uri}")
            else:
                logger.error("OAuth: Failed to initialize OAuth handler")
                self.enabled = False
            
            return success
            
        except Exception as e:
            logger.error(f"OAuth: Error during initialization: {e}")
            self.enabled = False
            return False
    
    def is_enabled(self) -> bool:
        """Check if OAuth flow is enabled and initialized"""
        return self.enabled and self._initialized
    
    def should_challenge(self, user_id: str) -> bool:
        """
        Determine if OAuth challenge should be returned.
        
        Args:
            user_id: Extracted user ID from request
        
        Returns:
            bool: True if OAuth challenge should be returned
        """
        # Only challenge if:
        # 1. OAuth is enabled and initialized
        # 2. User is not authenticated (anonymous)
        return self.is_enabled() and user_id == 'anonymous'
    
    def create_auth_challenge(self) -> Optional[Dict]:
        """
        Create OAuth authentication challenge for MCP client.
        
        Returns:
            Dict with OAuth challenge data, or None if OAuth disabled
        """
        if not self.is_enabled():
            return None
        
        if not self.oauth_handler:
            logger.error("OAuth: Handler not available")
            return None
        
        return self.oauth_handler.create_auth_challenge()
    
    async def exchange_code(self, code: str) -> Optional[Dict]:
        """
        Exchange authorization code for tokens.
        
        Args:
            code: Authorization code from IdP
        
        Returns:
            Dict with tokens, or None if failed
        """
        if not self.is_enabled():
            logger.warning("OAuth: Cannot exchange code - OAuth disabled")
            return None
        
        if not self.oauth_handler:
            logger.error("OAuth: Handler not available")
            return None
        
        return await self.oauth_handler.exchange_code_for_token(code)
    
    def get_config_summary(self) -> Dict:
        """Get OAuth configuration summary for debugging"""
        if not self.enabled:
            return {
                'enabled': False,
                'message': 'OAuth flow disabled. Set ENABLE_OAUTH_FLOW=true to enable.'
            }
        
        return {
            'enabled': self.enabled,
            'initialized': self._initialized,
            'issuer': os.getenv('OAUTH_ISSUER', 'not set'),
            'client_id': os.getenv('OAUTH_CLIENT_ID', 'not set'),
            'redirect_uri': os.getenv('OAUTH_REDIRECT_URI', 'default'),
            'has_client_secret': bool(os.getenv('OAUTH_CLIENT_SECRET'))
        }


# Global OAuth manager instance
oauth_manager = OAuthManager()
