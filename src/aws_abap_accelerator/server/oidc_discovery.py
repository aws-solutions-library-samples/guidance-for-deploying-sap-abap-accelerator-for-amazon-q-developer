"""
OIDC Discovery Module - IdP-Agnostic OAuth Configuration
Automatically discovers OAuth endpoints from any OIDC-compliant provider
"""

import logging
import httpx
from typing import Dict, Optional
from urllib.parse import urlencode
import secrets

logger = logging.getLogger(__name__)


class OIDCProvider:
    """
    Auto-discover OAuth endpoints from any OIDC provider.
    
    Supports:
    - AWS Cognito
    - Okta
    - Microsoft Entra ID (Azure AD)
    - Auth0
    - Google
    - Any OIDC-compliant provider
    """
    
    def __init__(self, issuer_url: str):
        """
        Initialize OIDC provider with issuer URL.
        
        Examples:
        - Cognito: https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxxx
        - Okta: https://your-domain.okta.com
        - Entra ID: https://login.microsoftonline.com/{tenant-id}/v2.0
        - Auth0: https://your-domain.auth0.com
        """
        self.issuer_url = issuer_url.rstrip('/')
        self.config: Optional[Dict] = None
        self._discovery_url = f"{self.issuer_url}/.well-known/openid-configuration"
    
    async def discover(self) -> bool:
        """
        Fetch OIDC configuration from .well-known/openid-configuration endpoint.
        
        Returns:
            bool: True if discovery successful, False otherwise
        """
        try:
            logger.info(f"OIDC: Discovering configuration from {self._discovery_url}")
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(self._discovery_url)
                response.raise_for_status()
                
                self.config = response.json()
                
                # Validate required endpoints exist
                required_fields = [
                    'authorization_endpoint',
                    'token_endpoint',
                    'issuer'
                ]
                
                for field in required_fields:
                    if field not in self.config:
                        logger.error(f"OIDC: Missing required field '{field}' in configuration")
                        return False
                
                logger.info(f"OIDC: Successfully discovered configuration for {self.config['issuer']}")
                return True
                
        except httpx.HTTPError as e:
            logger.error(f"OIDC: Failed to discover configuration: {e}")
            return False
        except Exception as e:
            logger.error(f"OIDC: Unexpected error during discovery: {e}")
            return False
    
    def get_endpoints(self) -> Optional[Dict[str, str]]:
        """
        Get OAuth endpoints from discovered configuration.
        
        Returns:
            Dict with authorization_endpoint, token_endpoint, jwks_uri, issuer
            None if discovery hasn't been performed
        """
        if not self.config:
            logger.warning("OIDC: Configuration not discovered yet. Call discover() first.")
            return None
        
        return {
            'authorization_endpoint': self.config['authorization_endpoint'],
            'token_endpoint': self.config['token_endpoint'],
            'jwks_uri': self.config.get('jwks_uri'),
            'issuer': self.config['issuer'],
            'userinfo_endpoint': self.config.get('userinfo_endpoint')
        }
    
    def get_supported_scopes(self) -> list:
        """Get list of supported scopes from OIDC configuration"""
        if not self.config:
            return ['openid', 'email', 'profile']  # Default scopes
        
        return self.config.get('scopes_supported', ['openid', 'email', 'profile'])


class OAuthHandler:
    """
    Handle OAuth 2.0 authorization code flow for MCP server.
    IdP-agnostic implementation using OIDC discovery.
    """
    
    def __init__(self, issuer: str, client_id: str, redirect_uri: str, client_secret: Optional[str] = None):
        """
        Initialize OAuth handler.
        
        Args:
            issuer: OIDC issuer URL
            client_id: OAuth client ID
            redirect_uri: OAuth redirect URI (where IdP sends user after auth)
            client_secret: OAuth client secret (optional, for confidential clients)
        """
        self.issuer = issuer
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.client_secret = client_secret
        self.provider: Optional[OIDCProvider] = None
        self._initialized = False
    
    async def initialize(self) -> bool:
        """
        Initialize OAuth handler by discovering OIDC configuration.
        
        Returns:
            bool: True if initialization successful
        """
        try:
            self.provider = OIDCProvider(self.issuer)
            success = await self.provider.discover()
            
            if success:
                self._initialized = True
                logger.info(f"OAuth: Handler initialized for {self.issuer}")
            else:
                logger.error(f"OAuth: Failed to initialize handler for {self.issuer}")
            
            return success
            
        except Exception as e:
            logger.error(f"OAuth: Error initializing handler: {e}")
            return False
    
    def is_initialized(self) -> bool:
        """Check if OAuth handler is initialized"""
        return self._initialized and self.provider is not None
    
    def create_authorization_url(self, state: Optional[str] = None, scopes: Optional[list] = None) -> Optional[str]:
        """
        Create OAuth authorization URL for user to authenticate.
        
        Args:
            state: Optional state parameter for CSRF protection
            scopes: Optional list of scopes (default: ['openid', 'email', 'profile'])
        
        Returns:
            Authorization URL string, or None if not initialized
        """
        if not self.is_initialized():
            logger.error("OAuth: Handler not initialized. Call initialize() first.")
            return None
        
        endpoints = self.provider.get_endpoints()
        if not endpoints:
            return None
        
        # Generate state if not provided (CSRF protection)
        if not state:
            state = secrets.token_urlsafe(32)
        
        # Use provided scopes or default
        if not scopes:
            scopes = ['openid', 'email', 'profile']
        
        # Build authorization URL parameters
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(scopes),
            'state': state
        }
        
        auth_url = f"{endpoints['authorization_endpoint']}?{urlencode(params)}"
        
        logger.debug(f"OAuth: Created authorization URL with state={state}")
        return auth_url
    
    async def exchange_code_for_token(self, code: str) -> Optional[Dict]:
        """
        Exchange authorization code for access token.
        
        Args:
            code: Authorization code from IdP
        
        Returns:
            Dict with access_token, id_token, refresh_token, etc.
            None if exchange failed
        """
        if not self.is_initialized():
            logger.error("OAuth: Handler not initialized")
            return None
        
        endpoints = self.provider.get_endpoints()
        if not endpoints:
            return None
        
        try:
            # Prepare token request
            data = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': self.redirect_uri,
                'client_id': self.client_id
            }
            
            # Add client secret if available (for confidential clients)
            if self.client_secret:
                data['client_secret'] = self.client_secret
            
            # Exchange code for token
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    endpoints['token_endpoint'],
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                
                response.raise_for_status()
                token_response = response.json()
                
                logger.info("OAuth: Successfully exchanged code for token")
                return token_response
                
        except httpx.HTTPError as e:
            logger.error(f"OAuth: Failed to exchange code for token: {e}")
            return None
        except Exception as e:
            logger.error(f"OAuth: Unexpected error during token exchange: {e}")
            return None
    
    def create_auth_challenge(self, state: Optional[str] = None) -> Optional[Dict]:
        """
        Create OAuth challenge for MCP client (Q Developer).
        
        This is what gets returned to Q Developer when authentication is required.
        Q Developer will open a browser with the auth_url.
        
        Args:
            state: Optional state parameter for CSRF protection
        
        Returns:
            Dict with auth_url, token_endpoint, method
            None if not initialized
        """
        if not self.is_initialized():
            return None
        
        auth_url = self.create_authorization_url(state=state)
        if not auth_url:
            return None
        
        endpoints = self.provider.get_endpoints()
        
        return {
            'auth_url': auth_url,
            'token_endpoint': endpoints['token_endpoint'],
            'method': 'oauth2',
            'state': state or 'no-state'
        }
