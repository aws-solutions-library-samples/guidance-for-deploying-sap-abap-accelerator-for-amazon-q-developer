"""
SAP Client Factory for creating fresh clients with cached tokens
"""

import logging
import aiohttp
import ssl
from typing import Optional, Dict, Any

from sap.sap_client import SAPADTClient
from sap_types.sap_types import SAPConnection
from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)


class SAPClientFactory:
    """Factory for creating fresh SAP clients with cached session tokens"""
    
    @staticmethod
    async def create_client_with_tokens(sap_tokens: Dict[str, Any]) -> Optional[SAPADTClient]:
        """
        Create a fresh SAP client using cached session tokens
        
        Args:
            sap_tokens: Dictionary containing CSRF token, cookies, and connection info
            
        Returns:
            Connected SAPADTClient or None if failed
        """
        try:
            # Create connection config from tokens with actual credentials
            connection = SAPConnection(
                host=sap_tokens['sap_host'],
                client=sap_tokens['sap_client'],
                username=sap_tokens['sap_username'],
                password=sap_tokens.get('sap_password', ''),  # Include actual password for re-auth
                language=sap_tokens.get('sap_language', 'EN'),
                secure=True
            )
            
            # Create client
            sap_client = SAPADTClient(connection)
            
            # Set base URL
            sap_client.base_url = sap_tokens['base_url']
            
            # Create fresh HTTP session
            sap_client.session = await sap_client._create_session()
            
            # Restore session tokens
            sap_client.csrf_token = sap_tokens.get('csrf_token')
            sap_client.cookies = sap_tokens.get('cookies', {})
            
            # If we have session cookies from Playwright, add them
            if 'session_cookies' in sap_tokens:
                playwright_cookies = sap_tokens['session_cookies']
                sap_client.cookies.update(playwright_cookies)
                logger.info(f"Added {len(playwright_cookies)} Playwright session cookies to SAP client")
                
                # For Playwright authentication, mark for cookie-only auth
                if sap_tokens.get('authentication_method') == 'playwright':
                    logger.info("Using Playwright authentication - will prefer cookie-based auth")
                    # Keep password but mark as Playwright auth
                    sap_client._playwright_auth = True
            
            # Add cookies to session
            if sap_client.cookies:
                for name, value in sap_client.cookies.items():
                    sap_client.session.cookie_jar.update_cookies({name: value})
            
            logger.info(f"Created fresh SAP client with tokens for {sap_tokens['sap_username']}@{sap_tokens['sap_host']}")
            return sap_client
            
        except Exception as e:
            logger.error(f"Failed to create SAP client with tokens: {sanitize_for_logging(str(e))}")
            return None
    
    @staticmethod
    async def refresh_tokens_from_keychain(keychain_identifier: str, sap_tokens: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Refresh SAP tokens by re-authenticating from keychain
        
        Args:
            keychain_identifier: Keychain identifier for credentials
            sap_tokens: Current token info (for connection details)
            
        Returns:
            New token dictionary or None if failed
        """
        try:
            from .keychain_manager import keychain_manager
            from .providers.basic_auth import BasicAuthProvider
            
            logger.info(f"Refreshing tokens from keychain for identifier: {keychain_identifier}")
            
            # Get fresh credentials from keychain
            credentials = keychain_manager.get_sap_credentials_by_identifier(keychain_identifier)
            if not credentials:
                logger.error(f"No credentials found for keychain identifier: {keychain_identifier}")
                return None
            
            # Create basic auth provider and authenticate
            auth_provider = BasicAuthProvider()
            auth_result = await auth_provider.authenticate({'keychain_identifier': keychain_identifier})
            
            if auth_result.success and auth_result.user_info:
                logger.info("Successfully refreshed tokens from keychain")
                return auth_result.user_info.get('sap_tokens')
            else:
                logger.error(f"Failed to refresh tokens: {auth_result.error_message}")
                return None
                
        except Exception as e:
            logger.error(f"Error refreshing tokens from keychain: {sanitize_for_logging(str(e))}")
            return None