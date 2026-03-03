"""
Enterprise SAP Client Factory
Creates SAP clients dynamically based on user context and stored credentials
"""

import logging
from typing import Dict, Optional, Tuple, Any
from datetime import datetime

from .context_manager import UserContext
from auth.keychain_manager import keychain_manager

logger = logging.getLogger(__name__)


class EnterpriseSAPClientFactory:
    """
    Factory for creating SAP clients based on user context and stored credentials
    Uses the existing keychain_manager for credential storage
    """
    
    def __init__(self):
        self._client_cache = {}  # Cache for reusable clients
        logger.info("Enterprise SAP Client Factory initialized")
    
    async def get_sap_client_for_context(self, user_context: UserContext, 
                                       headers: Dict[str, str]) -> Tuple[Optional[Any], Optional[Any]]:
        """
        Get SAP client and tool handlers for a specific user context
        
        Args:
            user_context: User context containing session info
            headers: Request headers with system information
            
        Returns:
            Tuple of (sap_client, tool_handlers) or (None, None) if failed
        """
        try:
            # Check if context already has authenticated client
            # nosemgrep: is-function-without-parentheses - is_authenticated is a boolean attribute in UserContext dataclass
            if user_context.sap_client and user_context.tool_handlers and user_context.is_authenticated:
                logger.debug(f"Using existing SAP client for {user_context.user_id}@{user_context.system_id}")
                return user_context.sap_client, user_context.tool_handlers
            
            # Get SAP connection details from existing keychain manager
            connection_details = self._get_connection_by_headers(headers)
            
            if not connection_details:
                logger.warning(f"No SAP connection found for user {user_context.user_id} on system {user_context.system_id}")
                return None, None
            
            # Create SAP client with connection details
            sap_client, tool_handlers = await self._create_sap_client(connection_details, user_context)
            
            if sap_client and tool_handlers:
                # Update user context with new client
                user_context.sap_client = sap_client
                user_context.tool_handlers = tool_handlers
                # nosemgrep: is-function-without-parentheses - is_authenticated is a boolean attribute in UserContext dataclass
                user_context.is_authenticated = True
                user_context.sap_credentials = connection_details
                
                logger.info(f"Created SAP client for {user_context.user_id}@{user_context.system_id} -> {connection_details.sap_username}@{connection_details.sap_host}")
                return sap_client, tool_handlers
            else:
                logger.error(f"Failed to create SAP client for {user_context.user_id}@{user_context.system_id}")
                return None, None
                
        except Exception as e:
            logger.error(f"Error getting SAP client for context {user_context.get_context_key()}: {e}")
            return None, None
    
    def _get_connection_by_headers(self, headers: Dict[str, str]) -> Optional[Dict[str, str]]:
        """
        Get SAP connection based on request headers using existing keychain manager
        """
        # Extract system identifier from headers
        system_id = headers.get('x-sap-system-id', 'default')
        user_id = headers.get('x-user-id', 'anonymous')
        
        # Try different system identifier patterns
        system_identifiers = [
            f"sap-{system_id.lower()}-{user_id}",  # User-specific: sap-s4h-dev-user001
            f"sap-{system_id.lower()}",            # System-specific: sap-s4h-dev
            system_id.lower(),                     # Direct: s4h-dev
            f"{system_id.lower()}-{user_id}",      # Combined: s4h-dev-user001
        ]
        
        for identifier in system_identifiers:
            credentials = keychain_manager.get_sap_credentials_by_identifier(identifier)
            if credentials:
                logger.debug(f"Found connection using identifier: {identifier}")
                return credentials
        
        logger.warning(f"No SAP connection found for system_id='{system_id}', user_id='{user_id}'")
        logger.debug(f"Tried identifiers: {system_identifiers}")
        return None
    
    async def _create_sap_client(self, connection_details: Dict[str, str], 
                               user_context: UserContext) -> Tuple[Optional[Any], Optional[Any]]:
        """
        Create SAP client and tool handlers from connection details
        
        Args:
            connection_details: SAP connection details
            user_context: User context for logging/tracking
            
        Returns:
            Tuple of (sap_client, tool_handlers) or (None, None) if failed
        """
        try:
            # Import SAP client components
            from sap.sap_client import SAPADTClient
            from server.tool_handlers import ToolHandlers
            from sap_types.sap_types import SAPConnection
            
            # Create SAP connection object
            sap_connection = SAPConnection(
                host=connection_details['sap_host'],
                client=connection_details['sap_client'],
                username=connection_details['sap_username'],
                password=connection_details['sap_password'],
                language=connection_details.get('sap_language', 'EN'),
                secure=connection_details.get('sap_secure', 'true').lower() == 'true',
                instance_number=connection_details.get('sap_instance_number')
            )
            
            # Create SAP client
            sap_client = SAPADTClient(sap_connection)
            
            # Test connection
            logger.info(f"Testing SAP connection for {user_context.user_id}@{user_context.system_id}")
            connected = await sap_client.connect()
            
            if not connected:
                logger.error(f"Failed to connect to SAP system for {user_context.user_id}@{user_context.system_id}")
                return None, None
            
            # Create tool handlers
            tool_handlers = ToolHandlers(sap_client)
            
            logger.info(f"Successfully created SAP client for {user_context.user_id}@{user_context.system_id}")
            return sap_client, tool_handlers
            
        except Exception as e:
            logger.error(f"Error creating SAP client: {e}")
            return None, None
    
    def get_client_cache_stats(self) -> Dict[str, Any]:
        """Get statistics about cached clients"""
        return {
            "cached_clients": len(self._client_cache),
            "cache_keys": list(self._client_cache.keys())
        }
    
    async def cleanup_expired_clients(self):
        """Clean up expired or disconnected clients"""
        try:
            expired_keys = []
            
            for key, (client, created_at) in self._client_cache.items():
                # Check if client is still connected
                if hasattr(client, 'session') and not client.session:
                    expired_keys.append(key)
                # Check if client is too old (e.g., > 1 hour)
                elif (datetime.now() - created_at).total_seconds() > 3600:
                    expired_keys.append(key)
            
            for key in expired_keys:
                try:
                    client, _ = self._client_cache[key]
                    if hasattr(client, 'close'):
                        await client.close()
                    del self._client_cache[key]
                    logger.info(f"Cleaned up expired SAP client: {key}")
                except Exception as e:
                    logger.warning(f"Error cleaning up client {key}: {e}")
            
            if expired_keys:
                logger.info(f"Cleaned up {len(expired_keys)} expired SAP clients")
                
        except Exception as e:
            logger.error(f"Error during client cleanup: {e}")


# Global enterprise SAP client factory instance
enterprise_sap_client_factory = EnterpriseSAPClientFactory()