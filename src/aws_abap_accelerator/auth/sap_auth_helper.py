"""
SAP Authentication Helper for ABAP-Accelerator MCP Server

This module provides a unified interface for SAP authentication that supports:
1. Principal Propagation (certificate-based) - for production
2. Keychain-based authentication - for development/testing
3. Basic authentication - fallback

Usage in MCP tools:
    from auth.sap_auth_helper import get_sap_client_for_request
    
    sap_client = await get_sap_client_for_request(
        headers=request_headers,
        sap_system_id="S4H-100"
    )
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)

# Authentication mode
AUTH_MODE_PRINCIPAL_PROPAGATION = "principal_propagation"
AUTH_MODE_KEYCHAIN = "keychain"
AUTH_MODE_BASIC = "basic"


class SAPAuthHelper:
    """
    Unified SAP authentication helper.
    
    Automatically selects the best authentication method based on:
    1. Environment configuration
    2. Available credentials
    3. Request context
    """
    
    def __init__(self):
        self._auth_mode = os.getenv('SAP_AUTH_MODE', AUTH_MODE_KEYCHAIN)
        self._principal_propagation_enabled = os.getenv(
            'ENABLE_PRINCIPAL_PROPAGATION', 'false'
        ).lower() == 'true'
        self._initialized = False

    async def initialize(self) -> bool:
        """Initialize authentication helper based on configured mode"""
        try:
            if self._principal_propagation_enabled:
                logger.info("Initializing Principal Propagation authentication mode")
                from .principal_propagation_middleware import principal_propagation_middleware
                success = await principal_propagation_middleware.initialize()
                if success:
                    self._auth_mode = AUTH_MODE_PRINCIPAL_PROPAGATION
                    logger.info("Principal Propagation mode initialized successfully")
                else:
                    logger.warning("Principal Propagation initialization failed, falling back to keychain")
                    self._auth_mode = AUTH_MODE_KEYCHAIN
            else:
                logger.info(f"Using authentication mode: {self._auth_mode}")
            
            self._initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize SAP auth helper: {sanitize_for_logging(str(e))}")
            self._auth_mode = AUTH_MODE_KEYCHAIN
            self._initialized = True
            return True
    
    async def get_sap_client(
        self,
        headers: Dict[str, str],
        sap_system_id: str
    ) -> Tuple[Any, Dict[str, Any]]:
        """
        Get SAP client for a request.
        
        Args:
            headers: HTTP request headers (containing IAM identity for principal propagation)
            sap_system_id: Target SAP system identifier
            
        Returns:
            Tuple of (sap_client, context_info)
            context_info contains: iam_identity, sap_username, sap_host, auth_mode
        """
        if self._auth_mode == AUTH_MODE_PRINCIPAL_PROPAGATION:
            return await self._get_client_principal_propagation(headers, sap_system_id)
        elif self._auth_mode == AUTH_MODE_KEYCHAIN:
            return await self._get_client_keychain(headers, sap_system_id)
        else:
            return await self._get_client_basic(headers, sap_system_id)
    
    async def _get_client_principal_propagation(
        self,
        headers: Dict[str, str],
        sap_system_id: str
    ) -> Tuple[Any, Dict[str, Any]]:
        """Get SAP client using principal propagation (certificate auth)"""
        try:
            from .principal_propagation_middleware import principal_propagation_middleware
            from sap.sap_client import SAPADTClient
            from sap_types.sap_types import SAPConnection, AuthType
            
            # Process principal propagation
            context = await principal_propagation_middleware.process_request(
                headers=headers,
                sap_system_id=sap_system_id
            )
            
            if not context.validated:
                raise ValueError(f"Principal propagation failed: {context.error}")
            
            # Create SAP connection with certificate auth
            sap_connection = SAPConnection(
                host=context.sap_host,
                client=context.sap_client,
                username=context.sap_username,
                password="",  # Not needed for cert auth
                language="EN",
                secure=True,
                auth_type=AuthType.CERTIFICATE
            )
            
            # Create SAP client
            sap_client = SAPADTClient(sap_connection)
            
            # Attach certificate data for authentication
            sap_client.client_certificate_pem = context.cert_pem
            sap_client.client_private_key_pem = context.key_pem
            sap_client.use_certificate_auth = True
            
            # Connect to SAP
            connected = await sap_client.connect()
            if not connected:
                raise ValueError(f"Failed to connect to SAP system {context.sap_host}")
            
            # Return client and context info
            context_info = {
                'iam_identity': context.iam_identity,
                'sap_username': context.sap_username,
                'sap_host': context.sap_host,
                'sap_client': context.sap_client,
                'sap_system_id': sap_system_id,
                'auth_mode': AUTH_MODE_PRINCIPAL_PROPAGATION,
                'authenticated_at': datetime.now().isoformat()
            }
            
            logger.info(
                f"SAP client created via principal propagation: "
                f"{context.iam_identity} -> {context.sap_username}@{context.sap_host}"
            )
            
            return sap_client, context_info
            
        except Exception as e:
            # Use warning level when re-raising - caller handles the error
            logger.warning(f"Principal propagation auth failed: {sanitize_for_logging(str(e))}")
            raise
    
    async def _get_client_keychain(
        self,
        headers: Dict[str, str],
        sap_system_id: str
    ) -> Tuple[Any, Dict[str, Any]]:
        """Get SAP client using keychain credentials"""
        try:
            from .keychain_manager import keychain_manager
            from sap.sap_client import SAPADTClient
            from sap_types.sap_types import SAPConnection
            
            # Extract user context from headers
            user_id = headers.get('x-user-id', 'unknown')
            
            # Try different identifier patterns
            identifiers = [
                sap_system_id,
                f"sap-{sap_system_id}",
                sap_system_id.replace('sap-', '')
            ]
            
            credentials = None
            used_identifier = None
            for identifier in identifiers:
                credentials = keychain_manager.get_sap_credentials_by_identifier(identifier)
                if credentials:
                    used_identifier = identifier
                    break
            
            if not credentials:
                raise ValueError(
                    f"No SAP credentials found for system '{sap_system_id}'. "
                    f"Tried identifiers: {identifiers}"
                )
            
            # Create SAP connection
            sap_connection = SAPConnection(
                host=credentials['sap_host'],
                client=credentials['sap_client'],
                username=credentials['sap_username'],
                password=credentials['sap_password'],
                language=credentials.get('sap_language', 'EN'),
                secure=credentials.get('sap_secure', 'true').lower() == 'true'
            )
            
            # Create and connect SAP client
            sap_client = SAPADTClient(sap_connection)
            connected = await sap_client.connect()
            
            if not connected:
                raise ValueError(f"Failed to connect to SAP system {credentials['sap_host']}")
            
            # Return client and context info
            context_info = {
                'iam_identity': user_id,
                'sap_username': credentials['sap_username'],
                'sap_host': credentials['sap_host'],
                'sap_client': credentials['sap_client'],
                'sap_system_id': sap_system_id,
                'keychain_identifier': used_identifier,
                'auth_mode': AUTH_MODE_KEYCHAIN,
                'authenticated_at': datetime.now().isoformat()
            }
            
            logger.info(
                f"SAP client created via keychain: "
                f"{user_id} -> {credentials['sap_username']}@{credentials['sap_host']}"
            )
            
            return sap_client, context_info
            
        except Exception as e:
            # Use warning level when re-raising - caller handles the error
            logger.warning(f"Keychain auth failed: {sanitize_for_logging(str(e))}")
            raise
    
    async def _get_client_basic(
        self,
        headers: Dict[str, str],
        sap_system_id: str
    ) -> Tuple[Any, Dict[str, Any]]:
        """Get SAP client using basic authentication from environment"""
        try:
            from sap.sap_client import SAPADTClient
            from sap_types.sap_types import SAPConnection
            from config.settings import load_config
            
            # Load config from environment
            config = load_config()
            
            # Create SAP connection
            sap_connection = SAPConnection(
                host=config.host,
                client=config.client,
                username=config.username,
                password=config.password,
                language=config.language,
                secure=config.secure
            )
            
            # Create and connect SAP client
            sap_client = SAPADTClient(sap_connection)
            connected = await sap_client.connect()
            
            if not connected:
                raise ValueError(f"Failed to connect to SAP system {config.host}")
            
            # Return client and context info
            context_info = {
                'iam_identity': headers.get('x-user-id', 'unknown'),
                'sap_username': config.username,
                'sap_host': config.host,
                'sap_client': config.client,
                'sap_system_id': sap_system_id,
                'auth_mode': AUTH_MODE_BASIC,
                'authenticated_at': datetime.now().isoformat()
            }
            
            logger.info(f"SAP client created via basic auth: {config.username}@{config.host}")
            
            return sap_client, context_info
            
        except Exception as e:
            # Use warning level when re-raising - caller handles the error
            logger.warning(f"Basic auth failed: {sanitize_for_logging(str(e))}")
            raise
    
    def get_auth_mode(self) -> str:
        """Get current authentication mode"""
        return self._auth_mode
    
    def is_principal_propagation_enabled(self) -> bool:
        """Check if principal propagation is enabled"""
        return self._auth_mode == AUTH_MODE_PRINCIPAL_PROPAGATION


# Global instance
sap_auth_helper = SAPAuthHelper()


async def get_sap_client_for_request(
    headers: Dict[str, str],
    sap_system_id: str
) -> Tuple[Any, Dict[str, Any]]:
    """
    Convenience function to get SAP client for a request.
    
    Args:
        headers: HTTP request headers
        sap_system_id: Target SAP system identifier
        
    Returns:
        Tuple of (sap_client, context_info)
    """
    if not sap_auth_helper._initialized:
        await sap_auth_helper.initialize()
    
    return await sap_auth_helper.get_sap_client(headers, sap_system_id)
