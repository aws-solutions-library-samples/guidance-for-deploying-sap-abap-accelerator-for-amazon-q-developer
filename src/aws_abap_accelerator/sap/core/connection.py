"""
SAP Connection Management Module

This module handles all connection-related functionality:
- Authentication (basic auth, CSRF tokens)
- Session management
- HTTP client setup
- SSL configuration
"""

import asyncio
import aiohttp
import ssl
import os
import base64
from typing import Optional, Dict
import logging

from sap_types.sap_types import SAPConnection
from utils.logger import rap_logger
from utils.security import (
    sanitize_for_logging, validate_sap_host, decrypt_from_memory
)

logger = logging.getLogger(__name__)


class SAPConnectionManager:
    """Manages SAP system connections and authentication"""
    
    def __init__(self, connection: SAPConnection):
        self.connection = connection
        self.session_id: Optional[str] = None
        self.csrf_token: Optional[str] = None
        self.cookies: Dict[str, str] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Validate SAP host for security
        if not validate_sap_host(connection.host):
            raise ValueError(f"Invalid or potentially unsafe SAP host: {sanitize_for_logging(connection.host)}")
        
        # Determine base URL
        self.base_url = self._build_base_url()
    
    def _build_base_url(self) -> str:
        """Build the base URL for SAP system"""
        clean_host = self.connection.host.replace('https://', '').replace('http://', '')
        
        if ':' in clean_host:
            # Host already includes port
            base_url = f"{'https' if self.connection.secure else 'http'}://{clean_host}"
        else:
            # Calculate port based on instance number
            if self.connection.instance_number:
                instance_num = int(self.connection.instance_number)
                http_port = (44300 + instance_num) if self.connection.secure else (8000 + instance_num)
                base_url = f"{'https' if self.connection.secure else 'http'}://{clean_host}:{http_port}"
            else:
                # Use default ports
                base_url = f"{'https' if self.connection.secure else 'http'}://{clean_host}"
        
        return base_url
    
    async def create_session(self) -> aiohttp.ClientSession:
        """Create HTTP session with proper configuration"""
        # SSL context for secure connections
        ssl_context = None
        if self.connection.secure:
            ssl_context = ssl.create_default_context()
            
            # Check for custom CA certificate (for corporate/internal CAs)
            custom_ca_path = os.environ.get('CUSTOM_CA_CERT_PATH') or os.environ.get('SSL_CERT_FILE')
            if custom_ca_path and os.path.exists(custom_ca_path):
                try:
                    ssl_context.load_verify_locations(custom_ca_path)
                    logger.info(f"Loaded custom CA certificate from: {custom_ca_path}")
                except Exception as e:
                    logger.warning(f"Failed to load custom CA certificate: {e}")
            
            # Check for SSL verification toggle (for testing only - NOT recommended for production)
            ssl_verify = os.environ.get('SSL_VERIFY', 'true').lower()
            if ssl_verify in ('false', '0', 'no'):
                logger.warning("SSL verification DISABLED - this is insecure and should only be used for testing!")
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            else:
                ssl_context.check_hostname = True
                ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # Create session with timeout and headers
        timeout = aiohttp.ClientTimeout(total=60)
        headers = {
            'Content-Type': 'application/xml',
            'Accept': 'application/xml',
            'User-Agent': 'ABAP-Accelerator-MCP-Server/1.0.0'
        }
        
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        
        session = aiohttp.ClientSession(
            base_url=self.base_url,
            timeout=timeout,
            headers=headers,
            connector=connector,
            cookie_jar=aiohttp.CookieJar()
        )
        
        return session
    
    async def connect(self) -> bool:
        """Establish connection to SAP system"""
        try:
            logger.info(f"Connecting to SAP system: {sanitize_for_logging(self.base_url)}")
            
            # Create session
            self.session = await self.create_session()
            
            # Authenticate using basic authentication
            success = await self._authenticate_basic()
            
            if success:
                logger.info("Successfully connected to SAP system")
                return True
            else:
                logger.error("Failed to authenticate with SAP system")
                return False
                
        except Exception as e:
            logger.error(f"Connection failed: {sanitize_for_logging(str(e))}")
            return False
    
    async def _authenticate_basic(self) -> bool:
        """Authenticate using basic authentication"""
        try:
            # Get password (decrypt if encrypted)
            password = self.connection.password
            if hasattr(self.connection, 'encrypted_password') and self.connection.encrypted_password:
                password = decrypt_from_memory(self.connection.encrypted_password)
                if not password:
                    logger.error("Failed to decrypt password for basic authentication")
                    return False
            
            if not password:
                logger.error("No password available for basic authentication")
                return False
            
            # Create basic auth
            auth = aiohttp.BasicAuth(self.connection.username, password)
            
            # Test connection with discovery endpoint
            discovery_url = f"/sap/bc/adt/discovery?sap-client={self.connection.client}"
            headers = {
                'x-sap-adt-sessiontype': 'stateful',
                'x-csrf-token': 'fetch',
                'Accept': 'application/atomsvc+xml, application/xml, text/xml, */*',
                'User-Agent': 'ABAP-Accelerator-MCP-Server/1.0.0'
            }
            
            async with self.session.get(discovery_url, auth=auth, headers=headers) as response:
                if response.status == 200:
                    # Store session information
                    self.csrf_token = response.headers.get('x-csrf-token')
                    
                    # Store cookies for session management
                    set_cookie_headers = response.headers.getall('set-cookie', [])
                    if set_cookie_headers:
                        self.cookies = {cookie.split('=')[0]: cookie.split('=')[1].split(';')[0] 
                                      for cookie in set_cookie_headers if '=' in cookie}
                    
                    logger.info(f"Authentication successful, CSRF token: {sanitize_for_logging(self.csrf_token)}")
                    return True
                else:
                    logger.error(f"Authentication failed with status: {response.status}")
                    response_text = await response.text()
                    logger.error(f"Response: {sanitize_for_logging(response_text[:500])}")
                    return False
                    
        except Exception as e:
            logger.error(f"Basic authentication failed: {sanitize_for_logging(str(e))}")
            return False
    
    async def get_appropriate_headers(self, fetch_csrf: bool = False) -> Dict[str, str]:
        """Get appropriate headers for SAP requests"""
        headers = {
            'Accept': 'application/xml, application/atomsvc+xml',
            'User-Agent': 'ABAP-Accelerator-MCP-Server/1.0.0'
        }
        
        # Add cookies for session management
        if self.cookies:
            cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
            headers['Cookie'] = cookie_str
        
        # Add authentication
        password = self.connection.password
        if hasattr(self.connection, 'encrypted_password') and self.connection.encrypted_password:
            password = decrypt_from_memory(self.connection.encrypted_password)
        
        if password:
            auth_str = base64.b64encode(f"{self.connection.username}:{password}".encode()).decode()
            headers['Authorization'] = f'Basic {auth_str}'
        
        # Add CSRF token
        if fetch_csrf:
            headers['x-csrf-token'] = 'fetch'
        elif self.csrf_token:
            headers['x-csrf-token'] = self.csrf_token
        else:
            headers['x-csrf-token'] = 'fetch'
        
        return headers
    
    def get_auth_header(self) -> str:
        """Get base64 encoded auth header"""
        # Get password (decrypt if encrypted)
        password = self.connection.password
        if hasattr(self.connection, 'encrypted_password') and self.connection.encrypted_password:
            password = decrypt_from_memory(self.connection.encrypted_password)
            if not password:
                raise ValueError("Failed to decrypt password for authentication")
        
        if not password:
            raise ValueError("No password available for authentication")
        
        # Create base64 encoded auth string
        auth_string = f"{self.connection.username}:{password}"
        return base64.b64encode(auth_string.encode()).decode()
    
    async def get_csrf_token(self) -> bool:
        """Get CSRF token for write operations"""
        try:
            headers = await self.get_appropriate_headers(fetch_csrf=True)
            
            async with self.session.get(f"/sap/bc/adt/discovery?sap-client={self.connection.client}", 
                                     headers=headers) as response:
                if response.status == 200:
                    self.csrf_token = response.headers.get('x-csrf-token')
                    return self.csrf_token is not None
                return False
                
        except Exception as e:
            logger.error(f"Failed to get CSRF token: {sanitize_for_logging(str(e))}")
            return False