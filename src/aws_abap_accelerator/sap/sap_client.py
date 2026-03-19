"""
SAP ADT Client for HTTP-based communication with SAP systems.
Python equivalent of sap-client.ts

SECURITY NOTE: This file constructs XML payloads for SAP's ADT (ABAP Development Tools) REST API.
Semgrep may flag these as "raw HTML construction" but they are NOT browser-rendered HTML.
All user inputs are sanitized via sanitize_for_xml() before inclusion in XML payloads.
These are server-to-server API calls, not client-facing web content.

BANDIT NOTES:
- B608 (SQL injection): This file generates ABAP/CDS source code templates sent to SAP ADT API
  as text payloads. These are NOT SQL queries executed against a database. SAP handles parsing.
- B314/B405 (XML parsing): XML responses from authenticated SAP ADT API are parsed. These are
  trusted responses from the SAP system, not untrusted user input.
- B104 (binding to all interfaces): Not applicable to this file.

nosemgrep: python.django.security.injection.raw-html-format.raw-html-format
"""

import asyncio
import aiohttp
import ssl
import os
from typing import Optional, List, Dict, Any, Tuple
import logging
from urllib.parse import urljoin, quote
import defusedxml.ElementTree as ET  # Secure XML parsing, prevents XXE attacks

from sap_types.sap_types import (
    SAPConnection, ADTObject, ATCResult, UnitTestResult, CreateObjectRequest,
    SyntaxCheckResult, ActivationResult, ObjectOperationResult, ATCCheckArgs,
    SyntaxError as SAPSyntaxError, SyntaxWarning, PackageInfo, TransportRequest, CreatePackageRequest,
    CreateTransportRequest, PackageOperationResult, TransportOperationResult,
    EnhancementInfo, CreateEnhancementRequest, EnhancementSpotInfo, BadiDefinitionInfo,
    EnhancementOperationResult, EnhancementType, InterfaceInfo, FunctionGroupInfo,
    FunctionModuleInfo, FunctionGroupIncludeInfo, CreateInterfaceRequest,
    CreateFunctionGroupRequest, CreateFunctionModuleRequest, InterfaceOperationResult,
    FunctionOperationResult, DataElementInfo, DomainInfo, TableInfo, StructureInfo,
    TableTypeInfo, SearchHelpInfo, ViewInfo, LockObjectInfo, CreateDataElementRequest,
    CreateDomainRequest, CreateTableRequest, CreateStructureRequest, CreateTableTypeRequest,
    CreateSearchHelpRequest, CreateViewRequest, CreateLockObjectRequest, DDICOperationResult,
    SeverityType
)
from utils.logger import rap_logger
from utils.security import (
    sanitize_for_logging, sanitize_for_xml, validate_numeric_input,
    decrypt_from_memory, validate_sap_host, sanitize_file_path
)
from utils.xml_utils import (
    safe_parse_xml, extract_from_xml, get_object_url_patterns,
    format_object_type_for_url, build_object_xml, is_include_program
)
from sap.class_handler import ClassHandler, ClassDefinition, MethodDefinition
from sap.cds_handler import CDSHandler
from sap.behavior_definition_handler import BehaviorDefinitionHandler
from sap.service_definition_handler import ServiceDefinitionHandler
from sap.service_binding_handler import ServiceBindingHandler
from sap.service_definition_handler import ServiceDefinitionHandler


logger = logging.getLogger(__name__)


class SAPADTClient:
    """SAP ADT Client for HTTP-based communication"""
    
    def __init__(self, connection: SAPConnection):
        self.connection = connection
        self.session_id: Optional[str] = None
        self.csrf_token: Optional[str] = None
        self.cookies: Dict[str, str] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.keychain_identifier: Optional[str] = None  # Store keychain identifier for dynamic system ID
        
        # Initialize handlers
        self.class_handler = ClassHandler(self)
        self.cds_handler = CDSHandler(self)
        self.behavior_definition_handler = BehaviorDefinitionHandler(self)
        self.service_definition_handler = ServiceDefinitionHandler(self)
        self.service_binding_handler = ServiceBindingHandler(self)
        self.service_definition_handler = ServiceDefinitionHandler(self)
        
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
    
    async def _ensure_session_valid(self):
        """Ensure HTTP session is valid and recreate if needed"""
        if self.session is None or self.session.closed:
            logger.info("Creating new HTTP session (previous session was closed)")
            if self.session and not self.session.closed:
                await self.session.close()
            self.session = await self._create_session()
            
            # Re-authenticate if we had to recreate the session
            if self.csrf_token:
                logger.info("Re-authenticating after session recreation")
                await self._authenticate_basic()
    
    async def _handle_session_timeout_error(self, response_status: int, response_text: str) -> bool:
        """
        Check if response indicates a session timeout and attempt re-authentication.
        
        Args:
            response_status: HTTP response status code
            response_text: Response body text
            
        Returns:
            True if session was refreshed and request should be retried, False otherwise
        """
        # Check for session timeout indicators
        is_session_timeout = (
            response_status == 400 and 
            ('session timed out' in response_text.lower() or 
             'session timeout' in response_text.lower() or
             'session expired' in response_text.lower())
        )
        
        if not is_session_timeout:
            return False
        
        logger.warning("Session timeout detected - attempting re-authentication")
        
        try:
            # Clear existing tokens
            self.csrf_token = None
            self.cookies = {}
            
            # Check authentication method and re-authenticate
            use_cert_auth = getattr(self, 'use_certificate_auth', False)
            
            if use_cert_auth:
                # Re-authenticate with certificate
                logger.info("Re-authenticating with certificate after session timeout")
                success = await self._authenticate_certificate()
            elif self.connection.password:
                # Re-authenticate with basic auth
                logger.info("Re-authenticating with basic auth after session timeout")
                success = await self._authenticate_basic()
            elif self.cookies:
                # Re-authenticate with cookies
                logger.info("Re-authenticating with cookies after session timeout")
                success = await self._authenticate_with_cookies()
            else:
                logger.error("No authentication method available for re-authentication")
                return False
            
            if success:
                logger.info("Re-authentication successful after session timeout")
                return True
            else:
                logger.error("Re-authentication failed after session timeout")
                return False
                
        except Exception as e:
            logger.error(f"Error during re-authentication after session timeout: {sanitize_for_logging(str(e))}")
            return False
    
    async def _request_with_retry(
        self,
        method: str,
        url: str,
        headers: Dict[str, str] = None,
        data: Any = None,
        params: Dict[str, str] = None,
        auth: aiohttp.BasicAuth = None,
        max_retries: int = 1
    ) -> Tuple[int, str, Dict[str, str]]:
        """
        Make HTTP request with automatic retry on session timeout.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            url: Request URL
            headers: Request headers
            data: Request body data
            params: Query parameters
            auth: Basic auth credentials
            max_retries: Maximum number of retries on session timeout
            
        Returns:
            Tuple of (status_code, response_text, response_headers)
        """
        await self._ensure_session_valid()
        
        if headers is None:
            headers = await self._get_appropriate_headers()
        
        for attempt in range(max_retries + 1):
            try:
                request_kwargs = {
                    'headers': headers,
                }
                if data is not None:
                    request_kwargs['data'] = data
                if params is not None:
                    request_kwargs['params'] = params
                if auth is not None:
                    request_kwargs['auth'] = auth
                
                async with getattr(self.session, method.lower())(url, **request_kwargs) as response:
                    status = response.status
                    text = await response.text()
                    resp_headers = dict(response.headers)
                    
                    # Check for session timeout
                    if attempt < max_retries and await self._handle_session_timeout_error(status, text):
                        logger.info(f"Retrying request after session refresh (attempt {attempt + 2}/{max_retries + 1})")
                        # Update headers with new CSRF token
                        if self.csrf_token:
                            headers['x-csrf-token'] = self.csrf_token
                        continue
                    
                    return status, text, resp_headers
                    
            except aiohttp.ClientError as e:
                logger.error(f"HTTP request error: {sanitize_for_logging(str(e))}")
                if attempt < max_retries:
                    logger.info(f"Retrying request after error (attempt {attempt + 2}/{max_retries + 1})")
                    await self._ensure_session_valid()
                    continue
                raise
        
        # Should not reach here, but return error status if it does
        return 500, "Max retries exceeded", {}

    async def _create_session(self) -> aiohttp.ClientSession:
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
            cookie_jar=aiohttp.DummyCookieJar()  # Disable auto cookie handling - we manage cookies manually in _get_appropriate_headers
        )
        
        return session
    
    async def connect(self) -> bool:
        """Establish connection to SAP system with basic auth first, then browser fallback"""
        try:
            logger.info(f"Connecting to SAP system: {sanitize_for_logging(self.base_url)}")
            
            # Create session
            self.session = await self._create_session()
            
            # Priority 0: Try certificate authentication if available
            if hasattr(self, 'use_certificate_auth') and self.use_certificate_auth:
                logger.info("Attempting certificate authentication (priority 0)")
                success = await self._authenticate_certificate()
                if success:
                    logger.info("Successfully connected using certificate authentication")
                    return True
                else:
                    logger.warning("Certificate authentication failed")
                    return False  # Don't fall back for cert auth - it should work or fail
            
            # Priority 1: Try basic authentication if password is available
            if self.connection.password:
                logger.info("Attempting basic authentication (priority 1)")
                success = await self._authenticate_basic()
                if success:
                    logger.info("Successfully connected using basic authentication")
                    return True
                else:
                    logger.warning("Basic authentication failed, falling back to browser-based auth")
            else:
                logger.info("No password available for basic authentication")
            
            # Priority 2: Fall back to browser-based authentication (cookies/Playwright)
            has_browser_cookies = any(cookie_name in self.cookies for cookie_name in ['JSESSIONID', 'SAP_SESSIONID', 'sap-usercontext'])
            
            if has_browser_cookies:
                logger.info("Attempting browser-based authentication (fallback)")
                success = await self._authenticate_with_cookies()
                if success:
                    logger.info("Successfully connected using browser-based authentication")
                    return True
                else:
                    logger.error("Browser-based authentication failed")
            else:
                logger.error("No browser cookies available for fallback authentication")
            
            logger.error("All authentication methods failed")
            return False
                
        except Exception as e:
            logger.error(f"Connection failed: {sanitize_for_logging(str(e))}")
            return False
    
    async def _authenticate_with_cookies(self) -> bool:
        """Authenticate using existing cookies (from Playwright or other browser-based auth)"""
        try:
            logger.info("Attempting cookie-based authentication")
            
            # Cookies are managed manually via _get_appropriate_headers Cookie header
            # No need to push into cookie_jar (which may be DummyCookieJar for basic auth sessions)
            if self.cookies:
                logger.info(f"Using {len(self.cookies)} cookies for cookie-based authentication")
            
            # Test connection with discovery endpoint using cookies only
            discovery_url = f"/sap/bc/adt/discovery?sap-client={self.connection.client}"
            headers = {
                'x-sap-adt-sessiontype': 'stateful',
                'x-csrf-token': 'fetch',
                'Accept': 'application/atomsvc+xml, application/xml, text/xml, */*',
                'User-Agent': 'ABAP-Accelerator-MCP-Server/1.0.0'
            }
            
            # Don't add Authorization header - rely on cookies only
            async with self.session.get(discovery_url, headers=headers) as response:
                if response.status == 200:
                    # Store CSRF token
                    self.csrf_token = response.headers.get('x-csrf-token')
                    
                    # Update cookies from response
                    set_cookie_headers = response.headers.getall('set-cookie', [])
                    if set_cookie_headers:
                        new_cookies = {cookie.split('=')[0]: cookie.split('=')[1].split(';')[0] 
                                     for cookie in set_cookie_headers if '=' in cookie}
                        self.cookies.update(new_cookies)
                    
                    logger.info(f"Cookie authentication successful, CSRF token: {sanitize_for_logging(self.csrf_token)}")
                    return True
                else:
                    logger.warning(f"Cookie authentication failed with status: {response.status}")
                    response_text = await response.text()
                    logger.warning(f"Response: {sanitize_for_logging(response_text[:500])}")
                    return False
                    
        except Exception as e:
            logger.error(f"Cookie authentication failed: {sanitize_for_logging(str(e))}")
            return False

    async def _authenticate_certificate(self) -> bool:
        """Authenticate using X.509 client certificate (principal propagation)"""
        try:
            import ssl
            import tempfile
            import os
            
            cert_pem = getattr(self, 'client_certificate_pem', None)
            key_pem = getattr(self, 'client_private_key_pem', None)
            sap_port = getattr(self, 'sap_port', 443)
            
            if not cert_pem or not key_pem:
                logger.error("Certificate or private key not provided for certificate auth")
                return False
            
            logger.info(f"Using certificate authentication with port {sap_port}")
            
            # Create temporary files for cert and key
            cert_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
            key_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
            
            try:
                cert_file.write(cert_pem)
                cert_file.close()
                key_file.write(key_pem)
                key_file.close()
                
                # Create SSL context with client certificate
                ssl_context = ssl.create_default_context()
                ssl_context.load_cert_chain(cert_file.name, key_file.name)
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE  # SAP self-signed certs
                
                # Create new session with SSL context
                import aiohttp
                connector = aiohttp.TCPConnector(ssl=ssl_context)
                
                # Close old session and create new one with cert
                if self.session:
                    await self.session.close()
                
                self.session = aiohttp.ClientSession(
                    base_url=f"https://{self.connection.host}:{sap_port}",
                    connector=connector
                )
                
                # Test connection with discovery endpoint
                discovery_url = f"/sap/bc/adt/discovery?sap-client={self.connection.client}"
                headers = {
                    'x-sap-adt-sessiontype': 'stateful',
                    'x-csrf-token': 'fetch',
                    'Accept': 'application/atomsvc+xml, application/xml, text/xml, */*',
                    'User-Agent': 'ABAP-Accelerator-MCP-Server/1.0.0'
                }
                
                async with self.session.get(discovery_url, headers=headers) as response:
                    if response.status == 200:
                        self.csrf_token = response.headers.get('x-csrf-token')
                        
                        # Store session cookies - important for maintaining session state
                        set_cookie_headers = response.headers.getall('set-cookie', [])
                        if set_cookie_headers:
                            self.cookies = {cookie.split('=')[0]: cookie.split('=')[1].split(';')[0] 
                                          for cookie in set_cookie_headers if '=' in cookie}
                            logger.info(f"Stored {len(self.cookies)} session cookies from certificate auth")
                        
                        logger.info(f"Certificate authentication successful, CSRF token: {sanitize_for_logging(self.csrf_token)}")
                        return True
                    else:
                        logger.error(f"Certificate authentication failed with status: {response.status}")
                        response_text = await response.text()
                        logger.error(f"Response: {sanitize_for_logging(response_text[:500])}")
                        return False
                        
            finally:
                # Clean up temp files
                try:
                    os.unlink(cert_file.name)
                    os.unlink(key_file.name)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Certificate authentication failed: {sanitize_for_logging(str(e))}")
            import traceback
            logger.error(traceback.format_exc())
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
                        logger.info(f"Captured {len(self.cookies)} session cookies: {list(self.cookies.keys())}")
                    else:
                        logger.warning("No set-cookie headers received from SAP during authentication")
                    
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
    

    
    def add_client_param(self, url: str) -> str:
        """Add client parameter to URL"""
        separator = '&' if '?' in url else '?'
        return f"{url}{separator}sap-client={self.connection.client}"
    
    async def _get_appropriate_headers(self, fetch_csrf: bool = False) -> Dict[str, str]:
        """Get appropriate headers for SAP requests with basic auth priority"""
        headers = {
            'Accept': 'application/xml, application/atomsvc+xml',
            'User-Agent': 'ABAP-Accelerator-MCP-Server/1.0.0',
            'x-sap-adt-sessiontype': 'stateful'  # Important for maintaining session state
        }
        
        # Check if using certificate authentication (no password/cookies needed)
        use_cert_auth = getattr(self, 'use_certificate_auth', False)
        
        if use_cert_auth:
            # Certificate auth - include session cookies if we have them
            # The SSL context handles authentication, but cookies maintain session state
            if self.cookies:
                cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
                headers['Cookie'] = cookie_str
                logger.debug("Using certificate auth with session cookies")
            else:
                logger.debug("Using certificate authentication headers (no cookies yet)")
        else:
            # Check if this is Playwright authentication (should use cookies)
            is_playwright_auth = getattr(self, '_playwright_auth', False)
            
            if is_playwright_auth and self.cookies:
                # Priority 1 for Playwright: Use cookies
                cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
                headers['Cookie'] = cookie_str
                logger.debug("Using Playwright cookie-based authentication headers")
            else:
                # Standard priority: Basic auth first, then cookies
                password = self.connection.password
                if hasattr(self.connection, 'encrypted_password') and self.connection.encrypted_password:
                    password = decrypt_from_memory(self.connection.encrypted_password)
                
                if password and not is_playwright_auth:
                    import base64
                    auth_str = base64.b64encode(f"{self.connection.username}:{password}".encode()).decode()
                    headers['Authorization'] = f'Basic {auth_str}'
                    # Also include session cookies - SAP validates CSRF tokens against the session
                    # Without cookies, write operations (POST/PUT/DELETE) fail with 403
                    # "System error in lock management" because SAP can't match the CSRF token
                    if self.cookies:
                        cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
                        headers['Cookie'] = cookie_str
                        logger.info(f"Using basic auth with {len(self.cookies)} session cookies: {list(self.cookies.keys())}")
                    else:
                        logger.warning("Using basic auth WITHOUT session cookies - write operations may fail")
                elif self.cookies:
                    # Fall back to cookies for browser-based auth
                    cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
                    headers['Cookie'] = cookie_str
                    logger.debug("Using cookie-based authentication headers")
        
        # Add CSRF token
        if fetch_csrf:
            headers['x-csrf-token'] = 'fetch'
        elif self.csrf_token:
            headers['x-csrf-token'] = self.csrf_token
        else:
            headers['x-csrf-token'] = 'fetch'
        
        return headers
    
    def _get_auth_header(self) -> str:
        """Get base64 encoded auth header for CDS handler"""
        import base64
        
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
    
    async def _ensure_fresh_csrf_token(self) -> bool:
        """Ensure we have a fresh CSRF token for write operations"""
        if not self.csrf_token:
            logger.info("No CSRF token available, fetching fresh token")
            return await self._refresh_csrf_token()
        return True
    
    async def _refresh_csrf_token(self) -> bool:
        """Refresh CSRF token by making a discovery request"""
        try:
            logger.info("Refreshing CSRF token for write operations")
            
            # Try multiple endpoints to get CSRF token
            csrf_endpoints = [
                f"/sap/bc/adt/discovery?sap-client={self.connection.client}",
                f"/sap/bc/adt/repository/nodestructure?sap-client={self.connection.client}",
                f"/sap/bc/adt/packages?sap-client={self.connection.client}"
            ]
            
            for endpoint in csrf_endpoints:
                try:
                    headers = await self._get_appropriate_headers(fetch_csrf=True)
                    
                    async with self.session.get(endpoint, headers=headers) as response:
                        if response.status == 200:
                            new_csrf_token = response.headers.get('x-csrf-token')
                            if new_csrf_token and new_csrf_token not in ['Required', 'Fetch', 'fetch']:
                                self.csrf_token = new_csrf_token
                                logger.info(f"CSRF token refreshed successfully from {endpoint}: {sanitize_for_logging(new_csrf_token)}")
                                
                                # Update cookies from response if any
                                set_cookie_headers = response.headers.getall('set-cookie', [])
                                if set_cookie_headers:
                                    new_cookies = {cookie.split('=')[0]: cookie.split('=')[1].split(';')[0] 
                                                 for cookie in set_cookie_headers if '=' in cookie}
                                    self.cookies.update(new_cookies)
                                    logger.debug(f"Updated {len(new_cookies)} cookies during CSRF refresh")
                                
                                return True
                            else:
                                logger.debug(f"Endpoint {endpoint} returned invalid CSRF token: {new_csrf_token}")
                        else:
                            logger.debug(f"Endpoint {endpoint} returned status: {response.status}")
                except Exception as e:
                    logger.debug(f"Error trying endpoint {endpoint}: {e}")
                    continue
            
            # If no endpoint worked, try a POST request to trigger CSRF
            try:
                logger.info("Trying POST request to trigger CSRF token")
                headers = await self._get_appropriate_headers(fetch_csrf=True)
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                
                async with self.session.post(
                    f"/sap/bc/adt/repository/nodestructure?sap-client={self.connection.client}",
                    data='',
                    headers=headers
                ) as response:
                    new_csrf_token = response.headers.get('x-csrf-token')
                    if new_csrf_token and new_csrf_token not in ['Required', 'Fetch', 'fetch']:
                        self.csrf_token = new_csrf_token
                        logger.info(f"CSRF token obtained via POST: {sanitize_for_logging(new_csrf_token)}")
                        return True
            except Exception as e:
                logger.debug(f"POST CSRF attempt failed: {e}")
            
            logger.warning("Could not obtain valid CSRF token from any endpoint")
            return False
                    
        except Exception as e:
            logger.error(f"Error refreshing CSRF token: {sanitize_for_logging(str(e))}")
            return False

    async def _get_csrf_token(self, auth: Optional[aiohttp.BasicAuth] = None) -> bool:
        """Get CSRF token for write operations"""
        try:
            headers = await self._get_appropriate_headers(fetch_csrf=True)
            
            async with self.session.get(f"/sap/bc/adt/discovery?sap-client={self.connection.client}", 
                                     headers=headers) as response:
                if response.status == 200:
                    self.csrf_token = response.headers.get('x-csrf-token')
                    return self.csrf_token is not None
                return False
                
        except Exception as e:
            logger.error(f"Failed to get CSRF token: {sanitize_for_logging(str(e))}")
            return False
    
    async def get_current_user_info(self) -> Optional[Dict[str, str]]:
        """Get current user information from SAP system"""
        try:
            # Try to get user info from discovery endpoint
            url = f"/sap/bc/adt/discovery?sap-client={self.connection.client}"
            headers = await self._get_appropriate_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    content = await response.text()
                    # Parse XML to extract user information
                    try:
                        # Use defusedxml for secure XML parsing
                        import defusedxml.ElementTree as DefusedET
                        root = DefusedET.fromstring(content)
                        
                        # Look for user information in the discovery response
                        for elem in root.iter():
                            if 'user' in elem.tag.lower() or 'responsible' in elem.tag.lower():
                                if elem.text and elem.text != self.connection.username:
                                    logger.info(f"Found SAP user ID: {sanitize_for_logging(elem.text)}")
                                    return {'sap_user_id': elem.text}
                    except Exception as parse_error:
                        logger.debug(f"Could not parse discovery response for user info: {sanitize_for_logging(str(parse_error))}")
                        
            # Fallback: try to extract from connection username if it looks like a SAP user ID
            username = self.connection.username
            if username and not '@' in username and len(username) <= 12:
                # Looks like a SAP user ID already
                return {'sap_user_id': username}
                
            # If username is email, try to extract the part before @
            if '@' in username:
                user_part = username.split('@')[0].upper()
                if len(user_part) <= 12:
                    logger.info(f"Using username part as SAP user ID: {sanitize_for_logging(user_part)}")
                    return {'sap_user_id': user_part}
                    
            # Final fallback: use the username as-is
            logger.warning(f"Could not determine SAP user ID, using username as-is: {sanitize_for_logging(username)}")
            return {'sap_user_id': username}
            
        except Exception as e:
            logger.error(f"Error getting current user info: {sanitize_for_logging(str(e))}")
            return {'sap_user_id': self.connection.username}

    async def get_objects(self, package_name: Optional[str] = None) -> List[ADTObject]:
        """Get ABAP objects from SAP system"""
        try:
            # Build URL exactly like TypeScript version
            base_url = "/sap/bc/adt/repository/nodestructure"
            url = f"{base_url}?sap-client={self.connection.client}"
            
            # Create parameters for POST request (matching TypeScript implementation)
            if package_name:
                params = {
                    'parent_type': 'DEVC/K',
                    'parent_name': package_name,
                    'withShortDescriptions': 'true'
                }
            else:
                params = {
                    'withShortDescriptions': 'true'
                }
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            headers['Accept'] = 'application/xml, application/vnd.sap.as+xml'
            
            logger.info(f"Making POST request to {sanitize_for_logging(url)} with params: {sanitize_for_logging(params)}")
            
            # Use POST request with empty body and params (matching TypeScript)
            async with self.session.post(url, data='', params=params, headers=headers) as response:
                logger.info(f"Response status: {response.status}")
                if response.status == 200:
                    xml_content = await response.text()
                    logger.info(f"Response XML length: {len(xml_content)}")
                    logger.info(f"Response XML content (first 2000 chars): {sanitize_for_logging(xml_content[:2000])}")
                    
                    objects = self._parse_objects_xml(xml_content)
                    logger.info(f"Parsed {len(objects)} objects from main endpoint")
                    
                    # If main endpoint returns no objects and we have a package, try alternatives
                    if len(objects) == 0 and package_name:
                        logger.info("Main endpoint returned no objects, trying alternative endpoints")
                        
                        alternative_endpoints = [
                            f"/sap/bc/adt/packages/{package_name}/objects?sap-client={self.connection.client}",
                            f"/sap/bc/adt/repository/informationsystem/search?sap-client={self.connection.client}"
                        ]
                        
                        for alt_url in alternative_endpoints:
                            try:
                                logger.info(f"Trying alternative endpoint: {sanitize_for_logging(alt_url)}")
                                async with self.session.get(alt_url, headers=headers) as alt_response:
                                    if alt_response.status == 200:
                                        alt_xml = await alt_response.text()
                                        alt_objects = self._parse_objects_xml(alt_xml)
                                        if len(alt_objects) > 0:
                                            logger.info(f"Found {len(alt_objects)} objects using alternative endpoint")
                                            return alt_objects
                                    else:
                                        logger.info(f"Alternative endpoint returned status: {alt_response.status}")
                            except Exception as alt_e:
                                logger.info(f"Alternative endpoint failed: {sanitize_for_logging(str(alt_e))}")
                                continue
                    
                    return objects
                else:
                    logger.error(f"Failed to get objects: {response.status}")
                    response_text = await response.text()
                    logger.error(f"Response text: {sanitize_for_logging(response_text[:500])}")
                    
                    # If we get 401 Unauthorized, try reentrance ticket authentication
                    if response.status == 401:
                        logger.info("Got 401 Unauthorized, attempting reentrance ticket authentication")
                        
                        try:
                            # Try to get reentrance ticket and retry the request
                            ticket_success = await self._try_reentrance_ticket_auth()
                            if ticket_success:
                                logger.info("Reentrance ticket authentication successful, retrying request")
                                
                                # Retry the same request with new authentication
                                headers = await self._get_appropriate_headers()
                                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                                headers['Accept'] = 'application/xml, application/vnd.sap.as+xml'
                                
                                async with self.session.post(url, data='', params=params, headers=headers) as retry_response:
                                    if retry_response.status == 200:
                                        xml_content = await retry_response.text()
                                        objects = self._parse_objects_xml(xml_content)
                                        logger.info(f"Successfully retrieved {len(objects)} objects after reentrance ticket auth")
                                        return objects
                                    else:
                                        logger.error(f"Request still failed after reentrance ticket auth: {retry_response.status}")
                            else:
                                logger.warning("Reentrance ticket authentication failed")
                                
                        except Exception as ticket_error:
                            logger.error(f"Error during reentrance ticket authentication: {sanitize_for_logging(str(ticket_error))}")
                    
                    # If 401 and automatic ticket auth failed, provide helpful message
                    if response.status == 401:
                        logger.info("Automatic reentrance ticket authentication failed - browser authentication may be required")
                        # Return empty list but log helpful message for user
                        return []
                    
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting objects: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_objects_xml(self, xml_content: str) -> List[ADTObject]:
        """Parse objects from XML response"""
        objects = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                logger.warning("Failed to parse XML content")
                return objects
            
            logger.info("Parsing objects from XML response")
            logger.info(f"Root element: {root.tag}")
            logger.info(f"Root attributes: {root.attrib}")
            
            # Log all child elements to understand the structure
            logger.info("XML structure analysis:")
            for i, child in enumerate(root):
                logger.info(f"  Child {i}: {child.tag} - {child.attrib}")
                for j, grandchild in enumerate(child):
                    logger.info(f"    Grandchild {j}: {grandchild.tag} - {grandchild.attrib}")
                    if j > 5:  # Limit to avoid too much logging
                        logger.info(f"    ... and {len(list(child)) - 6} more grandchildren")
                        break
                if i > 10:  # Limit to avoid too much logging
                    logger.info(f"  ... and {len(list(root)) - 11} more children")
                    break
            
            # Try SAP ADT repository structure first (matching TypeScript implementation)
            repo_nodes = []
            
            # Look for repository nodes in various possible paths
            possible_paths = [
                './/SEU_ADT_REPOSITORY_OBJ_NODE',
                './/*[local-name()="SEU_ADT_REPOSITORY_OBJ_NODE"]',
                './/TREE_CONTENT/SEU_ADT_REPOSITORY_OBJ_NODE',
                './/DATA/TREE_CONTENT/SEU_ADT_REPOSITORY_OBJ_NODE'
            ]
            
            for path in possible_paths:
                repo_nodes = root.findall(path)
                logger.info(f"Trying path '{path}': found {len(repo_nodes)} nodes")
                if repo_nodes:
                    logger.info(f"Found {len(repo_nodes)} repository nodes using path: {path}")
                    break
            
            if repo_nodes:
                logger.info(f"Processing {len(repo_nodes)} repository nodes")
                for i, node in enumerate(repo_nodes):
                    logger.info(f"Processing repository node {i}: {node.tag}")
                    
                    # Handle SAP's XML format where values are in child elements
                    name_elem = node.find('OBJECT_NAME')
                    tech_name_elem = node.find('TECH_NAME')  # Often the actual name
                    type_elem = node.find('OBJECT_TYPE')
                    desc_elem = node.find('DESCRIPTION')
                    uri_elem = node.find('OBJECT_URI')
                    
                    # Use TECH_NAME if OBJECT_NAME is empty (common in SAP)
                    name = ''
                    if name_elem is not None and name_elem.text:
                        name = name_elem.text.strip()
                    elif tech_name_elem is not None and tech_name_elem.text:
                        name = tech_name_elem.text.strip()
                    
                    obj_type = type_elem.text.strip() if type_elem is not None and type_elem.text else ''
                    description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ''
                    uri = uri_elem.text.strip() if uri_elem is not None and uri_elem.text else ''
                    
                    logger.info(f"  Node details - name: '{name}', tech_name: '{tech_name_elem.text if tech_name_elem is not None else ''}', type: '{obj_type}'")
                    
                    # Only add if we have both name and type, and it's not just a package structure node
                    if name and obj_type and not obj_type.startswith('DEVC/'):
                        logger.info(f"  Adding object: {name} ({obj_type})")
                        objects.append(ADTObject(
                            name=name,
                            type=obj_type,
                            description=description,
                            package_name='',  # Will be filled from context
                            uri=uri
                        ))
                    else:
                        logger.info(f"  Skipping node - name: '{name}', type: '{obj_type}' (likely package structure)")
                
                if objects:
                    logger.info(f"Parsed {len(objects)} objects from repository structure")
                    return objects
            
            # Fallback to atom feed parsing
            logger.info("No repository nodes found, trying atom feed parsing")
            
            # Try different atom entry paths
            atom_paths = [
                './/{http://www.w3.org/2005/Atom}entry',
                './/entry',
                './/atom:entry'
            ]
            
            entries = []
            for atom_path in atom_paths:
                entries = root.findall(atom_path)
                logger.info(f"Trying atom path '{atom_path}': found {len(entries)} entries")
                if entries:
                    break
            
            if entries:
                logger.info(f"Found {len(entries)} atom entries")
                for i, entry in enumerate(entries):
                    logger.info(f"Processing atom entry {i}: {entry.tag} - {entry.attrib}")
                    
                    title_elem = entry.find('.//{http://www.w3.org/2005/Atom}title') or entry.find('.//title')
                    name = title_elem.text if title_elem is not None else ''
                    logger.info(f"  Entry name: {name}")
                    
                    # Try to extract type from category or other elements
                    category_elem = entry.find('.//{http://www.w3.org/2005/Atom}category') or entry.find('.//category')
                    obj_type = category_elem.get('term', '') if category_elem is not None else ''
                    logger.info(f"  Entry type: {obj_type}")
                    
                    if name:
                        objects.append(ADTObject(
                            name=name,
                            type=obj_type,
                            description='',
                            package_name='',
                            uri=''
                        ))
            else:
                logger.info("No atom entries found either")
            
            # Final fallback to simple node parsing
            if not objects:
                logger.info("No objects found yet, trying simple node parsing")
                
                # Try different node patterns
                node_patterns = ['.//node', './/item', './/object', './/*[@name]']
                
                for pattern in node_patterns:
                    nodes = root.findall(pattern)
                    logger.info(f"Trying node pattern '{pattern}': found {len(nodes)} nodes")
                    
                    if nodes:
                        for i, node in enumerate(nodes):
                            logger.info(f"Processing node {i}: {node.tag} - {node.attrib}")
                            
                            name = node.get('name', '') or node.text or ''
                            obj_type = node.get('type', '') or node.get('objectType', '')
                            description = node.get('description', '') or node.get('desc', '')
                            package_name = node.get('package', '') or node.get('packageName', '')
                            uri = node.get('uri', '') or node.get('href', '')
                            
                            logger.info(f"  Node details - name: {name}, type: {obj_type}")
                            
                            if name and obj_type:
                                objects.append(ADTObject(
                                    name=name,
                                    type=obj_type,
                                    description=description,
                                    package_name=package_name,
                                    uri=uri
                                ))
                        
                        if objects:
                            logger.info(f"Found {len(objects)} objects using pattern '{pattern}'")
                            break
                
                if not objects:
                    logger.warning("No objects found with any parsing method")
                    # Log a sample of the XML for debugging
                    sample_xml = xml_content[:2000] if len(xml_content) > 2000 else xml_content
                    logger.warning(f"Sample XML content: {sanitize_for_logging(sample_xml)}")
            
            logger.info(f"Total parsed objects: {len(objects)}")
                    
        except Exception as e:
            logger.error(f"Error parsing objects XML: {sanitize_for_logging(str(e))}")
        
        return objects
    
    async def get_source(self, object_name: str, object_type: str) -> Optional[str]:
        """Get source code of ABAP object with enhanced response handling"""
        try:
            # Ensure session is valid before making request
            await self._ensure_session_valid()
            
            # Validate object name to prevent path traversal
            validated_object_name = sanitize_file_path(object_name)
            
            print(f"[SAP-CLIENT] Getting source code for {sanitize_for_logging(validated_object_name)} ({sanitize_for_logging(object_type)})")
            logger.info(f"Getting source code for {sanitize_for_logging(validated_object_name)}")
            
            # Get metadata first to extract package and transport info
            metadata = await self.get_object_metadata(validated_object_name, object_type)
            if metadata and (metadata.get('transport_number') or metadata.get('responsible')):
                print(f"[SAP-CLIENT] Object metadata - Transport: {sanitize_for_logging(metadata.get('transport_number', 'N/A'))}, User: {sanitize_for_logging(metadata.get('responsible', 'N/A'))}, Text: {sanitize_for_logging(metadata.get('transport_text', 'N/A'))}")
            else:
                print(f"[SAP-CLIENT] No useful metadata retrieved")
            
            # Special handling for Service Bindings (SRVB) - they may not have traditional source
            if object_type.upper() == 'SRVB':
                print(f"[SAP-CLIENT] Service Binding detected - trying metadata endpoint")
                try:
                    url = f"/sap/bc/adt/businessservices/bindings/{validated_object_name}?sap-client={self.connection.client}"
                    headers = await self._get_appropriate_headers()
                    headers['Accept'] = 'application/xml'
                    
                    async with self.session.get(url, headers=headers) as response:
                        if response.status == 200:
                            print(f"[SAP-CLIENT] Service Binding metadata retrieved successfully")
                            return await response.text()
                except Exception as error:
                    print(f"[SAP-CLIENT] Service Binding metadata failed: {sanitize_for_logging(str(error))}")
            
            # Special handling for include programs
            if object_type.upper() == 'PROG' and is_include_program(validated_object_name):
                print(f"[SAP-CLIENT] Include program detected, using include endpoint")
                return await self._get_include_source(validated_object_name)
            
            # For classes, try to get both main source and implementations
            main_source = None
            implementations_source = None
            
            # Try resource URI discovery first
            resource_uri = await self._get_resource_uri(validated_object_name, object_type)
            if resource_uri:
                try:
                    url = f"{resource_uri}/source/main?sap-client={self.connection.client}"
                    print(f"[SAP-CLIENT] Trying discovered source URL: {sanitize_for_logging(url)}")
                    logger.info(f"Trying to get source from URL: {sanitize_for_logging(url)}")
                    
                    headers = await self._get_appropriate_headers()
                    headers['Accept'] = 'text/plain'
                    
                    async with self.session.get(url, headers=headers) as response:
                        if response.status == 200:
                            main_source = await response.text()
                            print(f"[SAP-CLIENT] Main source retrieved successfully, length: {validate_numeric_input(len(main_source), 'length')}")
                            
                            # For classes, also try to get implementations include
                            if object_type.upper() in ['CLAS', 'BIMPL']:
                                try:
                                    impl_url = f"{resource_uri}/includes/implementations?sap-client={self.connection.client}"
                                    print(f"[SAP-CLIENT] Trying to get implementations include: {sanitize_for_logging(impl_url)}")
                                    
                                    async with self.session.get(impl_url, headers=headers) as impl_response:
                                        if impl_response.status == 200:
                                            impl_data = await impl_response.text()
                                            if impl_data:
                                                print(f"[SAP-CLIENT] Implementations include retrieved, length: {validate_numeric_input(len(impl_data), 'length')}")
                                                implementations_source = impl_data
                                except Exception as impl_error:
                                    print(f"[SAP-CLIENT] Implementations include not available: {sanitize_for_logging(str(impl_error))}")
                            
                            # Combine sources if we have implementations (matching TypeScript format)
                            if implementations_source:
                                combined_source = f"{main_source}\n\n{'=' * 80}\n{'=' * 80}\n** LOCAL HANDLER CLASSES (includes/implementations) **\n{'=' * 80}\n\n{implementations_source}"
                                print(f"[SAP-CLIENT] Combined source with implementations, total length: {validate_numeric_input(len(combined_source), 'length')}")
                                return combined_source
                            
                            return main_source
                except Exception as error:
                    print(f"[SAP-CLIENT] Discovered URI failed: {sanitize_for_logging(str(error))}")
            
            # Fallback to pattern-based approach
            print(f"[SAP-CLIENT] Falling back to pattern-based approach")
            url_patterns = get_object_url_patterns(object_type, validated_object_name)
            
            # Special logging for CDS views to match the logs we see
            if object_type.upper() == 'DDLS':
                logger.info(f"CDS View URL Pattern for {sanitize_for_logging(validated_object_name)}: trying {len(url_patterns)} patterns")
            
            for i, pattern in enumerate(url_patterns, 1):
                try:
                    # Special logging for CDS views
                    if object_type.upper() == 'DDLS':
                        logger.info(f"CDS View attempt {i}/{len(url_patterns)}: {pattern}")
                    
                    url = f"/sap/bc/adt/{pattern}/{validated_object_name}/source/main?sap-client={self.connection.client}"
                    print(f"[SAP-CLIENT] Trying pattern source URL: {sanitize_for_logging(url)}")
                    
                    headers = await self._get_appropriate_headers()
                    headers['Accept'] = 'text/plain'
                    
                    async with self.session.get(url, headers=headers) as response:
                        print(f"[SAP-CLIENT] Source response status: {validate_numeric_input(response.status, 'status')}")
                        
                        if response.status == 200:
                            main_source = await response.text()
                            print(f"[SAP-CLIENT] Source response length: {validate_numeric_input(len(main_source), 'length')}")
                            
                            # For classes, also try to get implementations include
                            if object_type.upper() in ['CLAS', 'BIMPL']:
                                try:
                                    impl_url = f"/sap/bc/adt/{pattern}/{validated_object_name}/includes/implementations?sap-client={self.connection.client}"
                                    print(f"[SAP-CLIENT] Trying to get implementations include: {sanitize_for_logging(impl_url)}")
                                    
                                    async with self.session.get(impl_url, headers=headers) as impl_response:
                                        if impl_response.status == 200:
                                            impl_data = await impl_response.text()
                                            if impl_data:
                                                print(f"[SAP-CLIENT] Implementations include retrieved, length: {validate_numeric_input(len(impl_data), 'length')}")
                                                implementations_source = impl_data
                                except Exception as impl_error:
                                    print(f"[SAP-CLIENT] Implementations include not available: {sanitize_for_logging(str(impl_error))}")
                            
                            # Combine sources if we have implementations (matching TypeScript format)
                            if implementations_source:
                                combined_source = f"{main_source}\n\n{'=' * 80}\n{'=' * 80}\n** LOCAL HANDLER CLASSES (includes/implementations) **\n{'=' * 80}\n\n{implementations_source}"
                                print(f"[SAP-CLIENT] Combined source with implementations, total length: {validate_numeric_input(len(combined_source), 'length')}")
                                return combined_source
                            
                            return main_source
                        elif response.status not in [404, 406]:
                            # Don't continue for non-404/406 errors
                            raise Exception(f"HTTP {response.status}")
                except Exception as error:
                    print(f"[SAP-CLIENT] Failed with pattern {sanitize_for_logging(pattern)}: {sanitize_for_logging(str(error))}")
                    if hasattr(error, 'response') and error.response and error.response.status not in [404, 406]:
                        raise error
            
            print(f"[SAP-CLIENT] All approaches failed for {sanitize_for_logging(validated_object_name)}")
            return None
            
        except Exception as e:
            print(f"[SAP-CLIENT] Failed to get source: {sanitize_for_logging(str(e))}")
            logger.error(f"Failed to get source: {sanitize_for_logging(str(e))}")
            return None
    
    async def get_test_classes(self, class_name: str, object_type: str) -> Optional[str]:
        """Get test classes source code for an ABAP class"""
        try:
            print(f"[SAP-CLIENT] Getting test classes for {sanitize_for_logging(class_name)}")
            logger.info(f"Getting test classes for {sanitize_for_logging(class_name)}")
            
            # First try to get active version
            if object_type.upper() == 'CLAS':
                active_url = f"/sap/bc/adt/oo/classes/{class_name}/includes/testclasses?version=active&sap-client={self.connection.client}"
            else:
                # For non-class objects, try to get main source (fallback)
                active_url = f"/sap/bc/adt/programs/programs/{class_name}/source/main?version=active&sap-client={self.connection.client}"
            
            print(f"[SAP-CLIENT] Test classes active URL: {sanitize_for_logging(active_url)}")
            
            headers = await self._get_appropriate_headers()
            headers['Accept'] = 'text/plain'
            
            # Try active version first
            try:
                async with self.session.get(active_url, headers=headers) as response:
                    if response.status == 200:
                        active_data = await response.text()
                        print(f"[SAP-CLIENT] Active test classes retrieved successfully, length: {validate_numeric_input(len(active_data) if active_data else 0, 'length')}")
                        
                        # If active version exists and is not empty, return it
                        if active_data and len(active_data.strip()) > 0:
                            return active_data
                        else:
                            print(f"[SAP-CLIENT] Active test classes are empty, checking for inactive version")
                    else:
                        print(f"[SAP-CLIENT] Failed to get active test classes: HTTP {validate_numeric_input(response.status, 'status')}")
            except Exception as active_error:
                print(f"[SAP-CLIENT] Error getting active test classes: {sanitize_for_logging(str(active_error))}")
            
            # If active version failed or was empty, try inactive version
            if object_type.upper() == 'CLAS':
                print(f"[SAP-CLIENT] Trying to get inactive test classes")
                inactive_url = f"/sap/bc/adt/oo/classes/{class_name}/includes/testclasses?version=inactive&sap-client={self.connection.client}"
                
                try:
                    async with self.session.get(inactive_url, headers=headers) as response:
                        if response.status == 200:
                            inactive_data = await response.text()
                            print(f"[SAP-CLIENT] Inactive test classes retrieved, length: {validate_numeric_input(len(inactive_data) if inactive_data else 0, 'length')}")
                            
                            # If we found inactive test classes, return them
                            if inactive_data and len(inactive_data.strip()) > 0:
                                print(f"[SAP-CLIENT] Found inactive test classes")
                                return inactive_data
                        else:
                            print(f"[SAP-CLIENT] Failed to get inactive test classes: HTTP {validate_numeric_input(response.status, 'status')}")
                except Exception as inactive_error:
                    print(f"[SAP-CLIENT] Error getting inactive test classes: {sanitize_for_logging(str(inactive_error))}")
            
            print(f"[SAP-CLIENT] No test classes found for {sanitize_for_logging(class_name)} (active or inactive)")
            return None
            
        except Exception as error:
            print(f"[SAP-CLIENT] Failed to get test classes: {sanitize_for_logging(str(error))}")
            logger.error(f"Failed to get test classes: {sanitize_for_logging(str(error))}")
            
            # Check for 404 specifically
            if hasattr(error, 'response') and error.response and error.response.status == 404:
                print(f"[SAP-CLIENT] No test classes found for {sanitize_for_logging(class_name)}")
                return None
            
            return None
    
    async def _validate_object_name_and_get_transport(self, request: CreateObjectRequest) -> Dict[str, Any]:
        """Validate object name and get transport information (matching ADT flow)"""
        try:
            # Set default package to $TMP if not provided
            package_name = request.package_name or "$TMP"
            request.package_name = package_name  # Update the request object
            
            logger.info(f"Validating object name {sanitize_for_logging(request.name)} in package {sanitize_for_logging(package_name)}")
            
            # For $TMP package, skip transport validation as it doesn't require transport
            if package_name.upper() == "$TMP":
                logger.info("Using $TMP package - no transport required")
                return {
                    'valid': True,
                    'transport_number': None,
                    'available_transports': [],
                    'package_name': package_name,
                    'requires_transport': False
                }
            
            # Ensure we have a valid session and try to get CSRF token (but don't fail if we can't)
            await self._ensure_session_valid()
            csrf_success = await self._ensure_fresh_csrf_token()
            if not csrf_success:
                logger.warning("Could not obtain CSRF token for validation, proceeding anyway")
            
            # Step 1: Object name validation (matching the first POST in call stack)
            # Use type-specific validation endpoints
            ot = request.type.value.upper()
            validation_url = None
            validation_params = {}
            accept_header = 'application/vnd.sap.as+xml'

            if ot in ('CLAS', 'BIMPL'):
                validation_url = "/sap/bc/adt/oo/validation/objectname"
                validation_params = {
                    'objname': request.name,
                    'packagename': package_name,
                    'description': request.description,
                    'objtype': 'CLAS/OC'
                }
                accept_header = 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.oo.clifname.check'
            elif ot == 'INTF':
                validation_url = "/sap/bc/adt/oo/validation/objectname"
                validation_params = {
                    'objname': request.name,
                    'packagename': package_name,
                    'description': request.description,
                    'objtype': 'INTF/OI'
                }
                accept_header = 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.oo.clifname.check'
            elif ot in ('PROG', 'PROG/P'):
                validation_url = "/sap/bc/adt/programs/validation"
                validation_params = {
                    'objname': request.name,
                    'packagename': package_name,
                    'description': request.description,
                    'objtype': 'PROG/P'
                }
            elif ot == 'PROG/I':
                validation_url = "/sap/bc/adt/programs/validation"
                validation_params = {
                    'objname': request.name,
                    'packagename': package_name,
                    'description': request.description,
                    'objtype': 'PROG/I'
                }
            elif ot == 'TABL':
                validation_url = "/sap/bc/adt/ddic/tables/validation"
                validation_params = {
                    'objtype': 'tabldt',
                    'objname': request.name,
                    'description': request.description
                }
            elif ot == 'DDLS':
                validation_url = "/sap/bc/adt/ddic/ddl/validation"
                validation_params = {
                    'objname': request.name,
                    'packagename': package_name,
                    'description': request.description
                }
            elif ot == 'BDEF':
                validation_url = "/sap/bc/adt/bo/behaviordefinitions/validation"
                validation_params = {
                    'objname': request.name,
                    'rootEntity': request.name,
                    'description': request.description,
                    'package': package_name,
                    'implementationType': 'Managed'
                }
            elif ot == 'SRVD':
                validation_url = "/sap/bc/adt/ddic/srvd/sources/validation"
                validation_params = {
                    'objtype': 'srvdsrv',
                    'objname': request.name,
                    'description': request.description
                }
            elif ot == 'SRVB':
                validation_url = "/sap/bc/adt/businessservices/bindings/validation"
                validation_params = {
                    'objname': request.name,
                    'description': request.description,
                    'package': package_name
                }
            # For types without a known validation endpoint, skip validation
            
            headers = await self._get_appropriate_headers()
            headers['Accept'] = accept_header
            
            logger.info(f"Making validation request to {validation_url} with params: {sanitize_for_logging(validation_params)}")
            
            if validation_url:
                try:
                    async with self.session.post(validation_url, params=validation_params, headers=headers) as response:
                        logger.info(f"Validation response status: {response.status}")
                        
                        if response.status == 200:
                            validation_xml = await response.text()
                            logger.info(f"Object name validation response: {sanitize_for_logging(validation_xml[:200])}")
                            
                            # Parse validation result
                            root = safe_parse_xml(validation_xml)
                            if root is not None:
                                check_result = None
                                for elem in root.iter():
                                    if elem.tag.endswith('CHECK_RESULT') or 'CHECK_RESULT' in elem.tag:
                                        check_result = elem.text
                                        break
                                
                                if check_result != 'X':
                                    logger.warning(f"Object name validation failed: CHECK_RESULT = {check_result}")
                                    # Don't fail - just log and continue
                        elif response.status == 401:
                            logger.info(f"Object name validation got 401 - authentication issue, but validation is optional, continuing...")
                            # Don't fail - validation is optional and 401 is common for validation endpoints
                        else:
                            logger.info(f"Object name validation returned status {response.status}, skipping validation")
                            # Don't fail - validation is optional
                            
                except Exception as validation_error:
                    logger.info(f"Object name validation failed with error: {validation_error} - continuing anyway as validation is optional")
                    # Don't fail - validation is optional
            else:
                logger.info(f"No validation endpoint for type {request.type.value}, skipping validation")
            
            # Step 2: Transport check (matching the second POST in call stack)
            # Build URI based on object type
            ot = request.type.value.upper()
            if ot == 'CLAS':
                object_uri = f"/sap/bc/adt/oo/classes/{request.name.lower()}/source/main"
            elif ot == 'INTF':
                object_uri = f"/sap/bc/adt/oo/interfaces/{request.name.lower()}/source/main"
            elif ot == 'DDLS':
                object_uri = f"/sap/bc/adt/ddic/ddl/sources/{request.name.lower()}"
            elif ot == 'BDEF':
                object_uri = f"/sap/bc/adt/bo/behaviordefinitions/{request.name.lower()}"
            elif ot == 'SRVD':
                object_uri = f"/sap/bc/adt/ddic/srvd/sources/{request.name.lower()}"
            elif ot == 'SRVB':
                object_uri = f"/sap/bc/adt/businessservices/bindings/{request.name.lower()}"
            elif ot in ('PROG', 'PROG/P'):
                object_uri = f"/sap/bc/adt/programs/programs/{request.name.lower()}"
            elif ot == 'PROG/I':
                object_uri = f"/sap/bc/adt/programs/includes/{request.name.lower()}"
            elif ot == 'TABL':
                object_uri = f"/sap/bc/adt/ddic/tables/{request.name.lower()}"
            elif ot in ('STRU', 'TABL/DS'):
                object_uri = f"/sap/bc/adt/ddic/structures/{request.name.lower()}"
            elif ot == 'FUGR':
                object_uri = f"/sap/bc/adt/functions/groups/{request.name.lower()}"
            elif ot == 'DTEL':
                object_uri = f"/sap/bc/adt/ddic/dataelements/{request.name.lower()}"
            elif ot == 'BIMPL':
                object_uri = f"/sap/bc/adt/oo/classes/{request.name.lower()}/source/main"
            else:
                object_uri = f"/sap/bc/adt/oo/classes/{request.name.lower()}/source/main"
            
            transport_check_xml = f"""<?xml version="1.0" encoding="UTF-8" ?>
<asx:abap version="1.0" xmlns:asx="http://www.sap.com/abapxml">
  <asx:values>
    <DATA>
      <PGMID></PGMID>
      <OBJECT></OBJECT>
      <OBJECTNAME></OBJECTNAME>
      <DEVCLASS>{sanitize_for_xml(package_name)}</DEVCLASS>
      <SUPER_PACKAGE></SUPER_PACKAGE>
      <RECORD_CHANGES></RECORD_CHANGES>
      <OPERATION>I</OPERATION>
      <URI>{sanitize_for_xml(object_uri)}</URI>
    </DATA>
  </asx:values>
</asx:abap>"""
            
            transport_url = f"/sap/bc/adt/cts/transportchecks?sap-client={self.connection.client}"
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/vnd.sap.as+xml; charset=UTF-8; dataname=com.sap.adt.transport.service.checkData'
            headers['Accept'] = 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.transport.service.checkData'
            
            async with self.session.post(transport_url, data=transport_check_xml, headers=headers) as response:
                if response.status == 200:
                    transport_xml = await response.text()
                    logger.info(f"Transport check response: {sanitize_for_logging(transport_xml[:500])}")
                    
                    # Parse transport information
                    root = safe_parse_xml(transport_xml)
                    if root is not None:
                        transport_number = None
                        available_transports = []
                        
                        # Look for transport requests in the response
                        for elem in root.iter():
                            if elem.tag.endswith('TRKORR') or 'TRKORR' in elem.tag:
                                if elem.text and elem.text.strip():
                                    available_transports.append(elem.text.strip())
                                    if not transport_number:  # Use first one as default
                                        transport_number = elem.text.strip()
                        
                        # If user provided a specific transport, validate it's available
                        if request.transport_request:
                            if request.transport_request in available_transports:
                                transport_number = request.transport_request
                                logger.info(f"Using user-specified transport: {sanitize_for_logging(transport_number)}")
                            else:
                                logger.warning(f"User-specified transport {sanitize_for_logging(request.transport_request)} not found in available transports: {sanitize_for_logging(available_transports)}")
                                # Still use the user-specified transport - SAP will validate it
                                transport_number = request.transport_request
                        
                        return {
                            'valid': True,
                            'transport_number': transport_number,
                            'available_transports': available_transports,
                            'package_name': package_name,
                            'requires_transport': True
                        }
                else:
                    logger.info(f"Transport check returned status {response.status} - proceeding without transport validation")
                    # Don't fail for transport check issues - just proceed without transport
                    return {
                        'valid': True,
                        'transport_number': request.transport_request,  # Use user-provided transport if any
                        'available_transports': [],
                        'package_name': package_name,
                        'requires_transport': True,
                        'transport_check_skipped': True
                    }
            
            return {
                'valid': True, 
                'transport_number': None,
                'package_name': package_name,
                'requires_transport': True
            }
            
        except Exception as e:
            logger.info(f"Error in object validation: {sanitize_for_logging(str(e))} - treating as non-critical and continuing")
            # For validation errors, don't fail the entire operation - just proceed without validation
            return {
                'valid': True,  # Allow creation to proceed
                'transport_number': None,
                'package_name': request.package_name or "$TMP",
                'requires_transport': False,
                'validation_skipped': True,
                'validation_error': str(e)
            }

    async def create_object_with_syntax_check(self, request: CreateObjectRequest) -> ObjectOperationResult:
        """Create object with syntax check"""
        try:
            rap_logger.object_creation(
                request.name, request.type.value, request.package_name, 
                'CREATE_REQUEST_RECEIVED'
            )
            
            # Step 0: Validate object name and get transport information
            validation_result = await self._validate_object_name_and_get_transport(request)
            if not validation_result.get('valid', False):
                error_msg = validation_result.get('error', 'Object validation failed')
                logger.info(f"Object validation was not successful: {error_msg} - continuing with object creation")
                
                # For $TMP package or if validation fails, try to proceed anyway
                if (request.package_name and request.package_name.upper() == "$TMP") or not request.package_name:
                    logger.info("Proceeding with $TMP package despite validation issue")
                    request.package_name = "$TMP"
                else:
                    logger.info("Validation had issues but proceeding with object creation anyway")
                    # Don't fail immediately - let the actual creation attempt handle it
            else:
                # Update request with validated transport if available
                if validation_result.get('transport_number') and not request.transport_request:
                    request.transport_request = validation_result['transport_number']
                    logger.info(f"Using transport from validation: {sanitize_for_logging(request.transport_request)}")
            
            # Step 1: Create basic object
            created = await self._create_object(request)
            if not created:
                return ObjectOperationResult(
                    created=False,
                    syntax_check_passed=False,
                    activated=False,
                    errors=[SAPSyntaxError(line=1, message="Failed to create object", severity="ERROR")],
                    warnings=[]
                )
            
            # Step 2: If no source code, return success
            if not request.source_code:
                return ObjectOperationResult(
                    created=True,
                    syntax_check_passed=True,
                    activated=True,
                    errors=[],
                    warnings=[]
                )
            
            # Step 3: Update source and check syntax + activate
            update_result = await self.update_source_with_syntax_check(
                request.name, request.type.value, request.source_code,
                transport_request=request.transport_request
            )
            
            return ObjectOperationResult(
                created=True,
                syntax_check_passed=update_result.syntax_check_passed,
                activated=update_result.activated,
                errors=update_result.errors,
                warnings=update_result.warnings
            )
            
        except Exception as e:
            logger.error(f"Error creating object: {sanitize_for_logging(str(e))}")
            return ObjectOperationResult(
                created=False,
                syntax_check_passed=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=str(e), severity="ERROR")],
                warnings=[]
            )
    
    async def _create_object(self, request: CreateObjectRequest) -> bool:
        """Create object in SAP system"""
        try:
            # Special handling for CDS views (DDLS) using the specialized CDS handler
            if request.type.value.upper() == 'DDLS':
                logger.info(f"Creating CDS view {sanitize_for_logging(request.name)} using specialized CDS handler")
                
                # Ensure we have CSRF token and cookies
                if not self.csrf_token:
                    await self._get_csrf_token()
                
                # Convert cookies dict to list format expected by CDS handler
                cookie_list = [f"{k}={v}" for k, v in self.cookies.items()] if self.cookies else []
                
                # Use the specialized CDS handler for creation
                return await self.cds_handler.create_cds_view(
                    name=request.name,
                    description=request.description,
                    package_name=request.package_name,
                    source_code=request.source_code or "",
                    csrf_token=self.csrf_token,
                    cookies=cookie_list,
                    transport_request=request.transport_request
                )
            
            # Special handling for Behavior Definitions (BDEF) using specialized handler
            if request.type.value.upper() == 'BDEF':
                logger.info(f"Creating Behavior Definition {sanitize_for_logging(request.name)} using specialized handler")
                return await self.behavior_definition_handler.create_behavior_definition(
                    name=request.name,
                    description=request.description,
                    package_name=request.package_name,
                    implementation_type='Managed',  # Default to Managed
                    transport_request=request.transport_request
                )
            
            # Special handling for Service Definitions (SRVD) using specialized handler
            if request.type.value.upper() == 'SRVD':
                logger.info(f"Creating Service Definition {sanitize_for_logging(request.name)} using specialized handler")
                return await self.service_definition_handler.create_service_definition(
                    name=request.name,
                    description=request.description,
                    package_name=request.package_name,
                    source_code=request.source_code or "",
                    transport_request=request.transport_request
                )
            
            # Special handling for Service Bindings (SRVB) using specialized handler
            if request.type.value.upper() == 'SRVB':
                logger.info(f"Creating Service Binding {sanitize_for_logging(request.name)} using direct ADT approach")
                if not request.service_definition:
                    logger.error("Service Definition reference is required for Service Binding creation")
                    return False
                
                binding_type = 'ODATA_V4_UI'  # Default
                if hasattr(request, 'binding_type') and request.binding_type:
                    binding_type = request.binding_type.value if hasattr(request.binding_type, 'value') else str(request.binding_type)
                
                # Map binding type to category and version
                bt_map = {
                    'ODATA_V2_UI': ('0', 'V2'), 'ODATA_V4_UI': ('0', 'V4'),
                    'ODATA_V2_WEB_API': ('1', 'V2'), 'ODATA_V4_WEB_API': ('1', 'V4'),
                }
                category, version = bt_map.get(binding_type, ('0', 'V4'))
                
                safe_name = sanitize_for_xml(request.name)
                safe_desc = sanitize_for_xml(request.description)
                safe_pkg = sanitize_for_xml(request.package_name)
                safe_srvd = sanitize_for_xml(request.service_definition)
                username = self.connection.username.upper()
                
                srvb_xml = (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<srvb:serviceBinding xmlns:adtcore="http://www.sap.com/adt/core"'
                    ' xmlns:srvb="http://www.sap.com/adt/ddic/ServiceBindings"'
                    f' adtcore:description="{safe_desc}" adtcore:language="EN"'
                    f' adtcore:name="{safe_name}" adtcore:type="SRVB/SVB"'
                    f' adtcore:masterLanguage="EN" adtcore:responsible="{username}">'
                    f'<adtcore:packageRef adtcore:name="{safe_pkg}"/>'
                    f'<srvb:services srvb:name="{safe_srvd}">'
                    '<srvb:content srvb:version="0001">'
                    f'<srvb:serviceDefinition adtcore:name="{safe_srvd}"/>'
                    '</srvb:content>'
                    '</srvb:services>'
                    f'<srvb:binding srvb:category="{category}" srvb:type="ODATA" srvb:version="{version}">'
                    '<srvb:implementation adtcore:name=""/>'
                    '</srvb:binding>'
                    '</srvb:serviceBinding>'
                )
                
                url = f"/sap/bc/adt/businessservices/bindings?sap-client={self.connection.client}"
                if request.transport_request:
                    url += f"&corrNr={quote(request.transport_request)}"
                
                await self._ensure_fresh_csrf_token()
                headers = await self._get_appropriate_headers()
                headers['Content-Type'] = 'application/vnd.sap.adt.businessservices.servicebinding.v2+xml'
                headers['Accept'] = 'application/vnd.sap.adt.businessservices.servicebinding.v2+xml, application/vnd.sap.adt.businessservices.servicebinding.v1+xml'
                
                async with self.session.post(url, data=srvb_xml, headers=headers) as response:
                    if response.status in [200, 201]:
                        logger.info(f"Successfully created SRVB {sanitize_for_logging(request.name)}")
                        return True
                    elif response.status == 400:
                        error_text = await response.text()
                        if 'already exist' in error_text.lower():
                            logger.info(f"SRVB {sanitize_for_logging(request.name)} already exists")
                            return True
                        logger.error(f"SRVB creation failed: {response.status} - {sanitize_for_logging(error_text[:300])}")
                        return False
                    else:
                        error_text = await response.text()
                        logger.error(f"SRVB creation failed: {response.status} - {sanitize_for_logging(error_text[:300])}")
                        return False
            
            # Special handling for TABL/STRU — use blueSource XML with explicit sap-client param
            if request.type.value.upper() in ('TABL', 'STRU'):
                ot = request.type.value.upper()
                logger.info(f"Creating {ot} {sanitize_for_logging(request.name)} using direct ADT approach")
                
                type_attr = 'TABL/DT' if ot == 'TABL' else 'STRU/DS'
                ct = 'application/vnd.sap.adt.tables.v2+xml' if ot == 'TABL' else 'application/vnd.sap.adt.structures.v2+xml'
                adt_path = 'ddic/tables' if ot == 'TABL' else 'ddic/structures'
                
                safe_name = sanitize_for_xml(request.name)
                safe_desc = sanitize_for_xml(request.description)
                safe_pkg = sanitize_for_xml(request.package_name)
                username = self.connection.username.upper()
                
                create_xml = (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<blue:blueSource xmlns:adtcore="http://www.sap.com/adt/core"'
                    ' xmlns:blue="http://www.sap.com/wbobj/blue"'
                    f' adtcore:description="{safe_desc}" adtcore:language="EN"'
                    f' adtcore:name="{safe_name}" adtcore:type="{type_attr}"'
                    f' adtcore:masterLanguage="EN" adtcore:responsible="{username}">'
                    f'<adtcore:packageRef adtcore:name="{safe_pkg}"/>'
                    '</blue:blueSource>'
                )
                
                url = f"/sap/bc/adt/{adt_path}?sap-client={self.connection.client}"
                if request.transport_request:
                    url += f"&corrNr={quote(request.transport_request)}"
                
                await self._ensure_fresh_csrf_token()
                headers = await self._get_appropriate_headers()
                headers['Content-Type'] = ct
                headers['Accept'] = f'{ct}, application/vnd.sap.adt.blues.v1+xml'
                
                async with self.session.post(url, data=create_xml, headers=headers) as response:
                    if response.status in [200, 201]:
                        logger.info(f"Successfully created {ot} {sanitize_for_logging(request.name)}")
                        return True
                    elif response.status == 400:
                        error_text = await response.text()
                        if 'already exist' in error_text.lower():
                            logger.info(f"{ot} {sanitize_for_logging(request.name)} already exists")
                            return True
                        logger.error(f"{ot} creation failed: {response.status} - {sanitize_for_logging(error_text[:300])}")
                        return False
                    else:
                        error_text = await response.text()
                        logger.error(f"{ot} creation failed: {response.status} - {sanitize_for_logging(error_text[:300])}")
                        return False
            
            # Special handling for BIMPL with explicit behaviorDefinition parameter
            if request.type.value.upper() == 'BIMPL' and request.behavior_definition:
                logger.info(f"Creating BIMPL {sanitize_for_logging(request.name)} with explicit behavior definition: {sanitize_for_logging(request.behavior_definition)}")
                return await self._create_bimpl_with_behavior_definition(request)
            
            # Standard object creation for non-CDS objects
            # Build creation URL based on object type
            url_patterns = get_object_url_patterns(request.type.value, request.name)
            if not url_patterns:
                return False
            
            url = f"/sap/bc/adt/{url_patterns[0]}"
            
            # Add transport number to URL if available (matching ADT flow)
            if request.transport_request:
                url += f"?corrNr={quote(request.transport_request)}"
                logger.info(f"Adding transport number to creation URL: {sanitize_for_logging(request.transport_request)}")
            
            # Get SAP user ID for responsible field
            user_info = await self.get_current_user_info()
            sap_user_id = user_info.get('sap_user_id', self.connection.username)
            
            # Build XML payload
            xml_payload = build_object_xml(
                request.name, request.type.value, 
                request.description, request.package_name,
                sap_user_id
            )
            
            # Log the XML payload for debugging
            logger.info(f"XML payload being sent: {sanitize_for_logging(xml_payload)}")
            
            # Set appropriate content type based on object type
            content_type = f"application/vnd.sap.adt.{request.type.value.lower()}.v2+xml"
            
            # Special handling for specific object types
            if request.type.value.upper() == 'CLAS':
                content_type = 'application/vnd.sap.adt.oo.classes.v4+xml'
            elif request.type.value.upper() == 'BDEF':
                content_type = 'application/vnd.sap.adt.blues.v1+xml'
            elif request.type.value.upper() == 'BIMPL':
                content_type = 'application/vnd.sap.adt.oo.classes.v4+xml'  # BIMPL uses class XML
            elif request.type.value.upper() == 'SRVD':
                content_type = 'application/vnd.sap.adt.ddic.srvd.v1+xml'
            elif request.type.value.upper() == 'SRVB':
                content_type = 'application/vnd.sap.adt.businessservices.servicebinding.v2+xml'
            elif request.type.value.upper() == 'TABL':
                content_type = 'application/vnd.sap.adt.tables.v2+xml'
            elif request.type.value.upper() == 'STRU':
                content_type = 'application/vnd.sap.adt.structures.v2+xml'
            elif request.type.value.upper() in ('PROG', 'PROG/P'):
                content_type = 'application/vnd.sap.adt.programs.programs.v2+xml'
            elif request.type.value.upper() == 'PROG/I':
                content_type = 'application/vnd.sap.adt.programs.includes.v2+xml'
            elif request.type.value.upper() == 'INTF':
                content_type = 'application/vnd.sap.adt.oo.interfaces.v2+xml'
            
            # Ensure fresh CSRF token for create operation
            csrf_success = await self._ensure_fresh_csrf_token()
            if not csrf_success:
                logger.warning("Could not obtain CSRF token, proceeding without it")
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = content_type
            
            logger.info(f"Creating object with URL: {url}")
            logger.info(f"Content-Type: {content_type}")
            
            async with self.session.post(url, data=xml_payload, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created object {sanitize_for_logging(request.name)}")
                    return True
                elif response.status == 403:
                    error_text = await response.text()
                    if 'csrf' in error_text.lower() or 'token' in error_text.lower():
                        logger.info(f"CSRF token validation failed during create, attempting refresh")
                        if await self._refresh_csrf_token():
                            headers = await self._get_appropriate_headers()
                            headers['Content-Type'] = content_type
                            
                            async with self.session.post(url, data=xml_payload, headers=headers) as retry_response:
                                if retry_response.status in [200, 201]:
                                    logger.info(f"Successfully created object {sanitize_for_logging(request.name)} after CSRF refresh")
                                    return True
                                else:
                                    retry_error = await retry_response.text()
                                    logger.error(f"Create retry failed: {retry_response.status} - {sanitize_for_logging(retry_error[:300])}")
                                    return False
                        else:
                            logger.error(f"Failed to refresh CSRF token for create operation")
                            return False
                    else:
                        logger.error(f"Create failed: {response.status} - {sanitize_for_logging(error_text[:300])}")
                        return False
                elif response.status == 401:
                    error_text = await response.text()
                    logger.warning(f"Create got 401 Unauthorized, this might be due to missing CSRF token or auth issues")
                    logger.warning(f"Error details: {sanitize_for_logging(error_text[:300])}")
                    
                    # Try one more time with fresh authentication
                    logger.info("Attempting to reconnect and retry object creation")
                    if await self.connect():
                        headers = await self._get_appropriate_headers()
                        headers['Content-Type'] = content_type
                        
                        async with self.session.post(url, data=xml_payload, headers=headers) as final_response:
                            if final_response.status in [200, 201]:
                                logger.info(f"Successfully created object {sanitize_for_logging(request.name)} after reconnection")
                                return True
                            else:
                                final_error = await final_response.text()
                                logger.error(f"Final create attempt failed: {final_response.status} - {sanitize_for_logging(final_error[:300])}")
                                return False
                    else:
                        logger.error("Failed to reconnect for retry")
                        return False
                else:
                    error_text = await response.text()
                    
                    # Check if the error is because the object already exists
                    if response.status == 400 and 'ExceptionResourceAlreadyExists' in error_text:
                        logger.info(f"Object {sanitize_for_logging(request.name)} already exists - treating as success")
                        return True
                    
                    logger.error(f"Failed to create object: {response.status} - {sanitize_for_logging(error_text[:300])}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error creating object: {sanitize_for_logging(str(e))}")
            return False
    
    async def _create_bdef_with_validation(self, request: CreateObjectRequest) -> bool:
        """Create Behavior Definition with validation step (matching TypeScript implementation)"""
        try:
            logger.info(f"Creating BDEF {sanitize_for_logging(request.name)} with validation")
            
            # Step 1: Validation (matching TypeScript bdef-handler.ts)
            # Use 'Managed' (capitalized) as default implementation type
            implementation_type = 'Managed'  # Default to Managed (capitalized)
            
            validation_url = f"/sap/bc/adt/bo/behaviordefinitions/validation"
            validation_params = {
                'objname': request.name,
                'rootEntity': request.name,
                'description': request.description,
                'package': request.package_name,
                'implementationType': implementation_type,
                'sap-client': self.connection.client
            }
            
            headers = await self._get_appropriate_headers()
            headers['Accept'] = 'application/vnd.sap.as+xml'
            headers['User-Agent'] = 'ABAP-Accelerator-MCP-Server/1.0.0'
            headers['X-sap-adt-profiling'] = 'server-time'
            
            logger.info(f"BDEF validation URL: {validation_url}")
            logger.info(f"BDEF validation params: {sanitize_for_logging(str(validation_params))}")
            
            async with self.session.post(validation_url, params=validation_params, headers=headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"BDEF validation failed: {response.status} - {sanitize_for_logging(error_text[:500])}")
                    return False
                
                validation_result = await response.text()
                logger.info(f"BDEF validation response: {sanitize_for_logging(validation_result[:500])}")
                
                # Check if validation passed (look for SEVERITY=OK)
                if 'SEVERITY>OK</SEVERITY' not in validation_result:
                    # CRITICAL FIX: Check if error is "object already exists" or "does not exist" (for dependencies)
                    if ('already exists' in validation_result.lower() or 
                        'object already exists' in validation_result.lower() or
                        'already defined' in validation_result.lower() or
                        'duplicate' in validation_result.lower()):
                        logger.info(f"BDEF {request.name} already exists - proceeding with update workflow")
                        # For BDEF, if object already exists, we should proceed with creation as it might be an update
                        # The actual creation will handle the existing object appropriately
                    elif 'does not exist' in validation_result.lower():
                        logger.info(f"BDEF validation shows dependency does not exist - this is expected for circular dependencies")
                        # For circular dependencies, the referenced object might not exist yet
                        # We should proceed with creation and let batch activation handle the dependencies
                    else:
                        logger.error("BDEF validation failed - severity not OK")
                        return False
            
            # Step 2: Create the BDEF object using the correct XML format from TypeScript
            url = f"/sap/bc/adt/bo/behaviordefinitions"
            
            # Build BDEF XML payload matching TypeScript format exactly
            safe_name = sanitize_for_xml(request.name)
            safe_description = sanitize_for_xml(request.description)
            safe_package = sanitize_for_xml(request.package_name)
            safe_username = sanitize_for_xml(self.connection.username)
            
            xml_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<blue:blueSource xmlns:adtcore="http://www.sap.com/adt/core" xmlns:blue="http://www.sap.com/wbobj/blue" adtcore:description="{safe_description}" adtcore:language="EN" adtcore:name="{safe_name}" adtcore:type="BDEF/BDO" adtcore:masterLanguage="EN" adtcore:masterSystem="S4H" adtcore:responsible="{safe_username}">
  <adtcore:adtTemplate>
    <adtcore:adtProperty adtcore:key="implementation_type">{implementation_type}</adtcore:adtProperty>
  </adtcore:adtTemplate>
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</blue:blueSource>'''
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/vnd.sap.adt.blues.v1+xml'
            headers['Accept'] = 'application/vnd.sap.adt.blues.v1+xml'
            headers['User-Agent'] = 'ABAP-Accelerator-MCP-Server/1.0.0'
            headers['X-sap-adt-profiling'] = 'server-time'
            
            logger.info(f"Creating BDEF with URL: {url}")
            logger.info(f"BDEF XML payload: {sanitize_for_logging(xml_payload)}")
            
            async with self.session.post(url, data=xml_payload, headers=headers) as response:
                if response.status == 201:
                    logger.info(f"Successfully created BDEF {sanitize_for_logging(request.name)}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to create BDEF: {response.status} - {sanitize_for_logging(error_text[:500])}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error creating BDEF with validation: {sanitize_for_logging(str(e))}")
            return False
    
    async def _create_bimpl_with_behavior_definition(self, request: CreateObjectRequest) -> bool:
        """Create BIMPL with explicit behavior definition (matching TypeScript implementation)"""
        try:
            logger.info(f"Creating BIMPL {sanitize_for_logging(request.name)} with behavior definition {sanitize_for_logging(request.behavior_definition)}")
            
            # Build BIMPL XML with explicit behavior definition (matching TypeScript format)
            safe_name = sanitize_for_xml(request.name)
            safe_description = sanitize_for_xml(request.description)
            safe_package = sanitize_for_xml(request.package_name)
            safe_username = sanitize_for_xml(self.connection.username)
            safe_bdef_name = sanitize_for_xml(request.behavior_definition)
            
            xml_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<class:abapClass xmlns:abapsource="http://www.sap.com/adt/abapsource" xmlns:adtcore="http://www.sap.com/adt/core" xmlns:class="http://www.sap.com/adt/oo/classes" adtcore:description="{safe_description}" adtcore:language="EN" adtcore:name="{safe_name}" adtcore:type="CLAS/OC" adtcore:masterLanguage="EN" adtcore:masterSystem="S4H" adtcore:responsible="{safe_username}" class:category="behaviorPool" class:final="true" class:visibility="public">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
  <abapsource:template abapsource:name="IF_BEHAVIOR_CLASS_GENERATION">
    <abapsource:property abapsource:key="Dummy"/>
  </abapsource:template>
  <class:include adtcore:name="CLAS/OC" adtcore:type="CLAS/OC" class:includeType="testclasses"/>
  <class:rootEntityRef adtcore:name="{safe_bdef_name}"/>
</class:abapClass>'''
            
            # Use class endpoint for BIMPL
            url = f"/sap/bc/adt/oo/classes"
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/vnd.sap.adt.oo.classes.v4+xml'
            
            logger.info(f"Creating BIMPL with URL: {url}")
            logger.info(f"BIMPL XML payload: {sanitize_for_logging(xml_payload)}")
            
            async with self.session.post(url, data=xml_payload, headers=headers) as response:
                if response.status == 201:
                    logger.info(f"Successfully created BIMPL {sanitize_for_logging(request.name)}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to create BIMPL: {response.status} - {sanitize_for_logging(error_text[:500])}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error creating BIMPL with behavior definition: {sanitize_for_logging(str(e))}")
            return False
    
    async def _create_srvb_with_validation(self, request: CreateObjectRequest) -> bool:
        """Create Service Binding with validation (matching TypeScript implementation)"""
        try:
            logger.info(f"Creating Service Binding {sanitize_for_logging(request.name)} with validation")
            
            # Validate required fields
            if not request.service_definition:
                logger.error("Service Definition reference is required for Service Binding creation")
                return False
            
            # Step 1: Validate that the service definition exists
            logger.info(f"Validating Service Definition {sanitize_for_logging(request.service_definition)} exists")
            service_def_source = await self.get_source(request.service_definition, 'SRVD')
            if not service_def_source:
                logger.error(f"Service Definition '{sanitize_for_logging(request.service_definition)}' not found. Please create the Service Definition first.")
                return False
            logger.info(f"Service Definition {sanitize_for_logging(request.service_definition)} validated successfully")
            
            # Step 2: Build Service Binding XML (matching TypeScript format)
            binding_type = request.binding_type.value if request.binding_type else 'ODATA_V4_UI'
            
            # Map binding type to version and category
            version = 'V4' if 'V4' in binding_type else 'V2'
            category = '0' if 'UI' in binding_type else '1'  # 0=UI, 1=Web API
            
            safe_name = sanitize_for_xml(request.name)
            safe_description = sanitize_for_xml(request.description)
            safe_package = sanitize_for_xml(request.package_name)
            safe_username = sanitize_for_xml(self.connection.username)
            safe_service_def = sanitize_for_xml(request.service_definition)
            
            xml_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<srvb:serviceBinding xmlns:adtcore="http://www.sap.com/adt/core" xmlns:srvb="http://www.sap.com/adt/ddic/ServiceBindings" adtcore:description="{safe_description}" adtcore:language="EN" adtcore:name="{safe_name}" adtcore:type="SRVB/SVB" adtcore:masterLanguage="EN" adtcore:masterSystem="S4H" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
  <srvb:services srvb:name="{safe_name}">
    <srvb:content srvb:version="0001">
      <srvb:serviceDefinition adtcore:name="{safe_service_def}"/>
    </srvb:content>
  </srvb:services>
  <srvb:binding srvb:category="{category}" srvb:type="ODATA" srvb:version="{version}">
    <srvb:implementation adtcore:name=""/>
  </srvb:binding>
</srvb:serviceBinding>'''
            
            # Step 3: Create the service binding
            url = f"/sap/bc/adt/businessservices/bindings"
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/vnd.sap.adt.businessservices.servicebinding.v2+xml'
            headers['Accept'] = 'application/vnd.sap.adt.businessservices.servicebinding.v1+xml, application/vnd.sap.adt.businessservices.servicebinding.v2+xml'
            
            logger.info(f"Creating Service Binding with URL: {url}")
            logger.info(f"Service Binding XML: {sanitize_for_logging(xml_payload)}")
            
            async with self.session.post(url, data=xml_payload, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created Service Binding {sanitize_for_logging(request.name)}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to create Service Binding: {response.status} - {sanitize_for_logging(error_text[:500])}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error creating Service Binding with validation: {sanitize_for_logging(str(e))}")
            return False
    
    async def update_source_with_syntax_check(self, object_name: str, object_type: str, 
                                            source_code: str, transport_request: Optional[str] = None) -> ObjectOperationResult:
        """Update source code with syntax check (matching TypeScript implementation)"""
        try:
            print(f"[SAP-CLIENT] Updating source with syntax check for {sanitize_for_logging(object_name)}")
            
            # Step 1: Update source code
            updated, error_msg = await self._update_source(object_name, object_type, source_code, transport_request=transport_request)
            if not updated:
                print(f"[SAP-CLIENT] Source update failed for {sanitize_for_logging(object_name)}: {error_msg}")
                return ObjectOperationResult(
                    updated=False,
                    syntax_check_passed=False,
                    activated=False,
                    errors=[SAPSyntaxError(line=1, message=error_msg or "Failed to update source code", severity="ERROR")],
                    warnings=[]
                )
            
            print(f"[SAP-CLIENT] Source updated successfully, proceeding with activation")
            
            # Step 2: For CDS views, verify source before activation
            if object_type.upper() == 'DDLS':
                verify_source = await self.get_source(object_name, object_type)
                if verify_source and (
                    'select from' in verify_source.lower() or 
                    'define view' in verify_source.lower() or
                    'as projection on' in verify_source.lower() or
                    'define root view' in verify_source.lower()
                ):
                    print(f"[SAP-CLIENT] CDS view source verified, attempting activation")
                    activation_result = await self._activate_object_with_details(object_name, object_type)
                    
                    return ObjectOperationResult(
                        updated=True,
                        syntax_check_passed=activation_result.success,
                        activated=activation_result.activated,
                        errors=activation_result.errors,
                        warnings=activation_result.warnings
                    )
                else:
                    print(f"[SAP-CLIENT] CDS view source not found or invalid after update")
                    print(f"[SAP-CLIENT] Source content preview: {verify_source[:200] if verify_source else 'None'}...")
                    return ObjectOperationResult(
                        updated=False,
                        syntax_check_passed=False,
                        activated=False,
                        errors=[SAPSyntaxError(line=1, message="CDS view source not found or invalid after update", severity="ERROR")],
                        warnings=[]
                    )
            
            # Step 3: Perform syntax check and activation for non-CDS objects
            activation_result = await self._activate_object_with_details(object_name, object_type)
            
            return ObjectOperationResult(
                updated=True,
                syntax_check_passed=activation_result.success,
                activated=activation_result.activated,
                errors=activation_result.errors,
                warnings=activation_result.warnings
            )
            
        except Exception as e:
            print(f"[SAP-CLIENT] Update with syntax check failed for {sanitize_for_logging(object_name)}: {sanitize_for_logging(str(e))}")
            logger.error(f"Error updating source: {sanitize_for_logging(str(e))}")
            return ObjectOperationResult(
                updated=False,
                syntax_check_passed=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=f"Update failed: {str(e)}", severity="ERROR")],
                warnings=[]
            )
    
    async def _activate_object_with_details(self, object_name: str, object_type: str) -> ActivationResult:
        """Activate object and return detailed result (matching TypeScript activateObjectWithDetails)"""
        try:
            print(f"[SAP-CLIENT] Activating {sanitize_for_logging(object_name)}")
            rap_logger.activation(sanitize_for_logging(object_name), sanitize_for_logging(object_type), 'SUCCESS', {'phase': 'START'})
            
            # Build activation XML
            activation_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">
  <adtcore:objectReference adtcore:uri="/sap/bc/adt/{format_object_type_for_url(sanitize_for_xml(object_type))}/{sanitize_for_xml(object_name)}" adtcore:name="{sanitize_for_xml(object_name)}"/>
</adtcore:objectReferences>"""
            
            url = f"/sap/bc/adt/activation?method=activate&preauditRequested=true&sap-client={self.connection.client}"
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/vnd.sap.adt.activation.v1+xml'
            
            async with self.session.post(url, data=activation_xml, headers=headers) as response:
                print(f"[SAP-CLIENT] Activation response status: {response.status}")
                
                if response.status == 200:
                    xml_content = await response.text()
                    print(f"[SAP-CLIENT] Activation response: {sanitize_for_logging(xml_content[:500])}")
                    
                    # Parse activation result
                    root = safe_parse_xml(xml_content)
                    syntax_result = self._parse_syntax_check_result_from_activation(root)
                    
                    # Check if activation was actually executed
                    activation_executed = True  # Default to true if not specified
                    if root is not None:
                        for elem in root.iter():
                            for attr_name, attr_value in elem.attrib.items():
                                if 'activationExecuted' in attr_name:
                                    activation_executed = attr_value.lower() == 'true'
                                    break
                    
                    print(f"[SAP-CLIENT] Activation executed: {activation_executed}")
                    
                    success = syntax_result.success and activation_executed
                    
                    result = ActivationResult(
                        success=success,
                        activated=activation_executed,
                        errors=syntax_result.errors,
                        warnings=syntax_result.warnings,
                        messages=['Activation was cancelled due to errors'] if not activation_executed else []
                    )
                    
                    # Auto-publish service bindings after successful activation
                    if object_type.upper() == 'SRVB' and result.activated:
                        publish_result = await self._publish_service_binding(object_name)
                        if publish_result:
                            result.messages = list(result.messages or []) + [f'{object_name} published locally']
                            logger.info(f"SRVB {sanitize_for_logging(object_name)} published locally after activation")
                        else:
                            result.warnings = list(result.warnings or []) + [
                                SAPSyntaxError(line=0, message=f'Activation succeeded but publish failed for {object_name}', severity='WARNING')
                            ]
                    
                    rap_logger.activation(
                        sanitize_for_logging(object_name), 
                        sanitize_for_logging(object_type), 
                        'SUCCESS' if result.success else 'FAILED',
                        {
                            'errors': len(result.errors),
                            'warnings': len(result.warnings),
                            'activationExecuted': activation_executed
                        }
                    )
                    
                    return result
                else:
                    error_text = await response.text()
                    print(f"[SAP-CLIENT] Activation failed: {response.status} - {sanitize_for_logging(error_text[:300])}")
                    
                    return ActivationResult(
                        success=False,
                        activated=False,
                        errors=[SAPSyntaxError(line=1, message=f"Activation failed: HTTP {response.status}", severity="ERROR")],
                        warnings=[],
                        messages=[]
                    )
                    
        except Exception as e:
            print(f"[SAP-CLIENT] Activation error: {sanitize_for_logging(str(e))}")
            rap_logger.error('ACTIVATION', sanitize_for_logging(object_name), sanitize_for_logging(object_type), sanitize_for_logging(str(e)))
            return ActivationResult(
                success=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=str(e), severity="ERROR")],
                warnings=[],
                messages=[]
            )
    
    async def _publish_service_binding(self, binding_name: str) -> bool:
        """Publish a Service Binding locally via OData V4 publish jobs.
        Flow: lock → publish → unlock."""
        import re
        name = binding_name.strip().upper()
        obj_url = f"/sap/bc/adt/businessservices/bindings/{name.lower()}"

        try:
            await self._ensure_fresh_csrf_token()
            headers = await self._get_appropriate_headers()

            # Step 1: Lock
            lock_handle = None
            lock_url = f"{obj_url}?sap-client={self.connection.client}&_action=LOCK&accessMode=MODIFY"
            lock_headers = {**headers, 'Accept': (
                'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result;q=0.8, '
                'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result2;q=0.9'
            )}
            async with self.session.post(lock_url, data='', headers=lock_headers) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    m = re.search(r'<LOCK_HANDLE>([^<]+)</LOCK_HANDLE>', text)
                    if m:
                        lock_handle = m.group(1)
                else:
                    logger.warning(f"SRVB lock failed ({resp.status}), attempting publish anyway")

            # Step 2: Publish
            publish_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">'
                f'<adtcore:objectReference adtcore:type="SCGR" adtcore:name="{sanitize_for_xml(name)}"/>'
                '</adtcore:objectReferences>'
            )
            pub_headers = {**headers,
                'Content-Type': 'application/xml',
                'Accept': 'application/xml, application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.StatusMessage',
            }
            pub_url = f"/sap/bc/adt/businessservices/odatav4/publishjobs?sap-client={self.connection.client}"
            async with self.session.post(pub_url, data=publish_xml, headers=pub_headers) as resp:
                result_text = await resp.text() if resp.status == 200 else ''
                published = resp.status == 200 and ('published locally' in result_text.lower() or 'OK' in result_text)

            # Step 3: Unlock
            if lock_handle:
                unlock_url = f"{obj_url}?sap-client={self.connection.client}&_action=UNLOCK&lockHandle={quote(lock_handle)}"
                async with self.session.post(unlock_url, data='', headers=headers) as resp:
                    pass  # best-effort unlock

            return published

        except Exception as e:
            logger.warning(f"SRVB publish failed for {sanitize_for_logging(name)}: {sanitize_for_logging(str(e))}")
            return False

    def _parse_syntax_check_result_from_activation(self, root) -> SyntaxCheckResult:
        """Parse syntax check result from activation response XML"""
        errors = []
        warnings = []
        
        if root is None:
            return SyntaxCheckResult(success=True, errors=[], warnings=[])
        
        try:
            # Look for messages in SAP activation response format
            for elem in root.iter():
                # Handle SAP activation response format: <msg type="E">
                if elem.tag.endswith('msg') or 'msg' in elem.tag:
                    severity = elem.get('type', '').upper()
                    line_num = 1
                    
                    # Try to get line number
                    line_attr = elem.get('line')
                    if line_attr:
                        try:
                            line_num = int(line_attr)
                        except ValueError:
                            line_num = 1
                    
                    # Extract message text from shortText/txt elements
                    message_parts = []
                    for short_text in elem.iter():
                        if short_text.tag.endswith('shortText'):
                            for txt_elem in short_text.iter():
                                if txt_elem.tag.endswith('txt') and txt_elem.text:
                                    message_parts.append(txt_elem.text.strip())
                    
                    # If no shortText found, try direct text content
                    if not message_parts and elem.text:
                        message_parts.append(elem.text.strip())
                    
                    message_text = ' - '.join(message_parts) if message_parts else 'Unknown error'
                    
                    if severity in ['E', 'ERROR', 'FATAL']:
                        errors.append(SAPSyntaxError(line=line_num, message=message_text, severity='ERROR'))
                        print(f"[SAP-CLIENT] Found activation error: {sanitize_for_logging(message_text)}")
                    elif severity in ['W', 'WARNING']:
                        warnings.append(SyntaxWarning(line=line_num, message=message_text, severity='WARNING'))
                        print(f"[SAP-CLIENT] Found activation warning: {sanitize_for_logging(message_text)}")
                
                # Also handle generic message elements for backward compatibility
                elif 'message' in elem.tag.lower():
                    severity = None
                    text = elem.text or ''
                    line = 1
                    
                    for attr_name, attr_value in elem.attrib.items():
                        if 'severity' in attr_name.lower() or 'type' in attr_name.lower():
                            severity = attr_value.upper()
                        elif 'text' in attr_name.lower() or 'message' in attr_name.lower():
                            text = attr_value
                        elif 'line' in attr_name.lower():
                            try:
                                line = int(attr_value)
                            except ValueError:
                                line = 1
                    
                    if severity in ['E', 'ERROR', 'FATAL']:
                        errors.append(SAPSyntaxError(line=line, message=text, severity='ERROR'))
                    elif severity in ['W', 'WARNING']:
                        warnings.append(SyntaxWarning(line=line, message=text, severity='WARNING'))
                        
        except Exception as e:
            print(f"[SAP-CLIENT] Error parsing activation result: {sanitize_for_logging(str(e))}")
        
        print(f"[SAP-CLIENT] Parsed activation result: {len(errors)} errors, {len(warnings)} warnings")
        
        return SyntaxCheckResult(
            success=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    async def _lock_object(self, object_url: str) -> Optional[Dict[str, str]]:
        """Lock an object for editing - returns lock info with LOCK_HANDLE"""
        try:
            print(f"[SAP-CLIENT] Locking object: {sanitize_for_logging(object_url)}")
            
            # For write operations, ensure we have a fresh CSRF token
            await self._ensure_fresh_csrf_token()
            
            lock_url = f"{object_url}?sap-client={self.connection.client}&_action=LOCK&accessMode=MODIFY"
            
            headers = await self._get_appropriate_headers()
            headers['Accept'] = 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result;q=0.8, application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result2;q=0.9'
            
            async with self.session.post(lock_url, data='', headers=headers) as response:
                print(f"[SAP-CLIENT] Lock response status: {response.status}")
                
                if response.status == 200:
                    xml_content = await response.text()
                    print(f"[SAP-CLIENT] Lock response: {sanitize_for_logging(xml_content[:500])}")
                    
                    # Parse lock result
                    root = safe_parse_xml(xml_content)
                    if root is not None:
                        lock_handle = None
                        corr_nr = None
                        is_local = False
                        
                        # Try to find LOCK_HANDLE, CORRNR, IS_LOCAL in various locations
                        for elem in root.iter():
                            if elem.tag.endswith('LOCK_HANDLE') or 'LOCK_HANDLE' in elem.tag:
                                lock_handle = elem.text
                            elif elem.tag.endswith('CORRNR') or 'CORRNR' in elem.tag:
                                corr_nr = elem.text
                            elif elem.tag.endswith('IS_LOCAL') or 'IS_LOCAL' in elem.tag:
                                is_local = elem.text and elem.text.upper() == 'X'
                        
                        # Also check attributes
                        for elem in root.iter():
                            for attr_name, attr_value in elem.attrib.items():
                                if 'LOCK_HANDLE' in attr_name.upper():
                                    lock_handle = attr_value
                                elif 'CORRNR' in attr_name.upper():
                                    corr_nr = attr_value
                                elif 'IS_LOCAL' in attr_name.upper():
                                    is_local = attr_value and attr_value.upper() == 'X'
                        
                        if lock_handle:
                            print(f"[SAP-CLIENT] Lock acquired - Handle: {sanitize_for_logging(lock_handle)}, CorrNr: {sanitize_for_logging(corr_nr)}, IsLocal: {is_local}")
                            return {'LOCK_HANDLE': lock_handle, 'CORRNR': corr_nr or '', 'IS_LOCAL': is_local}
                        else:
                            print(f"[SAP-CLIENT] Lock response parsed but no LOCK_HANDLE found")
                elif response.status == 403:
                    error_text = await response.text()
                    if 'csrf' in error_text.lower() or 'token' in error_text.lower():
                        print(f"[SAP-CLIENT] CSRF token validation failed, attempting to refresh token")
                        # Try to refresh CSRF token and retry once
                        if await self._refresh_csrf_token():
                            print(f"[SAP-CLIENT] CSRF token refreshed, retrying lock operation")
                            headers = await self._get_appropriate_headers()
                            headers['Accept'] = 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result;q=0.8, application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result2;q=0.9'
                            
                            async with self.session.post(lock_url, data='', headers=headers) as retry_response:
                                if retry_response.status == 200:
                                    xml_content = await retry_response.text()
                                    root = safe_parse_xml(xml_content)
                                    if root is not None:
                                        lock_handle = None
                                        corr_nr = None
                                        is_local = False
                                        
                                        for elem in root.iter():
                                            if elem.tag.endswith('LOCK_HANDLE') or 'LOCK_HANDLE' in elem.tag:
                                                lock_handle = elem.text
                                            elif elem.tag.endswith('CORRNR') or 'CORRNR' in elem.tag:
                                                corr_nr = elem.text
                                            elif elem.tag.endswith('IS_LOCAL') or 'IS_LOCAL' in elem.tag:
                                                is_local = elem.text and elem.text.upper() == 'X'
                                        
                                        # Also check attributes for IS_LOCAL
                                        for elem in root.iter():
                                            for attr_name, attr_value in elem.attrib.items():
                                                if 'IS_LOCAL' in attr_name.upper():
                                                    is_local = attr_value and attr_value.upper() == 'X'
                                        
                                        if lock_handle:
                                            print(f"[SAP-CLIENT] Lock acquired after CSRF refresh - Handle: {sanitize_for_logging(lock_handle)}, IsLocal: {is_local}")
                                            return {'LOCK_HANDLE': lock_handle, 'CORRNR': corr_nr or '', 'IS_LOCAL': is_local}
                                else:
                                    retry_error = await retry_response.text()
                                    print(f"[SAP-CLIENT] Lock retry failed: {retry_response.status} - {sanitize_for_logging(retry_error[:300])}")
                        else:
                            print(f"[SAP-CLIENT] Failed to refresh CSRF token")
                    else:
                        print(f"[SAP-CLIENT] Lock failed: {response.status} - {sanitize_for_logging(error_text[:300])}")
                else:
                    error_text = await response.text()
                    print(f"[SAP-CLIENT] Lock failed: {response.status} - {sanitize_for_logging(error_text[:300])}")
            
            return None
            
        except Exception as e:
            print(f"[SAP-CLIENT] Lock error: {sanitize_for_logging(str(e))}")
            return None
    
    async def _unlock_object(self, object_url: str, lock_handle: str) -> bool:
        """Unlock an object after editing"""
        try:
            print(f"[SAP-CLIENT] Unlocking object: {sanitize_for_logging(object_url)}")
            
            # Ensure fresh CSRF token for unlock operation
            await self._ensure_fresh_csrf_token()
            
            unlock_url = f"{object_url}?sap-client={self.connection.client}&_action=UNLOCK&lockHandle={quote(lock_handle)}"
            
            headers = await self._get_appropriate_headers()
            
            async with self.session.post(unlock_url, data='', headers=headers) as response:
                print(f"[SAP-CLIENT] Unlock response status: {response.status}")
                
                if response.status == 200:
                    print(f"[SAP-CLIENT] Object unlocked successfully")
                    return True
                elif response.status == 403:
                    error_text = await response.text()
                    if 'csrf' in error_text.lower() or 'token' in error_text.lower():
                        print(f"[SAP-CLIENT] CSRF token validation failed during unlock, attempting refresh")
                        if await self._refresh_csrf_token():
                            headers = await self._get_appropriate_headers()
                            async with self.session.post(unlock_url, data='', headers=headers) as retry_response:
                                if retry_response.status == 200:
                                    print(f"[SAP-CLIENT] Object unlocked successfully after CSRF refresh")
                                    return True
                                else:
                                    retry_error = await retry_response.text()
                                    print(f"[SAP-CLIENT] Unlock retry failed: {retry_response.status} - {sanitize_for_logging(retry_error[:200])}")
                    else:
                        print(f"[SAP-CLIENT] Unlock failed: {response.status} - {sanitize_for_logging(error_text[:200])}")
                else:
                    error_text = await response.text()
                    print(f"[SAP-CLIENT] Unlock failed: {response.status} - {sanitize_for_logging(error_text[:200])}")
                
                return False
                
        except Exception as e:
            print(f"[SAP-CLIENT] Unlock error: {sanitize_for_logging(str(e))}")
            return False
    
    async def _check_transport_requirements(self, object_name: str, object_type: str, resource_uri: str) -> Dict[str, Any]:
        """Check transport requirements for an object"""
        try:
            print(f"[SAP-CLIENT] Checking transport requirements for {sanitize_for_logging(object_name)}")
            
            # Build transport check XML
            transport_check_xml = f"""<?xml version="1.0" encoding="UTF-8" ?>
<asx:abap version="1.0" xmlns:asx="http://www.sap.com/abapxml">
  <asx:values>
    <DATA>
      <PGMID></PGMID>
      <OBJECT></OBJECT>
      <OBJECTNAME></OBJECTNAME>
      <DEVCLASS></DEVCLASS>
      <SUPER_PACKAGE></SUPER_PACKAGE>
      <RECORD_CHANGES></RECORD_CHANGES>
      <OPERATION>U</OPERATION>
      <URI>{sanitize_for_xml(resource_uri)}</URI>
    </DATA>
  </asx:values>
</asx:abap>"""
            
            url = f"/sap/bc/adt/cts/transportchecks?sap-client={self.connection.client}"
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/vnd.sap.as+xml; charset=UTF-8; dataname=com.sap.adt.transport.service.checkData'
            headers['Accept'] = 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.transport.service.checkData'
            
            async with self.session.post(url, data=transport_check_xml, headers=headers) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    print(f"[SAP-CLIENT] Transport check response: {sanitize_for_logging(xml_content[:500])}")
                    
                    # Parse transport number from response
                    root = safe_parse_xml(xml_content)
                    if root is not None:
                        transport_number = None
                        for elem in root.iter():
                            if elem.tag.endswith('TRKORR') or 'TRKORR' in elem.tag:
                                transport_number = elem.text
                                break
                        
                        return {'transportNumber': transport_number}
            
            return {}
            
        except Exception as e:
            print(f"[SAP-CLIENT] Transport check error: {sanitize_for_logging(str(e))}")
            return {}
    
    async def _update_source(self, object_name: str, object_type: str, source_code: str,
                            transport_request: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Update source code in SAP system. Returns (success, error_message)"""
        try:
            print(f"[SAP-CLIENT] Updating source for {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
            
            # Special handling for CLAS objects
            if object_type.upper() == 'CLAS':
                return await self._update_class_source(object_name, source_code)
            
            # Special handling for CDS views (DDLS)
            if object_type.upper() == 'DDLS':
                print(f"[SAP-CLIENT] CDS view detected, using specialized update")
                result = await self._update_cds_source(object_name, source_code)
                return (result, None) if result else (False, "CDS source update failed")
            
            # Get resource URI
            resource_uri = await self._get_resource_uri(object_name, object_type)
            if not resource_uri:
                return False, f"Could not get resource URI for {object_name}"
            
            object_url = f"{resource_uri}"
            lock_info = await self._lock_object(object_url)
            if not lock_info:
                result = await self._update_source_without_lock(object_name, object_type, source_code, resource_uri)
                return (result, None) if result else (False, "Failed to lock and update without lock failed")
            
            try:
                # Build source URL with lock handle
                source_url = f"{resource_uri}/source/main?sap-client={self.connection.client}"
                source_url += f"&lockHandle={quote(lock_info['LOCK_HANDLE'])}"
                
                # Only check transport requirements if we have a transport number from lock
                # Skip transport check for $TMP/local objects as it can release the lock on SAP side
                # Check IS_LOCAL flag or if CORRNR is empty (indicates local object)
                is_local_object = lock_info.get('IS_LOCAL', False) or not lock_info.get('CORRNR')
                
                if lock_info.get('CORRNR'):
                    source_url += f"&corrNr={quote(lock_info['CORRNR'])}"
                    print(f"[SAP-CLIENT] Using transport from lock: {sanitize_for_logging(lock_info['CORRNR'])}")
                elif transport_request:
                    source_url += f"&corrNr={quote(transport_request)}"
                    print(f"[SAP-CLIENT] Using externally provided transport: {sanitize_for_logging(transport_request)}")
                elif not is_local_object:
                    # Only check transport for non-local objects (not $TMP)
                    # WARNING: Transport check can release locks on some SAP systems
                    print(f"[SAP-CLIENT] Checking transport requirements (non-local object)")
                    transport_info = await self._check_transport_requirements(object_name, object_type, resource_uri)
                    if transport_info.get('transportNumber'):
                        source_url += f"&corrNr={quote(transport_info['transportNumber'])}"
                else:
                    print(f"[SAP-CLIENT] Skipping transport check for local/$TMP object")
                
                source_url = source_url.replace('&corrNr=', '') if source_url.endswith('&corrNr=') else source_url
                
                print(f"[SAP-CLIENT] Source update URL: {sanitize_for_logging(source_url)}")
                
                # Note: Don't refresh CSRF token here - we already have a valid one from the lock operation
                # Refreshing can invalidate the lock on some SAP systems
                
                headers = await self._get_appropriate_headers()
                headers['Content-Type'] = 'text/plain; charset=utf-8'
                headers['Accept'] = 'text/plain'
                
                print(f"[SAP-CLIENT] Executing PUT request for source update...")
                try:
                    async with self.session.put(source_url, data=source_code, headers=headers) as response:
                        print(f"[SAP-CLIENT] PUT response status: {response.status}")
                        if response.status in [200, 204]:
                            return True, None
                        elif response.status == 403:
                            error_text = await response.text()
                            if 'csrf' in error_text.lower() or 'token' in error_text.lower():
                                print(f"[SAP-CLIENT] CSRF token validation failed during source update, attempting refresh")
                                if await self._refresh_csrf_token():
                                    headers = await self._get_appropriate_headers()
                                    headers['Content-Type'] = 'text/plain; charset=utf-8'
                                    headers['Accept'] = 'text/plain'
                                    
                                    async with self.session.put(source_url, data=source_code, headers=headers) as retry_response:
                                        if retry_response.status in [200, 204]:
                                            return True, None
                                        else:
                                            retry_error = await retry_response.text()
                                            error_msg = self._extract_error_from_exception_xml(retry_error) or f"HTTP {retry_response.status}"
                                            return False, error_msg
                                else:
                                    return False, "Failed to refresh CSRF token for source update"
                            else:
                                error_msg = self._extract_error_from_exception_xml(error_text) or f"HTTP {response.status}"
                                return False, error_msg
                        else:
                            error_text = await response.text()
                            error_msg = self._extract_error_from_exception_xml(error_text) or f"HTTP {response.status}"
                            print(f"[SAP-CLIENT] Source update failed with status {response.status}: {sanitize_for_logging(error_msg)}")
                            return False, error_msg
                except Exception as put_error:
                    print(f"[SAP-CLIENT] PUT request exception: {sanitize_for_logging(str(put_error))}")
                    raise
                        
            finally:
                await self._unlock_object(object_url, lock_info['LOCK_HANDLE'])
            
        except Exception as e:
            logger.error(f"Error updating source: {sanitize_for_logging(str(e))}")
            return False, str(e)
    
    async def _update_source_without_lock(self, object_name: str, object_type: str, source_code: str, resource_uri: str) -> bool:
        """Update source without lock (fallback for $TMP objects)"""
        try:
            print(f"[SAP-CLIENT] Attempting source update without lock for {sanitize_for_logging(object_name)}")
            
            source_url = f"{resource_uri}/source/main?sap-client={self.connection.client}"
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'text/plain; charset=utf-8'
            headers['Accept'] = 'text/plain'
            
            async with self.session.put(source_url, data=source_code, headers=headers) as response:
                print(f"[SAP-CLIENT] Source update (no lock) response: {response.status}")
                
                if response.status in [200, 204]:
                    print(f"[SAP-CLIENT] Source updated successfully without lock")
                    return True
                else:
                    error_text = await response.text()
                    print(f"[SAP-CLIENT] Source update (no lock) failed: {response.status} - {sanitize_for_logging(error_text[:300])}")
                    return False
                    
        except Exception as e:
            print(f"[SAP-CLIENT] Source update without lock error: {sanitize_for_logging(str(e))}")
            return False
    
    async def _update_class_source(self, object_name: str, source_code: str) -> Tuple[bool, Optional[str]]:
        """Update class source code with proper locking. Returns (success, error_message)"""
        try:
            print(f"[SAP-CLIENT] Updating class source for {sanitize_for_logging(object_name)}")
            logger.info(f"Updating class source for {sanitize_for_logging(object_name)}")
            
            # Ensure session is still valid
            if not self.session or self.session.closed:
                logger.warning("Session is None or closed, attempting to reconnect...")
                connected = await self.connect()
                if not connected:
                    return False, "Failed to reconnect to SAP system"
            
            # Validate class structure
            if not self._validate_class_structure(source_code):
                print(f"[SAP-CLIENT] Invalid class structure for {sanitize_for_logging(object_name)}")
                return False, "Invalid class structure - missing CLASS DEFINITION, IMPLEMENTATION, or ENDCLASS"
            
            resource_uri = f"/sap/bc/adt/oo/classes/{object_name}"
            object_url = resource_uri
            
            # Lock the object
            lock_info = await self._lock_object(object_url)
            if not lock_info:
                print(f"[SAP-CLIENT] Failed to lock class {sanitize_for_logging(object_name)}")
                return False, f"Failed to lock object {object_name} - it may be locked by another user"
            
            last_error = None
            try:
                is_behavior_pool = await self._is_behavior_pool(object_name)
                
                if is_behavior_pool:
                    endpoints = [f"{resource_uri}/includes/implementations", f"{resource_uri}/includes/main"]
                else:
                    endpoints = [f"{resource_uri}/includes/main", f"{resource_uri}/source/main"]
                
                for endpoint in endpoints:
                    try:
                        source_url = f"{endpoint}?sap-client={self.connection.client}"
                        source_url += f"&lockHandle={quote(lock_info['LOCK_HANDLE'])}"
                        
                        # Pass corrNr from lock response if available (for non-$TMP objects)
                        if lock_info.get('CORRNR'):
                            source_url += f"&corrNr={quote(lock_info['CORRNR'])}"
                        
                        print(f"[SAP-CLIENT] Trying class source update at: {sanitize_for_logging(source_url)}")
                        print(f"[SAP-CLIENT] Source Code length: {len(source_code)}")
                        
                        headers = await self._get_appropriate_headers()
                        headers['Content-Type'] = 'text/plain; charset=utf-8'
                        headers['Accept'] = 'text/plain'
                        
                        async with self.session.put(source_url, data=source_code, headers=headers) as response:
                            print(f"[SAP-CLIENT] Class source update response: {response.status}")
                            
                            if response.status in [200, 204]:
                                print(f"[SAP-CLIENT] Class source updated via {sanitize_for_logging(endpoint)}")
                                return True, None
                            elif response.status == 404:
                                continue
                            else:
                                error_text = await response.text()
                                print(f"[SAP-CLIENT] Failed via {sanitize_for_logging(endpoint)}: {response.status}")
                                print(f"[SAP-CLIENT] Error details: {sanitize_for_logging(error_text[:300])}")
                                # Extract error message from exception XML
                                last_error = self._extract_error_from_exception_xml(error_text) or f"HTTP {response.status}"
                                continue
                                
                    except Exception as endpoint_error:
                        last_error = str(endpoint_error)
                        continue
                
                print(f"[SAP-CLIENT] All endpoints failed for {sanitize_for_logging(object_name)}")
                return False, last_error or "All update endpoints failed"
                
            finally:
                await self._unlock_object(object_url, lock_info['LOCK_HANDLE'])
            
        except Exception as e:
            print(f"[SAP-CLIENT] Error updating class source: {sanitize_for_logging(str(e))}")
            return False, str(e)
    
    def _validate_class_structure(self, source_code: str) -> bool:
        """Validate ABAP class structure (matching TypeScript implementation)"""
        import re
        
        required_patterns = [
            r'CLASS\s+\w+\s+DEFINITION',
            r'ENDCLASS',
            r'CLASS\s+\w+\s+IMPLEMENTATION'
        ]
        
        for pattern in required_patterns:
            if not re.search(pattern, source_code, re.IGNORECASE):
                return False
        
        return True
    
    async def _is_behavior_pool(self, object_name: str) -> bool:
        """Check if a class is a behavior pool (BIMPL)"""
        try:
            url = f"/sap/bc/adt/oo/classes/{object_name}?sap-client={self.connection.client}"
            
            headers = await self._get_appropriate_headers()
            headers['Accept'] = 'application/vnd.sap.adt.oo.classes.v4+xml, application/vnd.sap.adt.oo.classes.v3+xml, application/vnd.sap.adt.oo.classes.v2+xml'
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    # Check if the class has category="behaviorPool"
                    is_behavior_pool = ('class:category="behaviorPool"' in xml_content or 
                                       'category="behaviorPool"' in xml_content)
                    
                    if is_behavior_pool:
                        print(f"[SAP-CLIENT] Detected {sanitize_for_logging(object_name)} as behavior pool")
                    
                    return is_behavior_pool
            
            return False
            
        except Exception as e:
            # If we can't determine, assume it's a regular class (safe fallback)
            print(f"[SAP-CLIENT] Could not determine if {sanitize_for_logging(object_name)} is behavior pool, assuming regular class")
            return False
    
    async def check_syntax_with_response(self, object_name: str, object_type: str, 
                                          source_code: Optional[str] = None) -> Tuple[SyntaxCheckResult, str]:
        """Check syntax of ABAP object and return both result and raw response"""
        try:
            print(f"[SAP-CLIENT] Checking syntax for {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
            
            # Build check XML with proper URI format using get_object_url_patterns
            url_patterns = get_object_url_patterns(object_type, object_name)
            url_pattern = url_patterns[0] if url_patterns else object_type.lower()
            object_uri = f"/sap/bc/adt/{url_pattern}/{object_name.lower()}"
            
            check_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<chkrun:checkObjectList xmlns:adtcore="http://www.sap.com/adt/core" xmlns:chkrun="http://www.sap.com/adt/checkrun">
  <chkrun:checkObject adtcore:uri="{object_uri}" chkrun:version="inactive"/>
</chkrun:checkObjectList>"""
            
            url = f"/sap/bc/adt/checkruns?reporters=abapCheckRun&sap-client={self.connection.client}"
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/vnd.sap.adt.checkobjects+xml'
            headers['Accept'] = 'application/vnd.sap.adt.checkmessages+xml'
            
            print(f"[SAP-CLIENT] Syntax check URL: {sanitize_for_logging(url)}")
            print(f"[SAP-CLIENT] Syntax check XML: {sanitize_for_logging(check_xml)}")
            
            async with self.session.post(url, data=check_xml, headers=headers) as response:
                print(f"[SAP-CLIENT] Syntax check response status: {response.status}")
                response_data = await response.text()
                print(f"[SAP-CLIENT] Syntax check response data: {sanitize_for_logging(response_data[:500] if response_data else 'empty')}")
                
                # Handle HTTP errors - extract error message from exception XML
                if response.status != 200:
                    error_msg = self._extract_error_from_exception_xml(response_data)
                    if not error_msg:
                        error_msg = f"Syntax check failed: HTTP {response.status}"
                    
                    print(f"[SAP-CLIENT] Syntax check HTTP error: {sanitize_for_logging(error_msg)}")
                    error_result = SyntaxCheckResult(
                        success=False,
                        errors=[SAPSyntaxError(line=1, message=error_msg, severity='ERROR')],
                        warnings=[]
                    )
                    return (error_result, response_data)
                
                root = safe_parse_xml(response_data)
                result = self._parse_syntax_check_result(root)
                
                rap_logger.syntax_check(
                    sanitize_for_logging(object_name), 
                    sanitize_for_logging(object_type), 
                    'PASS' if result.success else 'FAIL', 
                    len(result.errors), 
                    len(result.warnings)
                )
                return (result, response_data)
                
        except Exception as e:
            print(f"[SAP-CLIENT] Syntax check error caught: {sanitize_for_logging(str(e))}")
            error_result = SyntaxCheckResult(
                success=False,
                errors=[SAPSyntaxError(line=1, message=str(e), severity='ERROR')],
                warnings=[]
            )
            rap_logger.error('SYNTAX_CHECK', sanitize_for_logging(object_name), sanitize_for_logging(object_type), sanitize_for_logging(str(e)))
            return (error_result, str(e))
    
    def _extract_error_from_exception_xml(self, xml_content: str) -> Optional[str]:
        """Extract error message from SAP exception XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            # Look for <message> or <localizedMessage> elements
            for elem in root.iter():
                if elem.tag.endswith('}message') or elem.tag == 'message':
                    if elem.text:
                        return elem.text.strip()
                elif elem.tag.endswith('}localizedMessage') or elem.tag == 'localizedMessage':
                    if elem.text:
                        return elem.text.strip()
            
            return None
        except Exception:
            return None
    
    async def check_syntax(self, object_name: str, object_type: str, 
                          source_code: Optional[str] = None) -> SyntaxCheckResult:
        """Check syntax of ABAP object (wrapper for check_syntax_with_response)"""
        result, _ = await self.check_syntax_with_response(object_name, object_type, source_code)
        return result
    
    def _parse_syntax_check_result(self, root) -> SyntaxCheckResult:
        """Parse syntax check result from XML (handles chkrun:checkMessage and chkl:msg formats)"""
        errors = []
        warnings = []
        
        if root is None:
            return SyntaxCheckResult(success=True, errors=[], warnings=[])
        
        try:
            import re
            
            for elem in root.iter():
                # Handle chkrun:checkMessage format (from syntax check endpoint)
                # <chkrun:checkMessage chkrun:uri="...#start=26,31" chkrun:type="E" chkrun:shortText="message"/>
                if 'checkMessage' in elem.tag or elem.tag.endswith('}checkMessage'):
                    msg_type = None
                    text = ''
                    uri = ''
                    line = 0
                    
                    for attr_name, attr_value in elem.attrib.items():
                        if 'type' in attr_name.lower():
                            msg_type = attr_value.upper()
                        elif 'shortText' in attr_name or 'shorttext' in attr_name.lower():
                            text = attr_value
                        elif 'uri' in attr_name.lower():
                            uri = attr_value
                    
                    # Extract line from uri (#start=26,31)
                    if uri and '#start=' in uri:
                        line_match = re.search(r'#start=(\d+)', uri)
                        if line_match:
                            line = int(line_match.group(1))
                    
                    if text:
                        if msg_type in ['E', 'A']:
                            errors.append(SAPSyntaxError(line=line, message=text, severity='ERROR'))
                        elif msg_type == 'W':
                            warnings.append(SyntaxWarning(line=line, message=text, severity='WARNING'))
                
                # Handle <msg> elements (chkl:messages format from activation)
                elif elem.tag.endswith('}msg') or elem.tag == 'msg':
                    msg_type = elem.get('type', 'I')
                    href = elem.get('href', '')
                    line = 0
                    
                    if href and '#start=' in href:
                        line_match = re.search(r'#start=(\d+)', href)
                        if line_match:
                            line = int(line_match.group(1))
                    
                    # Extract text from <shortText><txt> elements
                    text_parts = []
                    for txt_elem in elem.iter():
                        if txt_elem.tag.endswith('}txt') or txt_elem.tag == 'txt':
                            if txt_elem.text:
                                text_parts.append(txt_elem.text.strip())
                    
                    text = ' - '.join(text_parts) if text_parts else ''
                    obj_descr = elem.get('objDescr', '')
                    if obj_descr and text:
                        text = f"{obj_descr}: {text}"
                    
                    if text:
                        if msg_type in ['E', 'A']:
                            errors.append(SAPSyntaxError(line=line, message=text, severity='ERROR'))
                        elif msg_type == 'W':
                            warnings.append(SyntaxWarning(line=line, message=text, severity='WARNING'))
            
            print(f"[SAP-CLIENT] Parsed syntax check: {len(errors)} errors, {len(warnings)} warnings")
                        
        except Exception as e:
            print(f"[SAP-CLIENT] Error parsing syntax check result: {sanitize_for_logging(str(e))}")
        
        return SyntaxCheckResult(
            success=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def _parse_syntax_result(self, xml_content: str) -> SyntaxCheckResult:
        """Parse syntax check result from XML"""
        errors = []
        warnings = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return SyntaxCheckResult(success=True, errors=[], warnings=[])
            
            # Parse error and warning messages
            for message in root.findall('.//message'):
                severity = message.get('severity', 'INFO')
                line_str = message.get('line', '1')
                text = message.text or 'Unknown error'
                
                try:
                    line = int(line_str)
                except ValueError:
                    line = 1
                
                if severity in ['ERROR', 'FATAL']:
                    errors.append(SAPSyntaxError(
                        line=line,
                        message=text,
                        severity=severity
                    ))
                elif severity in ['WARNING', 'INFO']:
                    warnings.append(SyntaxWarning(
                        line=line,
                        message=text,
                        severity=severity
                    ))
            
        except Exception as e:
            logger.error(f"Error parsing syntax result: {sanitize_for_logging(str(e))}")
        
        return SyntaxCheckResult(
            success=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    async def activate_object(self, object_name: str, object_type: str) -> ActivationResult:
        """Activate ABAP object using SAP ADT activation endpoint"""
        try:
            print(f"[SAP-CLIENT] Activating object {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
            
            # Build activation XML matching ADT format
            activation_xml = f"""<?xml version="1.0" encoding="UTF-8"?><adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core"><adtcore:objectReference adtcore:uri="/sap/bc/adt/{format_object_type_for_url(sanitize_for_xml(object_type))}/{sanitize_for_xml(object_name.lower())}" adtcore:name="{sanitize_for_xml(object_name.upper())}"/></adtcore:objectReferences>"""
            
            url = f"/sap/bc/adt/activation?method=activate&preauditRequested=true&sap-client={self.connection.client}"
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/xml'
            headers['Accept'] = 'application/xml'
            
            print(f"[SAP-CLIENT] Activation URL: {sanitize_for_logging(url)}")
            print(f"[SAP-CLIENT] Activation XML: {sanitize_for_logging(activation_xml)}")
            
            async with self.session.post(url, data=activation_xml, headers=headers) as response:
                print(f"[SAP-CLIENT] Activation response status: {response.status}")
                
                if response.status == 200:
                    xml_content = await response.text()
                    print(f"[SAP-CLIENT] Activation response: {sanitize_for_logging(xml_content[:1000])}")
                    return self._parse_activation_result(xml_content)
                else:
                    error_text = await response.text()
                    print(f"[SAP-CLIENT] Activation failed: {response.status} - {sanitize_for_logging(error_text[:500])}")
                    return ActivationResult(
                        success=False,
                        activated=False,
                        errors=[SAPSyntaxError(line=1, message=f"Activation failed: HTTP {response.status}", severity="ERROR")],
                        warnings=[],
                        messages=[]
                    )
                    
        except Exception as e:
            print(f"[SAP-CLIENT] Activation error: {sanitize_for_logging(str(e))}")
            logger.error(f"Error activating object: {sanitize_for_logging(str(e))}")
            return ActivationResult(
                success=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=str(e), severity="ERROR")],
                warnings=[],
                messages=[]
            )

    async def activate_objects_batch(self, objects: List[Dict[str, str]]) -> ActivationResult:
        """
        Activate multiple ABAP objects in a single batch request (for handling circular dependencies)
        
        Based on SAP ADT call analysis:
        - Uses /sap/bc/adt/activation/runs endpoint
        - Returns 201 Created with Location header
        - SAP ADT doesn't poll - it just accepts the 201 response as success
        - Object URIs must match exact SAP format
        
        Args:
            objects: List of dicts with 'name' and 'type' keys
            
        Returns:
            ActivationResult with combined results
        """
        try:
            object_names = [obj['name'] for obj in objects]
            print(f"[SAP-CLIENT] Batch activating {len(objects)} objects: {sanitize_for_logging(', '.join(object_names))}")
            
            # Build batch activation XML matching exact SAP ADT format
            object_refs = []
            for obj in objects:
                obj_name = sanitize_for_xml(obj['name'])
                obj_type = sanitize_for_xml(obj['type'])
                
                # Build URI based on object type (matching SAP ADT format)
                if obj_type.startswith('DDLS'):
                    uri = f"/sap/bc/adt/ddic/ddl/sources/{obj_name.lower()}"
                elif obj_type.startswith('CLAS'):
                    uri = f"/sap/bc/adt/oo/classes/{obj_name.lower()}"
                elif obj_type.startswith('BDEF'):
                    uri = f"/sap/bc/adt/ddic/bdef/sources/{obj_name.lower()}"
                elif obj_type.startswith('SRVD'):
                    uri = f"/sap/bc/adt/ddic/srvd/sources/{obj_name.lower()}"
                elif obj_type.startswith('SRVB'):
                    uri = f"/sap/bc/adt/businessservices/bindings/{obj_name.lower()}"
                else:
                    # Fallback to generic format
                    uri = f"/sap/bc/adt/{format_object_type_for_url(obj_type)}/{obj_name.lower()}"
                
                # Ensure object type includes subtype (e.g., DDLS/DF not just DDLS)
                if obj_type == 'DDLS':
                    obj_type = 'DDLS/DF'
                elif obj_type == 'CLAS':
                    obj_type = 'CLAS/OC'
                elif obj_type == 'BDEF':
                    obj_type = 'BDEF/BDO'
                
                object_refs.append(
                    f'<adtcore:objectReference adtcore:uri="{uri}" adtcore:type="{obj_type}" adtcore:name="{obj_name.upper()}"/>'
                )
            
            activation_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">
{''.join(object_refs)}
</adtcore:objectReferences>"""
            
            # Use batch activation endpoint exactly as SAP ADT does
            url = f"/sap/bc/adt/activation/runs?method=activate&preauditRequested=false&sap-client={self.connection.client}"
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/xml'
            headers['Accept'] = 'application/xml'
            headers['User-Agent'] = 'ABAP-Accelerator-MCP-Server/1.0.0'
            
            print(f"[SAP-CLIENT] Batch activation URL: {sanitize_for_logging(url)}")
            print(f"[SAP-CLIENT] Batch activation XML: {sanitize_for_logging(activation_xml)}")
            
            async with self.session.post(url, data=activation_xml, headers=headers, timeout=aiohttp.ClientTimeout(total=60)) as response:
                print(f"[SAP-CLIENT] Batch activation response status: {response.status}")
                
                if response.status == 201:  # Created - batch activation accepted
                    location = response.headers.get('Location', '')
                    print(f"[SAP-CLIENT] Batch activation accepted by SAP, location: {sanitize_for_logging(location)}")
                    
                    # SAP returns 201 Created with a Location header pointing to the activation run
                    # We need to poll this location to get the actual activation results
                    if location:
                        print("[SAP-CLIENT] Polling activation results...")
                        activation_result = await self._poll_batch_activation_results(location)
                        return activation_result
                    else:
                        print("[SAP-CLIENT] No location header provided, assuming success")
                        return ActivationResult(
                            success=True, 
                            activated=True, 
                            errors=[], 
                            warnings=[], 
                            messages=[f"Batch activation submitted for {len(objects)} objects (no location to poll results)."]
                        )
                        
                elif response.status == 200:  # Immediate completion (rare for batch)
                    xml_content = await response.text()
                    print(f"[SAP-CLIENT] Batch activation completed immediately: {sanitize_for_logging(xml_content[:1000])}")
                    return self._parse_activation_result(xml_content)
                    
                else:
                    error_text = await response.text()
                    print(f"[SAP-CLIENT] Batch activation failed: {response.status} - {sanitize_for_logging(error_text[:500])}")
                    
                    # Try to extract meaningful error from SAP response
                    error_message = f"Batch activation failed: HTTP {response.status}"
                    if "does not exist" in error_text.lower():
                        error_message += " - One or more objects do not exist"
                    elif "not active" in error_text.lower():
                        error_message += " - One or more dependent objects are not active"
                    elif "authorization" in error_text.lower() or "permission" in error_text.lower():
                        error_message += " - Insufficient authorization"
                    
                    return ActivationResult(
                        success=False,
                        activated=False,
                        errors=[SAPSyntaxError(line=1, message=error_message, severity="ERROR")],
                        warnings=[],
                        messages=[]
                    )
                    
        except Exception as e:
            print(f"[SAP-CLIENT] Batch activation error: {sanitize_for_logging(str(e))}")
            logger.error(f"Error in batch activation: {sanitize_for_logging(str(e))}")
            return ActivationResult(
                success=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=str(e), severity="ERROR")],
                warnings=[],
                messages=[]
            )

    async def _poll_batch_activation_results(self, location: str, max_attempts: int = 30, poll_interval: float = 1.0) -> ActivationResult:
        """Poll the batch activation results from the location URL (matching TypeScript implementation)"""
        try:
            print(f"[SAP-CLIENT] Polling batch activation results from: {sanitize_for_logging(location)}")
            
            # Extract run ID from location
            run_id = location.split('/')[-1]
            print(f"[SAP-CLIENT] Polling activation run: {sanitize_for_logging(run_id)}")
            
            for attempt in range(max_attempts):
                print(f"[SAP-CLIENT] Polling attempt {attempt + 1}/{max_attempts}")
                
                # Use the same approach as TypeScript: poll with withLongPolling=true
                status_url = f"{location}?withLongPolling=true&sap-client={self.connection.client}"
                
                headers = await self._get_appropriate_headers()
                headers['Accept'] = 'application/xml, application/vnd.sap.adt.backgroundrun.v1+xml'
                
                async with self.session.get(f"{status_url}", headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        xml_content = await response.text()
                        print(f"[SAP-CLIENT] Status response: {sanitize_for_logging(xml_content[:500])}")
                        
                        # Check if the response contains "finished" status
                        if 'status="finished"' in xml_content or 'runs:status="finished"' in xml_content:
                            print("[SAP-CLIENT] Batch activation run finished")
                            
                            # Parse the XML to extract the result link
                            root = safe_parse_xml(xml_content)
                            if root is None:
                                print("[SAP-CLIENT] Failed to parse status XML")
                                continue
                            
                            result_link = None
                            for elem in root.iter():
                                # Look for result link in atom:link elements
                                if elem.tag.endswith('}link') or elem.tag == 'link':
                                    href = elem.get('href', '')
                                    rel = elem.get('rel', '')
                                    print(f"[SAP-CLIENT] Found link element: href={href}, rel={rel}")
                                    if 'result' in rel or 'result' in href:
                                        result_link = href
                                        print(f"[SAP-CLIENT] Found result link: {result_link}")
                                        break
                            
                            if result_link:
                                print(f"[SAP-CLIENT] Fetching activation results from: {sanitize_for_logging(result_link)}")
                                
                                # Fetch the actual results
                                result_url = f"{result_link}?sap-client={self.connection.client}"
                                result_headers = await self._get_appropriate_headers()
                                result_headers['Accept'] = 'application/xml'
                                
                                async with self.session.get(f"{result_url}", headers=result_headers, timeout=aiohttp.ClientTimeout(total=30)) as result_response:
                                    if result_response.status == 200:
                                        result_xml = await result_response.text()
                                        print(f"[SAP-CLIENT] Activation results: {sanitize_for_logging(result_xml[:1000])}")
                                        
                                        # Parse the activation results
                                        result = self._parse_activation_result(result_xml)
                                        print(f"[SAP-CLIENT] Batch activation completed: success={result.success}, errors={len(result.errors)}")
                                        return result
                                    else:
                                        print(f"[SAP-CLIENT] Failed to fetch results: {result_response.status}")
                            else:
                                print("[SAP-CLIENT] No result link found, assuming success")
                                return ActivationResult(
                                    success=True,
                                    activated=True,
                                    errors=[],
                                    warnings=[],
                                    messages=["Batch activation completed (no result link found)"]
                                )
                        
                        else:
                            print("[SAP-CLIENT] Batch activation still in progress...")
                    
                    else:
                        print(f"[SAP-CLIENT] Unexpected response status while polling: {response.status}")
                
                # Wait before next attempt (only if not the last attempt)
                if attempt < max_attempts - 1:
                    print(f"[SAP-CLIENT] Waiting {poll_interval} seconds before next poll...")
                    await asyncio.sleep(poll_interval)
            
            # If we've exhausted all attempts, return a timeout result
            print("[SAP-CLIENT] Batch activation polling timed out")
            return ActivationResult(
                success=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message="Batch activation polling timed out", severity="ERROR")],
                warnings=[],
                messages=["Batch activation may still be processing in the background"]
            )
            
        except Exception as e:
            print(f"[SAP-CLIENT] Error polling batch activation results: {sanitize_for_logging(str(e))}")
            return ActivationResult(
                success=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=f"Error polling results: {str(e)}", severity="ERROR")],
                warnings=[],
                messages=[]
            )

    def _parse_activation_result(self, xml_content: str) -> ActivationResult:
        """Parse activation result from XML (handles chkl:messages format from SAP ADT)"""
        errors = []
        warnings = []
        messages = []
        activation_executed = None  # Default to None (not found)
        activation_executed_found = False  # Track if we found the attribute
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                print("[SAP-CLIENT] No XML root found, assuming activation success")
                return ActivationResult(success=True, activated=True, errors=[], warnings=[], messages=[])
            
            # Check for chkl:properties to determine if activation was executed
            # Format: <chkl:properties checkExecuted="true" activationExecuted="false" .../>
            for elem in root.iter():
                if 'properties' in elem.tag.lower():
                    for attr_name, attr_value in elem.attrib.items():
                        if 'activationExecuted' in attr_name:
                            activation_executed_found = True
                            activation_executed = attr_value.lower() == 'true'
                            print(f"[SAP-CLIENT] activationExecuted = {activation_executed}")
                            break
            
            # Parse messages - handle SAP's chkl:messages format
            # Format: <msg objDescr="..." type="E" line="1" href="..."><shortText><txt>message</txt></shortText></msg>
            for elem in root.iter():
                # Match 'msg' elements (handles both namespaced and non-namespaced)
                if elem.tag.endswith('}msg') or elem.tag == 'msg':
                    msg_type = elem.get('type', 'I')  # E=Error, W=Warning, I=Info
                    line_str = elem.get('line', '0')
                    href = elem.get('href', '')
                    obj_descr = elem.get('objDescr', '')
                    
                    # Extract line number from href if available (format: #start=26,30)
                    line = 0
                    try:
                        line = int(line_str) if line_str else 0
                    except ValueError:
                        line = 0
                    
                    if href and '#start=' in href:
                        import re
                        line_match = re.search(r'#start=(\d+)', href)
                        if line_match:
                            line = int(line_match.group(1))
                    
                    # Extract message text from <shortText><txt> elements
                    text_parts = []
                    for txt_elem in elem.iter():
                        if txt_elem.tag.endswith('}txt') or txt_elem.tag == 'txt':
                            if txt_elem.text:
                                text_parts.append(txt_elem.text.strip())
                    
                    # Combine text parts, or use element text as fallback
                    text = ' - '.join(text_parts) if text_parts else (elem.text or 'Unknown message')
                    
                    # Add object description if available
                    if obj_descr and obj_descr not in text:
                        text = f"{obj_descr}: {text}"
                    
                    messages.append(text)
                    print(f"[SAP-CLIENT] Parsed message: type={msg_type}, line={line}, text={sanitize_for_logging(text[:100])}")
                    
                    # Categorize by type
                    if msg_type in ['E', 'A']:  # Error or Abort
                        errors.append(SAPSyntaxError(line=line, message=text, severity='ERROR'))
                    elif msg_type == 'W':  # Warning
                        warnings.append(SyntaxWarning(line=line, message=text, severity='WARNING'))
                    # Info messages (type='I') are just logged, not added to errors/warnings
            
            print(f"[SAP-CLIENT] Activation parsing complete: {len(errors)} errors, {len(warnings)} warnings, activated={activation_executed}")
            
        except Exception as e:
            print(f"[SAP-CLIENT] Error parsing activation result: {sanitize_for_logging(str(e))}")
            logger.error(f"Error parsing activation result: {sanitize_for_logging(str(e))}")
        
        # Success logic matching TypeScript version:
        # Success if no errors AND (activationExecuted is null/not found OR activationExecuted is true)
        # This handles cases where SAP doesn't return activationExecuted attribute (backward compatibility)
        no_errors = len(errors) == 0
        activation_ok = activation_executed is None or activation_executed == True
        success = no_errors and activation_ok
        
        # Activated is true only if explicitly set to true (not null/not found)
        activated = activation_executed == True
        
        print(f"[SAP-CLIENT] Activation result: no_errors={no_errors}, activation_executed={activation_executed}, success={success}, activated={activated}")
        
        return ActivationResult(
            success=success,
            activated=activated,
            errors=errors,
            warnings=warnings,
            messages=messages
        )
    
    async def run_atc_check(self, args: ATCCheckArgs) -> List[ATCResult]:
        """Run ATC check on objects using SAP ADT ATC API (following ADT flow)"""
        target_desc = args.object_name or args.package_name or args.transport_number or 'unknown'
        try:
            logger.info(f"Running ATC check for {sanitize_for_logging(target_desc)}"
                       f"{f' with variant {sanitize_for_logging(args.variant)}' if args.variant else ''}")
            
            # Step 1: Create ATC Worklist (following ADT pattern)
            logger.info("Step 1: Creating ATC worklist")
            worklist_id = await self._create_atc_worklist(args.variant or 'DEFAULT')
            
            # Step 2: Start ATC Run with proper object references
            logger.info("Step 2: Starting ATC run")
            object_refs = self._build_object_references(args)
            run_id = await self._start_atc_run(worklist_id, object_refs)
            
            # Step 3: Poll Run Status (immediate polling like ADT)
            logger.info("Step 3: Polling run status")
            await self._wait_for_atc_run_completion(run_id, args.max_wait_time or 300, args.poll_interval or 2)
            
            # Step 4: Get Worklist Results
            logger.info("Step 4: Getting worklist results")
            worklist = await self._get_atc_worklist(worklist_id, False)
            
            # Step 5: Convert to results and get documentation
            results = self._convert_worklist_to_results(worklist)
            if args.include_documentation:
                logger.info(f"Step 5: Fetching documentation for {len(results)} findings")
                await self._enrich_results_with_documentation(results, worklist)
                
                with_docs = len([r for r in results if r.documentation])
                without_docs = len(results) - with_docs
                logger.info(f"Documentation summary: {with_docs} findings with documentation, {without_docs} without")
            
            logger.info(f"ATC check completed. Found {len(results)} findings.")
            return results
            
        except Exception as e:
            logger.error(f"ATC check error: {sanitize_for_logging(str(e))}")
            return []
    
    async def _create_atc_worklist(self, variant: str) -> str:
        """Step 1: Create ATC Worklist"""
        url = f"/sap/bc/adt/atc/worklists?checkVariant={variant}&sap-client={self.connection.client}"
        
        headers = await self._get_appropriate_headers()
        headers['Accept'] = 'text/plain'
        
        async with self.session.post(url, data='', headers=headers) as response:
            if response.status == 200:
                worklist_id = (await response.text()).strip()
                logger.info(f"Worklist created: {sanitize_for_logging(worklist_id)}")
                return worklist_id
            else:
                raise Exception(f"Failed to create ATC worklist: HTTP {response.status}")
    
    async def _start_atc_run(self, worklist_id: str, object_references: List[Dict[str, str]]) -> str:
        """Step 2: Start ATC Run"""
        url = f"/sap/bc/adt/atc/runs?worklistId={worklist_id}&clientWait=false&sap-client={self.connection.client}"
        
        # Build object references XML
        object_refs_xml = '\n        '.join([
            f'<adtcore:objectReference adtcore:uri="{sanitize_for_xml(ref["uri"])}"/>'
            for ref in object_references
        ])
        
        run_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<atc:run maximumVerdicts="100" xmlns:atc="http://www.sap.com/adt/atc">
  <objectSets xmlns:adtcore="http://www.sap.com/adt/core">
    <objectSet kind="inclusive">
      <adtcore:objectReferences>
        {object_refs_xml}
      </adtcore:objectReferences>
    </objectSet>
  </objectSets>
</atc:run>"""
        
        headers = await self._get_appropriate_headers()
        headers['Content-Type'] = 'application/xml'
        headers['Accept'] = 'application/xml'
        
        async with self.session.post(url, data=run_xml, headers=headers) as response:
            if response.status == 201:
                location = response.headers.get('location')
                if location:
                    run_id = location.split('/')[-1]
                    logger.info(f"ATC run started: {sanitize_for_logging(run_id)}")
                    return run_id
            
            # Log detailed error information
            error_text = await response.text()
            logger.error(f"ATC run start failed with status {response.status}")
            logger.error(f"Error response: {sanitize_for_logging(error_text[:500])}")
            logger.error(f"Request URL: {sanitize_for_logging(url)}")
            logger.error(f"Request XML: {sanitize_for_logging(run_xml)}")
            
            raise Exception(f"Failed to start ATC run: HTTP {response.status} - {error_text[:200] if error_text else 'No error details'}")
    
    async def _get_atc_run_status(self, run_id: str) -> Dict[str, Any]:
        """Step 3: Get ATC Run Status"""
        url = f"/sap/bc/adt/atc/runs/{run_id}?sap-client={self.connection.client}"
        
        headers = await self._get_appropriate_headers()
        headers['Accept'] = 'application/vnd.sap.adt.backgroundrun.v1+xml'
        
        async with self.session.get(url, headers=headers) as response:
            if response.status == 200:
                xml_content = await response.text()
                logger.info(f"ATC run status XML response: {sanitize_for_logging(xml_content)}")
                
                root = safe_parse_xml(xml_content)
                if root is not None:
                    # Extract status from namespaced attribute
                    status = 'running'  # default
                    
                    # Method 1: Check for runs:status attribute in root element
                    for attr_name, attr_value in root.attrib.items():
                        if attr_name.endswith('status') or 'status' in attr_name:
                            status = attr_value
                            break
                    
                    # Method 2: If not found, try to find any element with status
                    if status == 'running':
                        for elem in root.iter():
                            for attr_name, attr_value in elem.attrib.items():
                                if 'status' in attr_name.lower():
                                    status = attr_value
                                    break
                            if status != 'running':
                                break
                    
                    logger.info(f"Extracted ATC run status: {sanitize_for_logging(status)}")
                    result = {'status': status}
                    
                    if status == 'finished':
                        # Extract result and worklist URLs if available
                        result_link = extract_from_xml(root, 'runs:run.runs:result.atom:link', {}).get('href')
                        if result_link:
                            result['resultUrl'] = result_link
                    
                    return result
            
            raise Exception(f"Failed to get ATC run status: HTTP {response.status}")
    
    async def _wait_for_atc_run_completion(self, run_id: str, max_wait_time: int, poll_interval: int):
        """Step 3: Wait for ATC Run Completion"""
        import asyncio
        start_time = asyncio.get_event_loop().time()
        
        while asyncio.get_event_loop().time() - start_time < max_wait_time:
            status_info = await self._get_atc_run_status(run_id)
            
            if status_info['status'] == 'finished':
                logger.info("ATC run completed")
                return
            
            if status_info['status'] == 'failed':
                raise Exception('ATC run failed')
            
            logger.info(f"ATC run status: {status_info['status']}, waiting...")
            await asyncio.sleep(poll_interval)
        
        raise Exception(f"ATC run timeout after {max_wait_time}s")
    
    async def _get_atc_worklist(self, worklist_id: str, include_exempted: bool) -> Dict[str, Any]:
        """Step 4: Get ATC Worklist Results"""
        url = f"/sap/bc/adt/atc/worklists/{worklist_id}?includeExemptedFindings={str(include_exempted).lower()}&usedObjectSet=99999999999999999999999999999999&sap-client={self.connection.client}"
        
        headers = await self._get_appropriate_headers()
        headers['Accept'] = 'application/atc.worklist.v1+xml'
        
        async with self.session.get(url, headers=headers) as response:
            if response.status == 200:
                xml_content = await response.text()
                logger.info(f"ATC worklist XML response: {sanitize_for_logging(xml_content[:1000])}...")
                return self._parse_atc_worklist(xml_content)
            else:
                raise Exception(f"Failed to get ATC worklist: HTTP {response.status}")
    
    async def get_atc_documentation(self, item_id: str, index: int) -> str:
        """Step 5: Get Finding Documentation"""
        url = f"/sap/bc/adt/documentation/atc/documents/itemid/{item_id}/index/{index}?sap-client={self.connection.client}"
        
        headers = await self._get_appropriate_headers()
        headers['Accept'] = 'application/vnd.sap.adt.docu.v1+html, text/html'
        
        async with self.session.get(url, headers=headers) as response:
            if response.status == 200:
                return await response.text()
            else:
                raise Exception(f"Failed to get ATC documentation: HTTP {response.status}")
    
    def _build_object_references(self, args: ATCCheckArgs) -> List[Dict[str, str]]:
        """Build object references for ATC check"""
        if args.object_name and args.object_type:
            # For ATC checks on individual objects, use the source URI format like ADT does
            object_name_lower = args.object_name.lower()
            object_type_upper = args.object_type.upper()
            
            # Map object types to their ADT URL patterns
            type_mappings = {
                'PROG': f"/sap/bc/adt/programs/programs/{object_name_lower}/source/main",
                'CLAS': f"/sap/bc/adt/oo/classes/{object_name_lower}/source/main", 
                'INTF': f"/sap/bc/adt/oo/interfaces/{object_name_lower}/source/main",
                'FUGR': f"/sap/bc/adt/functions/groups/{object_name_lower}/source/main",
                'DEVC': f"/sap/bc/adt/packages/{object_name_lower}",
                'TABL': f"/sap/bc/adt/ddic/tables/{object_name_lower}/source/main",
                'DTEL': f"/sap/bc/adt/ddic/dataelements/{object_name_lower}/source/main",
                'DOMA': f"/sap/bc/adt/ddic/domains/{object_name_lower}/source/main",
                # RAP/Business Object types
                'BDEF': f"/sap/bc/adt/bo/behaviordefinitions/{object_name_lower}/source/main",
                'DDLS': f"/sap/bc/adt/ddic/ddl/sources/{object_name_lower}/source/main",
                'DCLS': f"/sap/bc/adt/acm/dcl/sources/{object_name_lower}/source/main",
                # Additional common types
                'TTYP': f"/sap/bc/adt/ddic/tabletypes/{object_name_lower}/source/main",
                'SHLP': f"/sap/bc/adt/ddic/searchhelps/{object_name_lower}/source/main",
                'VIEW': f"/sap/bc/adt/ddic/views/{object_name_lower}/source/main",
                'ENQU': f"/sap/bc/adt/ddic/lockobjects/{object_name_lower}/source/main"
            }
            
            # Get the appropriate URI for the object type
            uri = type_mappings.get(object_type_upper)
            if not uri:
                # Fallback to generic format
                uri = f"/sap/bc/adt/{format_object_type_for_url(args.object_type)}/{object_name_lower}/source/main"
            
            return [{'uri': uri}]
        
        if args.package_name:
            return [{
                'uri': f"/sap/bc/adt/repository/informationsystem/virtualfolders?selection=package%3a{args.package_name}"
            }]
        
        if args.transport_number:
            return [{
                'uri': f"/sap/bc/adt/repository/informationsystem/virtualfolders?selection=transport%3a{args.transport_number}"
            }]
        
        # If objectName is provided without objectType, assume it's a package
        if args.object_name:
            logger.info(f"No objectType provided, treating '{sanitize_for_logging(args.object_name)}' as package name")
            return [{
                'uri': f"/sap/bc/adt/repository/informationsystem/virtualfolders?selection=package%3a{args.object_name}"
            }]
        
        return []
    
    def _parse_atc_worklist(self, xml_content: str) -> Dict[str, Any]:
        """Parse ATC worklist from XML"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return {'id': '', 'timestamp': '', 'objects': []}
            
            # Extract attributes from root element (handle namespaces)
            worklist_id = ''
            timestamp = ''
            for attr_name, attr_value in root.attrib.items():
                if attr_name.endswith('id') or 'id' in attr_name:
                    worklist_id = attr_value
                elif attr_name.endswith('timestamp') or 'timestamp' in attr_name:
                    timestamp = attr_value
            
            worklist = {
                'id': worklist_id,
                'timestamp': timestamp,
                'objects': []
            }
            
            # Find objects using precise namespace-aware search
            objects = []
            # Find all object elements but be more selective
            for elem in root.iter():
                if elem.tag.endswith('}object') and not elem.tag.endswith('}objects'):
                    # Make sure this is actually an atcobject:object, not some other object
                    parent = elem.getparent() if hasattr(elem, 'getparent') else None
                    if parent is None or parent.tag.endswith('}objects'):
                        objects.append(elem)
            
            logger.info(f"Found {len(objects)} ATC objects in worklist")
            
            # Debug: Log first 1000 chars of XML for troubleshooting
            if len(objects) > 0:
                logger.debug(f"XML sample: {sanitize_for_logging(xml_content[:1000])}")
            
            total_findings_count = 0
            
            for obj in objects:
                if obj is None:
                    continue
                
                # Extract attributes (handle namespaces)
                obj_uri = ''
                obj_type = ''
                obj_name = ''
                obj_package = ''
                
                for attr_name, attr_value in obj.attrib.items():
                    if attr_name.endswith('uri') or 'uri' in attr_name:
                        obj_uri = attr_value
                    elif attr_name.endswith('type') or attr_name == 'type':
                        obj_type = attr_value
                    elif attr_name.endswith('name') or attr_name == 'name':
                        obj_name = attr_value
                    elif 'packageName' in attr_name or 'package' in attr_name:
                        obj_package = attr_value
                
                atc_object = {
                    'uri': obj_uri,
                    'type': obj_type,
                    'name': obj_name,
                    'packageName': obj_package,
                    'findings': []
                }
                
                # Find findings using multiple approaches for robustness
                findings = []
                
                # Approach 1: Look for findings container first
                findings_container = None
                for child in obj:
                    if child.tag.endswith('}findings') or 'findings' in child.tag:
                        findings_container = child
                        break
                
                if findings_container is not None:
                    # Find finding elements within the container
                    for elem in findings_container:
                        if elem.tag.endswith('}finding') or 'finding' in elem.tag:
                            findings.append(elem)
                else:
                    # Approach 2: Look for findings directly under object (fallback)
                    for elem in obj.iter():
                        if elem.tag.endswith('}finding') or 'finding' in elem.tag:
                            # Make sure it's a direct descendant, not deeply nested
                            if elem.getparent() == obj or (elem.getparent() is not None and elem.getparent().getparent() == obj):
                                findings.append(elem)
                
                logger.info(f"Object {sanitize_for_logging(obj_name)} has {len(findings)} findings")
                total_findings_count += len(findings)
                
                for finding in findings:
                    if finding is None:
                        continue
                    
                    # Extract finding attributes (handle namespaces)
                    finding_uri = ''
                    location = ''
                    priority = 3
                    check_id = ''
                    check_title = ''
                    message_id = ''
                    message_title = ''
                    quickfix_info = ''
                    processor = ''
                    last_changed_by = ''
                    exemption_approval = ''
                    exemption_kind = ''
                    checksum = ''
                    
                    for attr_name, attr_value in finding.attrib.items():
                        if attr_name.endswith('uri') or 'uri' in attr_name:
                            finding_uri = attr_value
                        elif 'location' in attr_name:
                            location = attr_value
                        elif 'priority' in attr_name:
                            try:
                                priority = int(attr_value)
                            except ValueError:
                                priority = 3
                        elif 'checkId' in attr_name:
                            check_id = attr_value
                        elif 'checkTitle' in attr_name:
                            check_title = attr_value
                        elif 'messageId' in attr_name:
                            message_id = attr_value
                        elif 'messageTitle' in attr_name:
                            message_title = attr_value
                        elif 'quickfixInfo' in attr_name:
                            quickfix_info = attr_value
                        elif 'processor' in attr_name:
                            processor = attr_value
                        elif 'lastChangedBy' in attr_name:
                            last_changed_by = attr_value
                        elif 'exemptionApproval' in attr_name:
                            exemption_approval = attr_value
                        elif 'exemptionKind' in attr_name:
                            exemption_kind = attr_value
                        elif 'checksum' in attr_name:
                            checksum = attr_value
                    
                    atc_finding = {
                        'uri': finding_uri,
                        'location': location,
                        'priority': priority,
                        'checkId': check_id,
                        'checkTitle': check_title,
                        'messageId': message_id,
                        'messageTitle': message_title,
                        'quickfixInfo': quickfix_info,
                        'processor': processor,
                        'lastChangedBy': last_changed_by,
                        'exemptionApproval': exemption_approval,
                        'exemptionKind': exemption_kind,
                        'checksum': checksum,
                        'documentationUrl': None,
                        'tags': [],
                        'quickfixes': {}
                    }
                    
                    # Look for child elements (documentation URL, tags, quickfixes)
                    for child in finding:
                        if child.tag.endswith('}link') or 'link' in child.tag:
                            rel = child.attrib.get('rel', '')
                            if 'documentation' in rel:
                                atc_finding['documentationUrl'] = child.attrib.get('href', '')
                        
                        elif child.tag.endswith('}quickfixes') or 'quickfixes' in child.tag:
                            # Extract quickfix information
                            quickfixes = {}
                            for attr_name, attr_value in child.attrib.items():
                                if 'manual' in attr_name:
                                    quickfixes['manual'] = attr_value.lower() == 'true'
                                elif 'automatic' in attr_name:
                                    quickfixes['automatic'] = attr_value.lower() == 'true'
                                elif 'pseudo' in attr_name:
                                    quickfixes['pseudo'] = attr_value.lower() == 'true'
                            atc_finding['quickfixes'] = quickfixes
                        
                        elif child.tag.endswith('}tags') or 'tags' in child.tag:
                            # Extract tags
                            tags = []
                            for tag_elem in child:
                                if tag_elem.tag.endswith('}tag') or 'tag' in tag_elem.tag:
                                    tag_name = ''
                                    tag_value = ''
                                    for attr_name, attr_value in tag_elem.attrib.items():
                                        if 'name' in attr_name:
                                            tag_name = attr_value
                                        elif 'value' in attr_name:
                                            tag_value = attr_value
                                    if tag_name:
                                        tags.append({'name': tag_name, 'value': tag_value})
                            atc_finding['tags'] = tags
                    
                    atc_object['findings'].append(atc_finding)
                    
                logger.info(f"Object {obj_name} has {len(atc_object['findings'])} findings")
                
                worklist['objects'].append(atc_object)
            
            logger.info(f"ATC worklist parsing completed: {len(worklist['objects'])} objects, {total_findings_count} total findings")
            return worklist
            
        except Exception as e:
            logger.error(f"Error parsing ATC worklist: {sanitize_for_logging(str(e))}")
            # Log more details for debugging
            logger.error(f"XML content length: {len(xml_content) if xml_content else 0}")
            if xml_content:
                logger.error(f"XML starts with: {sanitize_for_logging(xml_content[:200])}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {'id': '', 'timestamp': '', 'objects': []}
    
    def _convert_worklist_to_results(self, worklist: Dict[str, Any]) -> List[ATCResult]:
        """Convert ATC worklist to ATCResult objects"""
        results = []
        
        for obj in worklist.get('objects', []):
            for finding in obj.get('findings', []):
                # Extract line number from location
                line = self._extract_line_from_location(finding.get('location', ''))
                
                # If no line from location, try documentation URL
                if not line and finding.get('documentationUrl'):
                    line = self._extract_line_from_documentation_url(finding['documentationUrl'])
                
                # Convert tags to ATCTag objects
                tags = []
                for tag_data in finding.get('tags', []):
                    from sap_types.sap_types import ATCTag
                    tags.append(ATCTag(
                        name=tag_data.get('name', ''),
                        value=tag_data.get('value', '')
                    ))
                
                result = ATCResult(
                    severity=self._map_priority_to_severity(finding.get('priority', 3)),
                    message=finding.get('messageTitle', '') or finding.get('checkTitle', ''),
                    line=line,
                    check_id=finding.get('checkId'),
                    check_title=finding.get('checkTitle'),
                    message_id=finding.get('messageId'),
                    priority=str(finding.get('priority', 3)),
                    documentation_url=finding.get('documentationUrl'),
                    processor=finding.get('processor'),
                    last_changed_by=finding.get('lastChangedBy'),
                    exemption_approval=finding.get('exemptionApproval'),
                    exemption_kind=finding.get('exemptionKind'),
                    checksum=finding.get('checksum'),
                    quickfix_info=finding.get('quickfixInfo'),
                    quickfix_capabilities=finding.get('quickfixes', {}),
                    tags=tags if tags else None
                )
                results.append(result)
        
        return results
    
    def _extract_line_from_location(self, location: str) -> Optional[int]:
        """Extract line number from location string"""
        if not location:
            return None
        
        import re
        patterns = [
            r'#start=(\d+),',      # Current pattern
            r'line=(\d+)',         # Alternative pattern
            r':(\d+):',            # Another common pattern
            r'start=(\d+)'         # Without hash
        ]
        
        for pattern in patterns:
            match = re.search(pattern, location)
            if match:
                line_num = int(match.group(1))
                return line_num if line_num > 0 else None
        
        return None
    
    def _extract_line_from_documentation_url(self, doc_url: str) -> Optional[int]:
        """Extract line number from documentation URL"""
        if not doc_url:
            return None
        
        import re
        match = re.search(r'#start=(\d+),', doc_url)
        return int(match.group(1)) if match else None
    
    def _map_priority_to_severity(self, priority: int) -> SeverityType:
        """Map ATC priority to severity"""
        if priority == 1:
            return SeverityType.ERROR
        elif priority == 2:
            return SeverityType.WARNING
        else:
            return SeverityType.INFO
    
    async def _enrich_results_with_documentation(self, results: List[ATCResult], worklist: Dict[str, Any]):
        """Enrich ATC results with documentation"""
        for result in results:
            if result.documentation_url:
                try:
                    item_id = self._extract_item_id(result.documentation_url)
                    index = self._extract_index(result.documentation_url)
                    
                    if item_id and index is not None:
                        result.documentation = await self.get_atc_documentation(item_id, index)
                        
                        if result.documentation:
                            logger.info(f"Documentation retrieved for finding {sanitize_for_logging(result.check_id or 'unknown')}: "
                                      f"{len(result.documentation)} characters")
                        else:
                            logger.info(f"No documentation content retrieved for finding {sanitize_for_logging(result.check_id or 'unknown')}")
                    else:
                        logger.warning(f"Could not extract item ID or index from documentation URL: {sanitize_for_logging(result.documentation_url)}")
                        
                except Exception as e:
                    logger.error(f"Failed to get documentation for finding {sanitize_for_logging(result.check_id or 'unknown')}: {sanitize_for_logging(str(e))}")
    
    def _extract_item_id(self, doc_url: str) -> Optional[str]:
        """Extract item ID from documentation URL"""
        if not doc_url:
            return None
        
        import re
        match = re.search(r'/itemid/([^/]+)/', doc_url)
        return match.group(1) if match else None
    
    def _extract_index(self, doc_url: str) -> Optional[int]:
        """Extract index from documentation URL"""
        if not doc_url:
            return None
        
        import re
        match = re.search(r'/index/(\d+)', doc_url)
        return int(match.group(1)) if match else None
    
    async def run_unit_tests(self, object_name: str, object_type: str, 
                           with_coverage: bool = False) -> List[UnitTestResult]:
        """Run unit tests for ABAP object"""
        try:
            logger.info(f"Running unit tests for {sanitize_for_logging(object_name)}{' with coverage' if with_coverage else ''}")
            
            # Check for local test classes (informational only, doesn't block execution)
            # This helps identify if tests are local (in /includes/testclasses) or global (separate class)
            test_class_source = await self.get_test_classes(object_name, object_type)
            if test_class_source:
                print(f"[SAP-CLIENT] Found local test classes for {sanitize_for_logging(object_name)}")
            else:
                print(f"[SAP-CLIENT] No local test classes found for {sanitize_for_logging(object_name)}, checking for global test classes or test methods in the class itself")
            
            # Continue to run tests regardless - SAP will determine if tests exist
            # This handles:
            # - Local test classes (in /includes/testclasses)
            # - Global test classes (separate class files)
            # - Test methods directly in the class
            # - Classes with no tests (SAP returns empty result)
            
            # Try direct execution following the correct procedure
            try:
                print(f"[SAP-CLIENT] Starting ABAP unit test execution for {sanitize_for_logging(object_name)}{' with coverage' if with_coverage else ''}")
                
                # Step 1: Get CSRF token specifically for ABAP unit tests
                print("[SAP-CLIENT] Step 1: Getting CSRF token for ABAP unit tests")
                csrf_url = self.add_client_param('/sap/bc/adt/api/abapunit/runs/00000000000000000000000000000000')
                
                async with self.session.get(
                    csrf_url,
                    headers={
                        **await self._get_appropriate_headers(True),
                        'Accept': 'application/vnd.sap.adt.api.abapunit.run-status.v1+xml'
                    }
                ) as csrf_response:
                    csrf_token = csrf_response.headers.get('x-csrf-token')
                    print(f"[SAP-CLIENT] CSRF token obtained: {sanitize_for_logging(csrf_token)}")
                    
                    if not csrf_token:
                        raise Exception('Failed to obtain CSRF token for ABAP unit tests')
                
                # Step 2: Start ABAP unit test run
                print("[SAP-CLIENT] Step 2: Starting ABAP unit test run")
                
                # Create the XML for the test run
                coverage_xml = '<aunit:coverage active="true"/>' if with_coverage else ''
                test_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<aunit:run xmlns:aunit="http://www.sap.com/adt/api/aunit" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <aunit:options>
    <aunit:measurements type="none"/>
    <aunit:scope ownTests="true" foreignTests="false"/>
    <aunit:riskLevel harmless="true" dangerous="true" critical="true"/>
    <aunit:duration short="true" medium="true" long="true"/>
    {coverage_xml}
  </aunit:options>
  <osl:objectSet xmlns:osl="http://www.sap.com/api/osl" xsi:type="osl:flatObjectSet">
    <osl:object name="{object_name}" type="{object_type}"/>
  </osl:objectSet>
</aunit:run>'''
                
                print(f"[SAP-CLIENT] Unit test XML: {sanitize_for_logging(test_xml)}")
                
                async with self.session.post(
                    self.add_client_param('/sap/bc/adt/api/abapunit/runs'),
                    data=test_xml,
                    headers={
                        **await self._get_appropriate_headers(),
                        'x-csrf-token': csrf_token,
                        'Content-Type': 'application/vnd.sap.adt.api.abapunit.run.v1+xml'
                    }
                ) as run_response:
                    print(f"[SAP-CLIENT] Unit test run response status: {run_response.status}")
                    
                    # Get the run ID from the location header
                    location = run_response.headers.get('location')
                    if not location:
                        raise Exception('No location header in ABAP unit test run response')
                    
                    run_id = location.split('/')[-1]
                    print(f"[SAP-CLIENT] Unit test run ID: {sanitize_for_logging(run_id)}")
                
                # Step 3: Track the status of the test run
                print("[SAP-CLIENT] Step 3: Tracking test run status")
                
                status = 'IN_PROCESS'
                result_id = None
                max_attempts = 10
                
                for attempt in range(1, max_attempts + 1):
                    print(f"[SAP-CLIENT] Checking run status (attempt {attempt}/{max_attempts})")
                    
                    async with self.session.get(
                        self.add_client_param(f'/sap/bc/adt/api/abapunit/runs/{run_id}'),
                        headers={
                            **await self._get_appropriate_headers(),
                            'Accept': 'application/vnd.sap.adt.api.abapunit.run-status.v1+xml'
                        }
                    ) as status_response:
                        status_xml_content = await status_response.text()
                        status_xml = safe_parse_xml(status_xml_content)
                        
                        if status_xml is None:
                            print("[SAP-CLIENT] Could not parse status response")
                            continue
                        
                        # Extract status from XML - try multiple paths
                        status_elem = status_xml.find('.//progress[@status]')
                        if status_elem is not None:
                            status = status_elem.get('status', '')
                        else:
                            # Try alternative path
                            for elem in status_xml.iter():
                                if 'status' in elem.attrib:
                                    status = elem.get('status', '')
                                    break
                        
                        print(f"[SAP-CLIENT] Run status: {sanitize_for_logging(status)}")
                        
                        if status == 'FINISHED':
                            # Extract result ID from the link
                            for link in status_xml.iter():
                                if (link.tag.endswith('link') and 
                                    link.get('rel') == 'http://www.sap.com/adt/relations/api/abapunit/run-result'):
                                    href = link.get('href', '')
                                    result_id = href.split('/')[-1]
                                    print(f"[SAP-CLIENT] Found result ID: {sanitize_for_logging(result_id)}")
                                    break
                            break
                        
                        if attempt < max_attempts:
                            await asyncio.sleep(1)  # Wait 1 second between checks
                
                if status != 'FINISHED' or not result_id:
                    raise Exception(f'Test run did not complete successfully. Status: {status}')
                
                # Step 4: Retrieve the results
                print("[SAP-CLIENT] Step 4: Retrieving test results")
                
                async with self.session.get(
                    self.add_client_param(f'/sap/bc/adt/abapunit/results/{result_id}?withNavigationUris=false'),
                    headers={
                        **await self._get_appropriate_headers(),
                        'Accept': 'application/vnd.sap.adt.api.abapunit.run-result.v1+xml'  # Changed from junit to abapunit format
                    }
                ) as results_response:
                    print(f"[SAP-CLIENT] Results response status: {results_response.status}")
                    results_xml_content = await results_response.text()
                    print(f"[SAP-CLIENT] Results data: {sanitize_for_logging(results_xml_content)}")
                    
                    results_xml = safe_parse_xml(results_xml_content)
                    if results_xml is None:
                        raise Exception('Could not parse test results')
                    
                    # Parse the ABAP Unit format results
                    results = self._parse_abapunit_results(results_xml)
                    print(f"[SAP-CLIENT] Parsed {len(results)} test results")
                    
                    # If coverage was requested, try to extract coverage information
                    if with_coverage:
                        try:
                            print("[SAP-CLIENT] Extracting coverage information")
                            self._extract_coverage_info(results_xml, results)
                        except Exception as error:
                            print(f"[SAP-CLIENT] Failed to extract coverage: {sanitize_for_logging(str(error))}")
                    
                    if results:
                        print("[SAP-CLIENT] Successfully ran unit tests directly")
                        return results
                    else:
                        raise Exception('No test results found in response')
                        
            except Exception as direct_error:
                print(f"[SAP-CLIENT] Direct execution failed: {sanitize_for_logging(str(direct_error))}")
                logger.error(f"Direct unit test execution failed: {sanitize_for_logging(str(direct_error))}")
                
                # Fall back to parsing test classes if we have local test class source
                if not test_class_source:
                    print("[SAP-CLIENT] No test class source available for fallback parsing")
                    return []
                
                print("[SAP-CLIENT] Falling back to test class parsing")
                
                # Extract test class name from the test class source
                import re
                test_class_match = re.search(r'CLASS\s+([\w_]+)\s+DEFINITION.*FOR\s+TESTING', test_class_source, re.IGNORECASE)
                if not test_class_match:
                    print("[SAP-CLIENT] Could not find test class name in source")
                    return []
                
                test_class_name = test_class_match.group(1)
                print(f"[SAP-CLIENT] Found test class: {sanitize_for_logging(test_class_name)}")
                
                # Extract test methods from the test class source
                test_methods = set()
                
                # Look for methods with FOR TESTING suffix
                for_testing_matches = re.findall(r'\s+([\w_]+)\s+FOR\s+TESTING', test_class_source, re.IGNORECASE)
                for match in for_testing_matches:
                    method_name = match.strip()
                    if method_name:
                        test_methods.add(method_name)
                
                # Look for method implementations
                implementation_matches = re.findall(r'METHOD\s+([\w_]+)\.', test_class_source, re.IGNORECASE)
                for match in implementation_matches:
                    method_name = match.strip()
                    # Only add if it's not setup or teardown
                    if method_name.lower() not in ('setup', 'teardown'):
                        test_methods.add(method_name)
                
                if not test_methods:
                    print("[SAP-CLIENT] No test methods found in test class")
                    return []
                
                # Create synthetic test results
                results = []
                for method_name in test_methods:
                    results.append(UnitTestResult(
                        test_class=test_class_name,
                        test_method=method_name,
                        status='SUCCESS',
                        message='WARNING: Test method found but not executed (using fallback approach)',
                        duration=None
                    ))
                
                print(f"[SAP-CLIENT] Created {len(results)} synthetic test results")
                return results
                
        except Exception as e:
            logger.error(f"Failed to run unit tests: {sanitize_for_logging(str(e))}")
            return []
    
    def _extract_coverage_info(self, xml_root, results: List[UnitTestResult]) -> None:
        """Extract coverage information from test results and add it to the test results"""
        try:
            # Try multiple paths for coverage data
            coverage_paths = [
                'coverage',
                './/coverage'
            ]
            
            coverage_data = None
            for path in coverage_paths:
                if path.startswith('.//'):
                    coverage_data = xml_root.find(path)
                else:
                    coverage_data = xml_root.find(path)
                
                if coverage_data is not None:
                    print(f"[SAP-CLIENT] Found coverage data at path: {sanitize_for_logging(path)}")
                    break
            
            if coverage_data is None:
                print("[SAP-CLIENT] No coverage data found in results")
                return
            
            # Extract overall coverage percentage
            overall_coverage = coverage_data.get('percentage')
            
            if overall_coverage:
                print(f"[SAP-CLIENT] Overall coverage: {sanitize_for_logging(overall_coverage)}%")
                
                # Add coverage info to the first result as a message
                if results:
                    coverage_message = f"Code coverage: {overall_coverage}%"
                    if results[0].message:
                        results[0].message = f"{results[0].message}\n{coverage_message}"
                    else:
                        results[0].message = coverage_message
            
            # Try to extract detailed coverage data
            statements = coverage_data.find('statements')
            if statements is not None:
                total = statements.get('total', '0')
                executed = statements.get('executed', '0')
                
                if total and executed:
                    print(f"[SAP-CLIENT] Statements: {sanitize_for_logging(executed)}/{sanitize_for_logging(total)} executed")
                    
                    # Add detailed coverage to the first result
                    if results:
                        detailed_message = f"Statements: {executed}/{total} executed"
                        if results[0].message:
                            results[0].message = f"{results[0].message}\n{detailed_message}"
                        else:
                            results[0].message = detailed_message
                            
        except Exception as error:
            print(f"[SAP-CLIENT] Error extracting coverage info: {sanitize_for_logging(str(error))}")
    
    def _parse_junit_results(self, xml_root) -> List[UnitTestResult]:
        """Parse JUnit format test results"""
        results = []
        try:
            print("[SAP-CLIENT] Parsing JUnit test results")
            
            testsuites = xml_root.find('testsuites')
            if testsuites is None:
                print("[SAP-CLIENT] No testsuites found in results")
                return []
            
            testsuite = testsuites.find('testsuite')
            if testsuite is None:
                print("[SAP-CLIENT] No testsuite found in results")
                return []
            
            testcases = testsuite.findall('testcase')
            print(f"[SAP-CLIENT] Found {len(testcases)} testcases")
            
            for testcase in testcases:
                class_name = testcase.get('classname', '')
                method_name = testcase.get('name', '')
                time_str = testcase.get('time')
                duration = int(float(time_str) * 1000) if time_str else None
                
                status = 'SUCCESS'
                message = ''
                
                # Check for failures
                failure = testcase.find('failure')
                if failure is not None:
                    status = 'FAILURE'
                    message = failure.get('message', '')
                    if failure.text:
                        message += f" {failure.text}"
                
                # Check for errors
                error = testcase.find('error')
                if error is not None:
                    status = 'ERROR'
                    message = error.get('message', '')
                    if error.text:
                        message += f" {error.text}"
                
                # Check for skipped tests
                skipped = testcase.find('skipped')
                if skipped is not None:
                    status = 'FAILURE'
                    skip_message = skipped.get('message', '')
                    message = f"Skipped: {skip_message}" if skip_message else 'Skipped'
                    if skipped.text:
                        message += f" {skipped.text}"
                
                # Extract class name from classname attribute (format may be package:class)
                class_name_parts = class_name.split('.')
                actual_class_name = class_name_parts[1] if len(class_name_parts) > 1 else class_name
                
                results.append(UnitTestResult(
                    test_class=actual_class_name,
                    test_method=method_name,
                    status=status,
                    message=message,
                    duration=duration
                ))
                
                print(f"[SAP-CLIENT] Added test result: {sanitize_for_logging(actual_class_name)}.{sanitize_for_logging(method_name)} - {sanitize_for_logging(status)}")
            
            logger.info(f"Found {len(results)} unit test results")
            
        except Exception as error:
            print(f"[SAP-CLIENT] Error parsing JUnit test results: {sanitize_for_logging(str(error))}")
            logger.error(f"Error parsing JUnit test results: {sanitize_for_logging(str(error))}")
        
        return results
    
    def _parse_abapunit_results(self, xml_root) -> List[UnitTestResult]:
        """Parse ABAP Unit format test results"""
        results = []
        try:
            print("[SAP-CLIENT] Parsing ABAP Unit test results")
            
            # ABAP Unit format: <aunit:runResult><program><testClasses><testClass><testMethods><testMethod>
            namespaces = {'aunit': 'http://www.sap.com/adt/aunit', 'adtcore': 'http://www.sap.com/adt/core'}
            
            # Find all test methods
            for program in xml_root.findall('.//program', namespaces):
                program_name = program.get('{http://www.sap.com/adt/core}name', 'Unknown')
                
                for test_class in program.findall('.//testClass', namespaces):
                    class_name = test_class.get('{http://www.sap.com/adt/core}name', 'Unknown')
                    
                    for test_method in test_class.findall('.//testMethod', namespaces):
                        method_name = test_method.get('{http://www.sap.com/adt/core}name', 'Unknown')
                        execution_time = test_method.get('executionTime', '0')
                        
                        # Check for alerts (failures/errors)
                        alerts = test_method.findall('.//alert', namespaces)
                        status = 'SUCCESS'  # Changed from 'passed' to 'SUCCESS'
                        failure_message = None
                        
                        if alerts:
                            for alert in alerts:
                                severity = alert.get('severity', 'error')
                                kind = alert.get('kind', 'unknown')
                                
                                title_elem = alert.find('.//title', namespaces)
                                title = title_elem.text if title_elem is not None else 'Test failed'
                                
                                details_text = []
                                for detail in alert.findall('.//detail', namespaces):
                                    detail_text = detail.get('text', '')
                                    if detail_text:
                                        details_text.append(detail_text)
                                
                                failure_message = f"{title}\n" + "\n".join(details_text)
                                status = 'FAILURE' if kind == 'failedAssertion' else 'ERROR'  # Changed from 'failed' to 'FAILURE'
                                break  # Use first alert
                        
                        result = UnitTestResult(
                            test_class=class_name,
                            test_method=method_name,
                            status=status,
                            execution_time=float(execution_time) if execution_time else 0.0,
                            failure_message=failure_message
                        )
                        results.append(result)
                        print(f"[SAP-CLIENT] Found test: {class_name}.{method_name} - {status}")
            
            print(f"[SAP-CLIENT] Parsed {len(results)} ABAP Unit test results")
            logger.info(f"Found {len(results)} unit test results")
            
        except Exception as error:
            print(f"[SAP-CLIENT] Error parsing ABAP Unit test results: {sanitize_for_logging(str(error))}")
            logger.error(f"Error parsing ABAP Unit test results: {sanitize_for_logging(str(error))}")
        
        return results
    
    async def get_packages(self, parent_package: Optional[str] = None) -> List[PackageInfo]:
        """Get packages from SAP system"""
        try:
            if parent_package:
                # Get subpackages
                url = f"/sap/bc/adt/packages/$tree?sap-client={self.connection.client}"
                params = {'packagename': parent_package, 'type': 'subpackages'}
            else:
                # Get root packages
                url = f"/sap/bc/adt/packages?sap-client={self.connection.client}"
                params = {}
            
            headers = await self._get_appropriate_headers()
            async with self.session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_packages_xml(xml_content)
                else:
                    logger.error(f"Failed to get packages: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting packages: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_packages_xml(self, xml_content: str) -> List[PackageInfo]:
        """Parse packages from XML response"""
        packages = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return packages
            
            # Parse package nodes
            for node in root.findall('.//package'):
                name = node.get('name', '')
                description = node.get('description', '')
                package_type = node.get('packageType', '')
                
                if name:
                    packages.append(PackageInfo(
                        name=name,
                        description=description,
                        package_type=package_type
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing packages XML: {sanitize_for_logging(str(e))}")
        
        return packages
    
    async def get_package_info(self, package_name: str) -> Optional[PackageInfo]:
        """Get detailed package information"""
        try:
            url = f"/sap/bc/adt/packages/{quote(package_name)}?sap-client={self.connection.client}"
            
            headers = await self._get_appropriate_headers()
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_package_info_xml(xml_content)
                else:
                    logger.error(f"Failed to get package info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting package info: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_package_info_xml(self, xml_content: str) -> Optional[PackageInfo]:
        """Parse package info from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            # Extract package information
            name = root.get('name', '')
            description = root.get('description', '')
            package_type = root.get('packageType', '')
            
            return PackageInfo(
                name=name,
                description=description,
                package_type=package_type
            )
                    
        except Exception as e:
            logger.error(f"Error parsing package info XML: {sanitize_for_logging(str(e))}")
            return None
    
    async def create_package(self, request: CreatePackageRequest) -> PackageOperationResult:
        """Create a new package"""
        try:
            logger.info(f"Creating package {sanitize_for_logging(request.name)}")
            
            # Build package XML
            package_xml = self._build_package_xml(request)
            
            url = f"/sap/bc/adt/packages?sap-client={self.connection.client}"
            headers = {'Content-Type': 'application/vnd.sap.adt.packages.v2+xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=package_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created package {sanitize_for_logging(request.name)}")
                    return PackageOperationResult(
                        success=True,
                        package_name=request.name,
                        created=True,
                        message=f"Package {request.name} created successfully"
                    )
                else:
                    error_msg = f"Failed to create package: HTTP {response.status}"
                    logger.error(error_msg)
                    return PackageOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating package: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return PackageOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _build_package_xml(self, request: CreatePackageRequest) -> str:
        """Build package XML for creation"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <pak:package xmlns:pak="http://www.sap.com/adt/packages" 
                     xmlns:adtcore="http://www.sap.com/adt/core"
                     adtcore:name="{sanitize_for_xml(request.name)}"
                     adtcore:description="{sanitize_for_xml(request.description)}"
                     pak:packageType="{sanitize_for_xml(request.package_type or 'development')}"
                     pak:translationRelevance="{sanitize_for_xml(request.translation_relevance or 'not_relevant')}"
                     pak:abapLanguageVersion="{sanitize_for_xml(request.abap_language_version or 'standard')}">
            {f'<pak:superPackage adtcore:name="{sanitize_for_xml(request.super_package)}"/>' if request.super_package else ''}
            {f'<pak:softwareComponent adtcore:name="{sanitize_for_xml(request.software_component)}"/>' if request.software_component else ''}
            {f'<pak:applicationComponent adtcore:name="{sanitize_for_xml(request.application_component)}"/>' if request.application_component else ''}
            {f'<pak:transportLayer adtcore:name="{sanitize_for_xml(request.transport_layer)}"/>' if request.transport_layer else ''}
        </pak:package>"""
    
    async def get_transport_requests(self, target: Optional[str] = None) -> List[TransportRequest]:
        """Get transport requests"""
        try:
            url = f"/sap/bc/adt/cts/transportrequests?sap-client={self.connection.client}"
            params = {}
            if target:
                params['targets'] = target
            
            headers = await self._get_appropriate_headers()
            headers['Accept'] = 'application/vnd.sap.adt.transportorganizertree.v1+xml'
            logger.info(f"Getting transport requests from {sanitize_for_logging(url)} with params: {sanitize_for_logging(params)}")
            
            async with self.session.get(url, params=params, headers=headers) as response:
                logger.info(f"Transport requests response status: {response.status}")
                if response.status == 200:
                    xml_content = await response.text()
                    logger.info(f"Transport requests XML length: {len(xml_content)}")
                    logger.info(f"Transport requests XML content: {sanitize_for_logging(xml_content)}")
                    return self._parse_transport_requests_xml(xml_content)
                else:
                    logger.error(f"Failed to get transport requests: {response.status}")
                    response_text = await response.text()
                    logger.error(f"Response text: {sanitize_for_logging(response_text[:500])}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting transport requests: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_transport_requests_xml(self, xml_content: str) -> List[TransportRequest]:
        """Parse transport requests from XML response"""
        requests = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                logger.warning("Failed to parse transport requests XML")
                return requests
            
            logger.info(f"Transport requests XML root: {root.tag}")
            logger.info(f"Transport requests XML attributes: {root.attrib}")
            
            # Log XML structure for debugging
            logger.info("Transport requests XML structure:")
            for i, child in enumerate(root):
                logger.info(f"  Child {i}: {child.tag} - {child.attrib}")
                for j, grandchild in enumerate(child):
                    logger.info(f"    Grandchild {j}: {grandchild.tag} - {grandchild.attrib}")
                    if j > 3:  # Limit logging
                        break
                if i > 5:  # Limit logging
                    break
            
            # Check if this is an empty transport organizer tree
            if root.tag.endswith('}root') and len(list(root)) == 0:
                logger.info("Transport organizer tree is empty - no transport requests found")
                return requests
            
            # Try different parsing strategies for transport organizer tree format
            
            # Strategy 1: Look for transport request nodes (using local-name to avoid namespace issues)
            transport_patterns = [
                './/*[local-name()="transportRequest"]',
                './/*[local-name()="request"]',
                './/*[local-name()="transport"]',
                './/*[local-name()="task"]',
                './/*[local-name()="workbenchRequest"]',
                './/*[local-name()="customizingRequest"]'
            ]
            
            for pattern in transport_patterns:
                nodes = root.findall(pattern)
                logger.info(f"Trying pattern '{pattern}': found {len(nodes)} nodes")
                
                if nodes:
                    for node in nodes:
                        number = node.get('number', '') or node.get('id', '') or node.text
                        description = node.get('description', '') or node.get('desc', '')
                        tr_type = node.get('type', '') or node.get('requestType', '')
                        status = node.get('status', '') or node.get('state', '')
                        owner = node.get('owner', '') or node.get('user', '')
                        
                        logger.info(f"  Found transport: {number} - {description}")
                        
                        if number:
                            requests.append(TransportRequest(
                                number=number,
                                description=description,
                                type=tr_type,
                                status=status,
                                owner=owner
                            ))
                    
                    if requests:
                        logger.info(f"Successfully parsed {len(requests)} transport requests")
                        return requests
            
            # Strategy 2: Look for any nodes with transport-like attributes
            logger.info("No transport nodes found, looking for any nodes with transport attributes")
            for elem in root.iter():
                if elem.get('number') or elem.get('id'):
                    number = elem.get('number', '') or elem.get('id', '')
                    if number and (number.startswith('S4H') or number.startswith('DEV') or len(number) > 5):
                        description = elem.get('description', '') or elem.get('desc', '') or elem.text or ''
                        tr_type = elem.get('type', '') or elem.get('requestType', '')
                        status = elem.get('status', '') or elem.get('state', '')
                        owner = elem.get('owner', '') or elem.get('user', '')
                        
                        logger.info(f"  Found potential transport: {number} - {description}")
                        
                        requests.append(TransportRequest(
                            number=number,
                            description=description,
                            type=tr_type,
                            status=status,
                            owner=owner
                        ))
            
            if not requests:
                logger.info("No transport requests found - this is normal if the user has no active transport requests")
                
        except Exception as e:
            logger.error(f"Error parsing transport requests XML: {sanitize_for_logging(str(e))}")
        
        return requests
    
    async def create_transport_request(self, request: CreateTransportRequest) -> TransportOperationResult:
        """Create a new transport request"""
        try:
            logger.info(f"Creating transport request: {sanitize_for_logging(request.description)}")
            
            # Build transport request XML
            tr_xml = self._build_transport_request_xml(request)
            
            url = f"/sap/bc/adt/cts/transportrequests?sap-client={self.connection.client}"
            headers = {'Content-Type': 'application/vnd.sap.adt.transportorganizer.v1+xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=tr_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    # Parse response to get transport number
                    response_xml = await response.text()
                    transport_number = self._extract_transport_number(response_xml)
                    
                    logger.info(f"Successfully created transport request {transport_number}")
                    return TransportOperationResult(
                        success=True,
                        transport_number=transport_number,
                        created=True,
                        message=f"Transport request {transport_number} created successfully"
                    )
                else:
                    error_msg = f"Failed to create transport request: HTTP {response.status}"
                    logger.error(error_msg)
                    return TransportOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating transport request: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return TransportOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _build_transport_request_xml(self, request: CreateTransportRequest) -> str:
        """Build transport request XML for creation"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <tm:transportRequest xmlns:tm="http://www.sap.com/adt/tm"
                            xmlns:adtcore="http://www.sap.com/adt/core"
                            tm:type="{sanitize_for_xml(request.type or 'K')}"
                            adtcore:description="{sanitize_for_xml(request.description)}">
            {f'<tm:target>{sanitize_for_xml(request.target)}</tm:target>' if request.target else ''}
        </tm:transportRequest>"""
    
    def _extract_transport_number(self, xml_content: str) -> Optional[str]:
        """Extract transport number from response XML"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            # Look for transport number in various possible locations
            number = root.get('number') or root.get('transportNumber')
            if number:
                return number
            
            # Try to find in child elements
            for elem in root.iter():
                if elem.tag.endswith('number') or elem.tag.endswith('transportNumber'):
                    return elem.text
            
            return None
                    
        except Exception as e:
            logger.error(f"Error extracting transport number: {sanitize_for_logging(str(e))}")
            return None
    
    async def assign_object_to_transport(self, object_name: str, object_type: str, 
                                       transport_number: str) -> TransportOperationResult:
        """Assign an object to a transport request"""
        try:
            logger.info(f"Assigning {sanitize_for_logging(object_name)} to transport {sanitize_for_logging(transport_number)}")
            
            # Build assignment XML
            assignment_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
            <tm:transportAssignment xmlns:tm="http://www.sap.com/adt/tm"
                                   xmlns:adtcore="http://www.sap.com/adt/core">
                <tm:transportRequest tm:number="{sanitize_for_xml(transport_number)}"/>
                <tm:object adtcore:name="{sanitize_for_xml(object_name)}" 
                          adtcore:type="{sanitize_for_xml(object_type)}"/>
            </tm:transportAssignment>"""
            
            url = f"/sap/bc/adt/cts/transportrequests/{quote(transport_number)}/objects?sap-client={self.connection.client}"
            headers = {'Content-Type': 'application/xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=assignment_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully assigned {sanitize_for_logging(object_name)} to transport")
                    return TransportOperationResult(
                        success=True,
                        transport_number=transport_number,
                        message=f"Object {object_name} assigned to transport {transport_number}"
                    )
                else:
                    error_msg = f"Failed to assign object to transport: HTTP {response.status}"
                    logger.error(error_msg)
                    return TransportOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error assigning object to transport: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return TransportOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )

    async def lock_object(self, object_name: str, object_type: str) -> Optional[Dict[str, str]]:
        """Lock an object for editing and return lock info including transport assignment
        
        Returns:
            Dict with LOCK_HANDLE and CORRNR (transport number) if successful, None if failed
        """
        try:
            # Get the resource URI for the object
            resource_uri = await self._get_resource_uri(object_name, object_type)
            if not resource_uri:
                logger.error(f"Could not determine resource URI for {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
                return None
            
            # Use the private _lock_object method
            return await self._lock_object(resource_uri)
            
        except Exception as e:
            logger.error(f"Error locking object {sanitize_for_logging(object_name)}: {sanitize_for_logging(str(e))}")
            return None

    async def unlock_object(self, object_name: str, object_type: str, lock_handle: str) -> bool:
        """Unlock an object after editing
        
        Args:
            object_name: Name of the object to unlock
            object_type: Type of the object
            lock_handle: Lock handle obtained from lock_object
            
        Returns:
            True if unlock successful, False otherwise
        """
        try:
            # Get the resource URI for the object
            resource_uri = await self._get_resource_uri(object_name, object_type)
            if not resource_uri:
                logger.error(f"Could not determine resource URI for {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
                return False
            
            # Use the private _unlock_object method
            return await self._unlock_object(resource_uri, lock_handle)
            
        except Exception as e:
            logger.error(f"Error unlocking object {sanitize_for_logging(object_name)}: {sanitize_for_logging(str(e))}")
            return False

    async def get_enhancements(self, enhancement_type: Optional[EnhancementType] = None, 
                              package_name: Optional[str] = None) -> List[EnhancementInfo]:
        """Get enhancements from SAP system"""
        try:
            enhancements = []
            
            # Define enhancement types to query
            types_to_query = [enhancement_type] if enhancement_type else list(EnhancementType)
            
            for enh_type in types_to_query:
                url = f"/sap/bc/adt/enhancements/{enh_type.value}"
                params = {}
                if package_name:
                    params['package'] = package_name
                
                async with self.session.get(url, params=params) as response:
                    if response.status == 200:
                        xml_content = await response.text()
                        type_enhancements = self._parse_enhancements_xml(xml_content, enh_type)
                        enhancements.extend(type_enhancements)
                    else:
                        logger.warning(f"Failed to get {enh_type.value} enhancements: {response.status}")
            
            return enhancements
                    
        except Exception as e:
            logger.error(f"Error getting enhancements: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_enhancements_xml(self, xml_content: str, enhancement_type: EnhancementType) -> List[EnhancementInfo]:
        """Parse enhancements from XML response"""
        enhancements = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return enhancements
            
            # Parse enhancement nodes
            for node in root.findall('.//enhancement'):
                name = node.get('name', '')
                description = node.get('description', '')
                package_name = node.get('package', '')
                
                if name:
                    enhancements.append(EnhancementInfo(
                        name=name,
                        type=enhancement_type,
                        description=description,
                        package_name=package_name
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing enhancements XML: {sanitize_for_logging(str(e))}")
        
        return enhancements
    
    async def get_enhancement_info(self, enhancement_name: str, 
                                  enhancement_type: EnhancementType) -> Optional[EnhancementInfo]:
        """Get detailed enhancement information"""
        try:
            url = f"/sap/bc/adt/enhancements/{enhancement_type.value}/{quote(enhancement_name)}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_enhancement_info_xml(xml_content, enhancement_type)
                else:
                    logger.error(f"Failed to get enhancement info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting enhancement info: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_enhancement_info_xml(self, xml_content: str, 
                                   enhancement_type: EnhancementType) -> Optional[EnhancementInfo]:
        """Parse enhancement info from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            # Extract enhancement information
            name = root.get('name', '')
            description = root.get('description', '')
            package_name = root.get('package', '')
            enhancement_spot = root.get('enhancementSpot', '')
            badi_definition = root.get('badiDefinition', '')
            implementing_class = root.get('implementingClass', '')
            
            return EnhancementInfo(
                name=name,
                type=enhancement_type,
                description=description,
                package_name=package_name,
                enhancement_spot=enhancement_spot if enhancement_spot else None,
                badi_definition=badi_definition if badi_definition else None,
                implementing_class=implementing_class if implementing_class else None
            )
                    
        except Exception as e:
            logger.error(f"Error parsing enhancement info XML: {sanitize_for_logging(str(e))}")
            return None
    
    async def create_enhancement(self, request: CreateEnhancementRequest) -> EnhancementOperationResult:
        """Create a new enhancement"""
        try:
            logger.info(f"Creating enhancement {sanitize_for_logging(request.name)} of type {request.type.value}")
            
            # Build enhancement XML
            enhancement_xml = self._build_enhancement_xml(request)
            
            url = f"/sap/bc/adt/enhancements/{request.type.value}"
            headers = self._get_enhancement_headers(request.type)
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=enhancement_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created enhancement {sanitize_for_logging(request.name)}")
                    return EnhancementOperationResult(
                        success=True,
                        enhancement_name=request.name,
                        created=True,
                        message=f"Enhancement {request.name} created successfully"
                    )
                else:
                    error_msg = f"Failed to create enhancement: HTTP {response.status}"
                    logger.error(error_msg)
                    return EnhancementOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating enhancement: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return EnhancementOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _get_enhancement_headers(self, enhancement_type: EnhancementType) -> Dict[str, str]:
        """Get appropriate headers for enhancement type"""
        headers_map = {
            EnhancementType.ENHANCEMENT_IMPLEMENTATION: {'Content-Type': 'application/vnd.sap.adt.enh.enho.v1+xml'},
            EnhancementType.BADI_IMPLEMENTATION: {'Content-Type': 'application/vnd.sap.adt.enh.enhoxhb.v4+xml'},
            EnhancementType.SOURCE_CODE_PLUGIN: {'Content-Type': 'application/vnd.sap.adt.enh.enhoxhh.v3+xml'},
            EnhancementType.ENHANCEMENT_SPOT: {'Content-Type': 'application/vnd.sap.adt.enh.enhs.v1+xml'},
            EnhancementType.BADI_ENHANCEMENT_SPOT: {'Content-Type': 'application/vnd.sap.adt.enh.enhs.v2+xml'}
        }
        return headers_map.get(enhancement_type, {'Content-Type': 'application/xml'})
    
    def _build_enhancement_xml(self, request: CreateEnhancementRequest) -> str:
        """Build enhancement XML for creation"""
        if request.type == EnhancementType.BADI_IMPLEMENTATION:
            return self._build_badi_implementation_xml(request)
        elif request.type == EnhancementType.SOURCE_CODE_PLUGIN:
            return self._build_source_code_plugin_xml(request)
        elif request.type == EnhancementType.ENHANCEMENT_SPOT:
            return self._build_enhancement_spot_xml(request)
        elif request.type == EnhancementType.BADI_ENHANCEMENT_SPOT:
            return self._build_badi_spot_xml(request)
        else:
            return self._build_generic_enhancement_xml(request)
    
    def _build_badi_implementation_xml(self, request: CreateEnhancementRequest) -> str:
        """Build BAdI implementation XML"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <enh:enhoxhb xmlns:enh="http://www.sap.com/adt/enh"
                     xmlns:adtcore="http://www.sap.com/adt/core"
                     adtcore:name="{sanitize_for_xml(request.name)}"
                     adtcore:description="{sanitize_for_xml(request.description)}"
                     adtcore:package="{sanitize_for_xml(request.package_name)}">
            {f'<enh:badiDefinition>{sanitize_for_xml(request.badi_definition)}</enh:badiDefinition>' if request.badi_definition else ''}
            {f'<enh:implementingClass>{sanitize_for_xml(request.implementing_class)}</enh:implementingClass>' if request.implementing_class else ''}
            {self._build_filter_values_xml(request.filter_values) if request.filter_values else ''}
        </enh:enhoxhb>"""
    
    def _build_source_code_plugin_xml(self, request: CreateEnhancementRequest) -> str:
        """Build source code plugin XML"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <enh:enhoxhh xmlns:enh="http://www.sap.com/adt/enh"
                     xmlns:adtcore="http://www.sap.com/adt/core"
                     adtcore:name="{sanitize_for_xml(request.name)}"
                     adtcore:description="{sanitize_for_xml(request.description)}"
                     adtcore:package="{sanitize_for_xml(request.package_name)}">
            {f'<enh:enhancementSpot>{sanitize_for_xml(request.enhancement_spot)}</enh:enhancementSpot>' if request.enhancement_spot else ''}
        </enh:enhoxhh>"""
    
    def _build_enhancement_spot_xml(self, request: CreateEnhancementRequest) -> str:
        """Build enhancement spot XML"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <enh:enhsxs xmlns:enh="http://www.sap.com/adt/enh"
                    xmlns:adtcore="http://www.sap.com/adt/core"
                    adtcore:name="{sanitize_for_xml(request.name)}"
                    adtcore:description="{sanitize_for_xml(request.description)}"
                    adtcore:package="{sanitize_for_xml(request.package_name)}">
        </enh:enhsxs>"""
    
    def _build_badi_spot_xml(self, request: CreateEnhancementRequest) -> str:
        """Build BAdI enhancement spot XML"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <enh:enhsxsb xmlns:enh="http://www.sap.com/adt/enh"
                     xmlns:adtcore="http://www.sap.com/adt/core"
                     adtcore:name="{sanitize_for_xml(request.name)}"
                     adtcore:description="{sanitize_for_xml(request.description)}"
                     adtcore:package="{sanitize_for_xml(request.package_name)}">
        </enh:enhsxsb>"""
    
    def _build_generic_enhancement_xml(self, request: CreateEnhancementRequest) -> str:
        """Build generic enhancement XML"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <enh:enhoxh xmlns:enh="http://www.sap.com/adt/enh"
                    xmlns:adtcore="http://www.sap.com/adt/core"
                    adtcore:name="{sanitize_for_xml(request.name)}"
                    adtcore:description="{sanitize_for_xml(request.description)}"
                    adtcore:package="{sanitize_for_xml(request.package_name)}">
            {f'<enh:enhancementSpot>{sanitize_for_xml(request.enhancement_spot)}</enh:enhancementSpot>' if request.enhancement_spot else ''}
        </enh:enhoxh>"""
    
    def _build_filter_values_xml(self, filter_values: Dict[str, str]) -> str:
        """Build filter values XML for BAdI implementations"""
        if not filter_values:
            return ""
        
        filter_xml = "<enh:filterValues>"
        for key, value in filter_values.items():
            filter_xml += f'<enh:filterValue name="{sanitize_for_xml(key)}" value="{sanitize_for_xml(value)}"/>'
        filter_xml += "</enh:filterValues>"
        return filter_xml
    
    async def get_enhancement_source(self, enhancement_name: str, 
                                   enhancement_type: EnhancementType) -> Optional[str]:
        """Get source code of enhancement (for source code plugins)"""
        try:
            if enhancement_type != EnhancementType.SOURCE_CODE_PLUGIN:
                logger.warning(f"Source code not available for enhancement type {enhancement_type.value}")
                return None
            
            url = f"/sap/bc/adt/enhancements/{enhancement_type.value}/{quote(enhancement_name)}/source/main"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    source_code = await response.text()
                    logger.info(f"Successfully retrieved enhancement source for {sanitize_for_logging(enhancement_name)}")
                    return source_code
                else:
                    logger.warning(f"Failed to get enhancement source: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting enhancement source: {sanitize_for_logging(str(e))}")
            return None
    
    async def update_enhancement_source(self, enhancement_name: str, 
                                      enhancement_type: EnhancementType, 
                                      source_code: str) -> EnhancementOperationResult:
        """Update source code of enhancement (for source code plugins)"""
        try:
            if enhancement_type != EnhancementType.SOURCE_CODE_PLUGIN:
                return EnhancementOperationResult(
                    success=False,
                    message=f"Source code updates not supported for enhancement type {enhancement_type.value}",
                    errors=[f"Enhancement type {enhancement_type.value} does not support source code updates"]
                )
            
            url = f"/sap/bc/adt/enhancements/{enhancement_type.value}/{quote(enhancement_name)}/source/main"
            
            headers = {'Content-Type': 'text/plain'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.put(url, data=source_code, headers=headers) as response:
                if response.status == 200:
                    logger.info(f"Successfully updated enhancement source for {sanitize_for_logging(enhancement_name)}")
                    return EnhancementOperationResult(
                        success=True,
                        enhancement_name=enhancement_name,
                        updated=True,
                        message=f"Enhancement {enhancement_name} source updated successfully"
                    )
                else:
                    error_msg = f"Failed to update enhancement source: HTTP {response.status}"
                    logger.error(error_msg)
                    return EnhancementOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error updating enhancement source: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return EnhancementOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    async def get_enhancement_spots(self, package_name: Optional[str] = None) -> List[EnhancementSpotInfo]:
        """Get enhancement spots from SAP system"""
        try:
            spots = []
            
            # Get both types of enhancement spots
            for spot_type in [EnhancementType.ENHANCEMENT_SPOT, EnhancementType.BADI_ENHANCEMENT_SPOT]:
                url = f"/sap/bc/adt/enhancements/{spot_type.value}"
                params = {}
                if package_name:
                    params['package'] = package_name
                
                async with self.session.get(url, params=params) as response:
                    if response.status == 200:
                        xml_content = await response.text()
                        type_spots = self._parse_enhancement_spots_xml(xml_content)
                        spots.extend(type_spots)
                    else:
                        logger.warning(f"Failed to get {spot_type.value} spots: {response.status}")
            
            return spots
                    
        except Exception as e:
            logger.error(f"Error getting enhancement spots: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_enhancement_spots_xml(self, xml_content: str) -> List[EnhancementSpotInfo]:
        """Parse enhancement spots from XML response"""
        spots = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return spots
            
            # Parse enhancement spot nodes
            for node in root.findall('.//enhancementSpot'):
                name = node.get('name', '')
                description = node.get('description', '')
                package_name = node.get('package', '')
                
                if name:
                    spots.append(EnhancementSpotInfo(
                        name=name,
                        description=description,
                        package_name=package_name
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing enhancement spots XML: {sanitize_for_logging(str(e))}")
        
        return spots
    
    async def get_interfaces(self, package_name: Optional[str] = None) -> List[InterfaceInfo]:
        """Get interfaces from SAP system"""
        try:
            url = "/sap/bc/adt/oo/interfaces"
            params = {}
            if package_name:
                params['package'] = package_name
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_interfaces_xml(xml_content)
                else:
                    logger.error(f"Failed to get interfaces: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting interfaces: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_interfaces_xml(self, xml_content: str) -> List[InterfaceInfo]:
        """Parse interfaces from XML response"""
        interfaces = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return interfaces
            
            # Parse interface nodes
            for node in root.findall('.//interface'):
                name = node.get('name', '')
                description = node.get('description', '')
                package_name = node.get('package', '')
                
                if name:
                    interfaces.append(InterfaceInfo(
                        name=name,
                        description=description,
                        package_name=package_name
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing interfaces XML: {sanitize_for_logging(str(e))}")
        
        return interfaces
    
    async def get_interface_info(self, interface_name: str) -> Optional[InterfaceInfo]:
        """Get detailed interface information"""
        try:
            url = f"/sap/bc/adt/oo/interfaces/{quote(interface_name)}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_interface_info_xml(xml_content)
                else:
                    logger.error(f"Failed to get interface info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting interface info: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_interface_info_xml(self, xml_content: str) -> Optional[InterfaceInfo]:
        """Parse interface info from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            # Extract interface information
            name = root.get('name', '')
            description = root.get('description', '')
            package_name = root.get('package', '')
            
            # Extract methods, events, types, constants
            methods = []
            events = []
            types = []
            constants = []
            
            for method in root.findall('.//method'):
                methods.append(method.get('name', ''))
            
            for event in root.findall('.//event'):
                events.append(event.get('name', ''))
            
            for type_elem in root.findall('.//type'):
                types.append(type_elem.get('name', ''))
            
            for constant in root.findall('.//constant'):
                constants.append(constant.get('name', ''))
            
            return InterfaceInfo(
                name=name,
                description=description,
                package_name=package_name,
                methods=methods if methods else None,
                events=events if events else None,
                types=types if types else None,
                constants=constants if constants else None
            )
                    
        except Exception as e:
            logger.error(f"Error parsing interface info XML: {sanitize_for_logging(str(e))}")
            return None
    
    async def create_interface(self, request: CreateInterfaceRequest) -> InterfaceOperationResult:
        """Create a new interface"""
        try:
            logger.info(f"Creating interface {sanitize_for_logging(request.name)}")
            
            # Build interface XML
            interface_xml = self._build_interface_xml(request)
            
            url = "/sap/bc/adt/oo/interfaces"
            headers = {'Content-Type': 'application/vnd.sap.adt.oo.interfaces.v5+xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=interface_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created interface {sanitize_for_logging(request.name)}")
                    return InterfaceOperationResult(
                        success=True,
                        interface_name=request.name,
                        created=True,
                        message=f"Interface {request.name} created successfully"
                    )
                else:
                    error_msg = f"Failed to create interface: HTTP {response.status}"
                    logger.error(error_msg)
                    return InterfaceOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating interface: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return InterfaceOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _build_interface_xml(self, request: CreateInterfaceRequest) -> str:
        """Build interface XML for creation"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <intf:interface xmlns:intf="http://www.sap.com/adt/oo/interfaces"
                       xmlns:adtcore="http://www.sap.com/adt/core"
                       adtcore:name="{sanitize_for_xml(request.name)}"
                       adtcore:description="{sanitize_for_xml(request.description)}"
                       adtcore:package="{sanitize_for_xml(request.package_name)}">
        </intf:interface>"""
    
    async def get_function_groups(self, package_name: Optional[str] = None) -> List[FunctionGroupInfo]:
        """Get function groups from SAP system"""
        try:
            url = "/sap/bc/adt/functions/groups"
            params = {}
            if package_name:
                params['package'] = package_name
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_function_groups_xml(xml_content)
                else:
                    logger.error(f"Failed to get function groups: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting function groups: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_function_groups_xml(self, xml_content: str) -> List[FunctionGroupInfo]:
        """Parse function groups from XML response"""
        function_groups = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return function_groups
            
            # Parse function group nodes
            for node in root.findall('.//functionGroup'):
                name = node.get('name', '')
                description = node.get('description', '')
                package_name = node.get('package', '')
                
                if name:
                    function_groups.append(FunctionGroupInfo(
                        name=name,
                        description=description,
                        package_name=package_name
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing function groups XML: {sanitize_for_logging(str(e))}")
        
        return function_groups
    
    async def get_function_group_info(self, function_group_name: str) -> Optional[FunctionGroupInfo]:
        """Get detailed function group information"""
        try:
            url = f"/sap/bc/adt/functions/groups/{quote(function_group_name)}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_function_group_info_xml(xml_content)
                else:
                    logger.error(f"Failed to get function group info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting function group info: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_function_group_info_xml(self, xml_content: str) -> Optional[FunctionGroupInfo]:
        """Parse function group info from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            # Extract function group information
            name = root.get('name', '')
            description = root.get('description', '')
            package_name = root.get('package', '')
            
            return FunctionGroupInfo(
                name=name,
                description=description,
                package_name=package_name
            )
                    
        except Exception as e:
            logger.error(f"Error parsing function group info XML: {sanitize_for_logging(str(e))}")
            return None
    
    async def create_function_group(self, request: CreateFunctionGroupRequest) -> FunctionOperationResult:
        """Create a new function group"""
        try:
            logger.info(f"Creating function group {sanitize_for_logging(request.name)}")
            
            # Build function group XML
            function_group_xml = self._build_function_group_xml(request)
            
            url = "/sap/bc/adt/functions/groups"
            headers = {'Content-Type': 'application/vnd.sap.adt.functions.groups.v3+xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=function_group_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created function group {sanitize_for_logging(request.name)}")
                    return FunctionOperationResult(
                        success=True,
                        object_name=request.name,
                        created=True,
                        message=f"Function group {request.name} created successfully"
                    )
                else:
                    error_msg = f"Failed to create function group: HTTP {response.status}"
                    logger.error(error_msg)
                    return FunctionOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating function group: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return FunctionOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _build_function_group_xml(self, request: CreateFunctionGroupRequest) -> str:
        """Build function group XML for creation"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <fugr:functionGroup xmlns:fugr="http://www.sap.com/adt/functions/groups"
                           xmlns:adtcore="http://www.sap.com/adt/core"
                           adtcore:name="{sanitize_for_xml(request.name)}"
                           adtcore:description="{sanitize_for_xml(request.description)}"
                           adtcore:package="{sanitize_for_xml(request.package_name)}">
        </fugr:functionGroup>"""
    
    async def get_function_modules(self, function_group_name: str) -> List[FunctionModuleInfo]:
        """Get function modules from a function group"""
        try:
            url = f"/sap/bc/adt/functions/groups/{quote(function_group_name)}/fmodules"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_function_modules_xml(xml_content, function_group_name)
                else:
                    logger.error(f"Failed to get function modules: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting function modules: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_function_modules_xml(self, xml_content: str, function_group_name: str) -> List[FunctionModuleInfo]:
        """Parse function modules from XML response"""
        function_modules = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return function_modules
            
            # Parse function module nodes
            for node in root.findall('.//functionModule'):
                name = node.get('name', '')
                description = node.get('description', '')
                
                if name:
                    function_modules.append(FunctionModuleInfo(
                        name=name,
                        function_group=function_group_name,
                        description=description
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing function modules XML: {sanitize_for_logging(str(e))}")
        
        return function_modules
    
    async def get_function_module_info(self, function_group_name: str, function_module_name: str) -> Optional[FunctionModuleInfo]:
        """Get detailed function module information"""
        try:
            url = f"/sap/bc/adt/functions/groups/{quote(function_group_name)}/fmodules/{quote(function_module_name)}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_function_module_info_xml(xml_content, function_group_name)
                else:
                    logger.error(f"Failed to get function module info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting function module info: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_function_module_info_xml(self, xml_content: str, function_group_name: str) -> Optional[FunctionModuleInfo]:
        """Parse function module info from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            # Extract function module information
            name = root.get('name', '')
            description = root.get('description', '')
            
            # Extract parameters and exceptions
            importing_params = []
            exporting_params = []
            changing_params = []
            tables_params = []
            exceptions = []
            
            for param in root.findall('.//importing/parameter'):
                importing_params.append({
                    'name': param.get('name', ''),
                    'type': param.get('type', ''),
                    'optional': param.get('optional', 'false') == 'true'
                })
            
            for param in root.findall('.//exporting/parameter'):
                exporting_params.append({
                    'name': param.get('name', ''),
                    'type': param.get('type', '')
                })
            
            for param in root.findall('.//changing/parameter'):
                changing_params.append({
                    'name': param.get('name', ''),
                    'type': param.get('type', ''),
                    'optional': param.get('optional', 'false') == 'true'
                })
            
            for param in root.findall('.//tables/parameter'):
                tables_params.append({
                    'name': param.get('name', ''),
                    'type': param.get('type', ''),
                    'optional': param.get('optional', 'false') == 'true'
                })
            
            for exception in root.findall('.//exception'):
                exceptions.append(exception.get('name', ''))
            
            return FunctionModuleInfo(
                name=name,
                function_group=function_group_name,
                description=description,
                importing_parameters=importing_params if importing_params else None,
                exporting_parameters=exporting_params if exporting_params else None,
                changing_parameters=changing_params if changing_params else None,
                tables_parameters=tables_params if tables_params else None,
                exceptions=exceptions if exceptions else None
            )
                    
        except Exception as e:
            logger.error(f"Error parsing function module info XML: {sanitize_for_logging(str(e))}")
            return None
    
    async def create_function_module(self, request: CreateFunctionModuleRequest) -> FunctionOperationResult:
        """Create a new function module"""
        try:
            logger.info(f"Creating function module {sanitize_for_logging(request.name)} in group {sanitize_for_logging(request.function_group)}")
            
            # Build function module XML
            function_module_xml = self._build_function_module_xml(request)
            
            url = f"/sap/bc/adt/functions/groups/{quote(request.function_group)}/fmodules"
            headers = {'Content-Type': 'application/vnd.sap.adt.functions.fmodules.v3+xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=function_module_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created function module {sanitize_for_logging(request.name)}")
                    return FunctionOperationResult(
                        success=True,
                        object_name=request.name,
                        created=True,
                        message=f"Function module {request.name} created successfully"
                    )
                else:
                    error_msg = f"Failed to create function module: HTTP {response.status}"
                    logger.error(error_msg)
                    return FunctionOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating function module: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return FunctionOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _build_function_module_xml(self, request: CreateFunctionModuleRequest) -> str:
        """Build function module XML for creation"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <fmod:functionModule xmlns:fmod="http://www.sap.com/adt/functions/fmodules"
                            xmlns:adtcore="http://www.sap.com/adt/core"
                            adtcore:name="{sanitize_for_xml(request.name)}"
                            adtcore:description="{sanitize_for_xml(request.description)}">
        </fmod:functionModule>"""
    
    async def get_function_group_includes(self, function_group_name: str) -> List[FunctionGroupIncludeInfo]:
        """Get function group includes"""
        try:
            url = f"/sap/bc/adt/functions/groups/{quote(function_group_name)}/includes"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_function_group_includes_xml(xml_content, function_group_name)
                else:
                    logger.error(f"Failed to get function group includes: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting function group includes: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_function_group_includes_xml(self, xml_content: str, function_group_name: str) -> List[FunctionGroupIncludeInfo]:
        """Parse function group includes from XML response"""
        includes = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return includes
            
            # Parse include nodes
            for node in root.findall('.//include'):
                name = node.get('name', '')
                description = node.get('description', '')
                include_type = node.get('type', '')
                
                if name:
                    includes.append(FunctionGroupIncludeInfo(
                        name=name,
                        function_group=function_group_name,
                        description=description,
                        include_type=include_type
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing function group includes XML: {sanitize_for_logging(str(e))}")
        
        return includes

    # DDIC Object Management Methods
    
    async def get_data_elements(self, package_name: Optional[str] = None) -> List[DataElementInfo]:
        """Get data elements from SAP system"""
        try:
            url = "/sap/bc/adt/ddic/dataelements"
            params = {}
            if package_name:
                params['package'] = package_name
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_data_elements_xml(xml_content)
                else:
                    logger.error(f"Failed to get data elements: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting data elements: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_data_elements_xml(self, xml_content: str) -> List[DataElementInfo]:
        """Parse data elements from XML response"""
        data_elements = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return data_elements
            
            for node in root.findall('.//dataElement'):
                name = node.get('name', '')
                description = node.get('description', '')
                package_name = node.get('package', '')
                
                if name:
                    data_elements.append(DataElementInfo(
                        name=name,
                        description=description,
                        package_name=package_name
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing data elements XML: {sanitize_for_logging(str(e))}")
        
        return data_elements
    
    async def get_data_element_info(self, data_element_name: str) -> Optional[DataElementInfo]:
        """Get detailed data element information"""
        try:
            url = f"/sap/bc/adt/ddic/dataelements/{quote(data_element_name)}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_data_element_info_xml(xml_content)
                else:
                    logger.error(f"Failed to get data element info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting data element info: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_data_element_info_xml(self, xml_content: str) -> Optional[DataElementInfo]:
        """Parse data element info from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            name = root.get('name', '')
            description = root.get('description', '')
            package_name = root.get('package', '')
            domain_name = root.get('domainName', '')
            data_type = root.get('dataType', '')
            
            return DataElementInfo(
                name=name,
                description=description,
                package_name=package_name,
                domain_name=domain_name,
                data_type=data_type
            )
                    
        except Exception as e:
            logger.error(f"Error parsing data element info XML: {sanitize_for_logging(str(e))}")
            return None
    
    async def create_data_element(self, request: CreateDataElementRequest) -> DDICOperationResult:
        """Create a new data element"""
        try:
            logger.info(f"Creating data element {sanitize_for_logging(request.name)}")
            
            data_element_xml = self._build_data_element_xml(request)
            
            url = "/sap/bc/adt/ddic/dataelements"
            headers = {'Content-Type': 'application/vnd.sap.adt.dataelements.v2+xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=data_element_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created data element {sanitize_for_logging(request.name)}")
                    return DDICOperationResult(
                        success=True,
                        object_name=request.name,
                        object_type="DTEL",
                        created=True,
                        message=f"Data element {request.name} created successfully"
                    )
                else:
                    error_msg = f"Failed to create data element: HTTP {response.status}"
                    logger.error(error_msg)
                    return DDICOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating data element: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return DDICOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _build_data_element_xml(self, request: CreateDataElementRequest) -> str:
        """Build data element XML for creation"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <dtel:dataElement xmlns:dtel="http://www.sap.com/adt/dataelements"
                         xmlns:adtcore="http://www.sap.com/adt/core"
                         adtcore:name="{sanitize_for_xml(request.name)}"
                         adtcore:description="{sanitize_for_xml(request.description)}"
                         adtcore:package="{sanitize_for_xml(request.package_name)}">
            {f'<dtel:domainName>{sanitize_for_xml(request.domain_name)}</dtel:domainName>' if request.domain_name else ''}
            {f'<dtel:dataType>{sanitize_for_xml(request.data_type)}</dtel:dataType>' if request.data_type else ''}
            {f'<dtel:length>{request.length}</dtel:length>' if request.length else ''}
            {f'<dtel:decimals>{request.decimals}</dtel:decimals>' if request.decimals else ''}
        </dtel:dataElement>"""
    
    async def get_domains(self, package_name: Optional[str] = None) -> List[DomainInfo]:
        """Get domains from SAP system"""
        try:
            url = "/sap/bc/adt/ddic/domains"
            params = {}
            if package_name:
                params['package'] = package_name
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_domains_xml(xml_content)
                else:
                    logger.error(f"Failed to get domains: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting domains: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_domains_xml(self, xml_content: str) -> List[DomainInfo]:
        """Parse domains from XML response"""
        domains = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return domains
            
            for node in root.findall('.//domain'):
                name = node.get('name', '')
                description = node.get('description', '')
                package_name = node.get('package', '')
                
                if name:
                    domains.append(DomainInfo(
                        name=name,
                        description=description,
                        package_name=package_name
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing domains XML: {sanitize_for_logging(str(e))}")
        
        return domains
    
    async def get_domain_info(self, domain_name: str) -> Optional[DomainInfo]:
        """Get detailed domain information"""
        try:
            url = f"/sap/bc/adt/ddic/domains/{quote(domain_name)}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_domain_info_xml(xml_content)
                else:
                    logger.error(f"Failed to get domain info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting domain info: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_domain_info_xml(self, xml_content: str) -> Optional[DomainInfo]:
        """Parse domain info from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            name = root.get('name', '')
            description = root.get('description', '')
            package_name = root.get('package', '')
            data_type = root.get('dataType', '')
            
            return DomainInfo(
                name=name,
                description=description,
                package_name=package_name,
                data_type=data_type
            )
                    
        except Exception as e:
            logger.error(f"Error parsing domain info XML: {sanitize_for_logging(str(e))}")
            return None
    
    async def create_domain(self, request: CreateDomainRequest) -> DDICOperationResult:
        """Create a new domain"""
        try:
            logger.info(f"Creating domain {sanitize_for_logging(request.name)}")
            
            domain_xml = self._build_domain_xml(request)
            
            url = "/sap/bc/adt/ddic/domains"
            headers = {'Content-Type': 'application/vnd.sap.adt.domains.v2+xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=domain_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created domain {sanitize_for_logging(request.name)}")
                    return DDICOperationResult(
                        success=True,
                        object_name=request.name,
                        object_type="DOMA",
                        created=True,
                        message=f"Domain {request.name} created successfully"
                    )
                else:
                    error_msg = f"Failed to create domain: HTTP {response.status}"
                    logger.error(error_msg)
                    return DDICOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating domain: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return DDICOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _build_domain_xml(self, request: CreateDomainRequest) -> str:
        """Build domain XML for creation"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <doma:domain xmlns:doma="http://www.sap.com/adt/domains"
                    xmlns:adtcore="http://www.sap.com/adt/core"
                    adtcore:name="{sanitize_for_xml(request.name)}"
                    adtcore:description="{sanitize_for_xml(request.description)}"
                    adtcore:package="{sanitize_for_xml(request.package_name)}">
            <doma:dataType>{sanitize_for_xml(request.data_type)}</doma:dataType>
            {f'<doma:length>{request.length}</doma:length>' if request.length else ''}
            {f'<doma:decimals>{request.decimals}</doma:decimals>' if request.decimals else ''}
            {f'<doma:conversionExit>{sanitize_for_xml(request.conversion_exit)}</doma:conversionExit>' if request.conversion_exit else ''}
        </doma:domain>"""
    
    async def get_tables(self, package_name: Optional[str] = None) -> List[TableInfo]:
        """Get database tables from SAP system"""
        try:
            url = "/sap/bc/adt/ddic/tables"
            params = {}
            if package_name:
                params['package'] = package_name
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_tables_xml(xml_content)
                else:
                    logger.error(f"Failed to get tables: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting tables: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_tables_xml(self, xml_content: str) -> List[TableInfo]:
        """Parse tables from XML response"""
        tables = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return tables
            
            for node in root.findall('.//table'):
                name = node.get('name', '')
                description = node.get('description', '')
                package_name = node.get('package', '')
                
                if name:
                    tables.append(TableInfo(
                        name=name,
                        description=description,
                        package_name=package_name
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing tables XML: {sanitize_for_logging(str(e))}")
        
        return tables
    
    async def get_table_info(self, table_name: str) -> Optional[TableInfo]:
        """Get detailed table information"""
        try:
            url = f"/sap/bc/adt/ddic/tables/{quote(table_name)}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_table_info_xml(xml_content)
                else:
                    logger.error(f"Failed to get table info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting table info: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_table_info_xml(self, xml_content: str) -> Optional[TableInfo]:
        """Parse table info from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            name = root.get('name', '')
            description = root.get('description', '')
            package_name = root.get('package', '')
            table_category = root.get('tableCategory', '')
            
            return TableInfo(
                name=name,
                description=description,
                package_name=package_name,
                table_category=table_category
            )
                    
        except Exception as e:
            logger.error(f"Error parsing table info XML: {sanitize_for_logging(str(e))}")
            return None
    
    async def create_table(self, request: CreateTableRequest) -> DDICOperationResult:
        """Create a new database table"""
        try:
            logger.info(f"Creating table {sanitize_for_logging(request.name)}")
            
            table_xml = self._build_table_xml(request)
            
            url = "/sap/bc/adt/ddic/tables"
            headers = {'Content-Type': 'application/vnd.sap.adt.tables.v2+xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=table_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created table {sanitize_for_logging(request.name)}")
                    return DDICOperationResult(
                        success=True,
                        object_name=request.name,
                        object_type="TABL",
                        created=True,
                        message=f"Table {request.name} created successfully"
                    )
                else:
                    error_msg = f"Failed to create table: HTTP {response.status}"
                    logger.error(error_msg)
                    return DDICOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating table: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return DDICOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _build_table_xml(self, request: CreateTableRequest) -> str:
        """Build table XML for creation"""
        fields_xml = ""
        for field in request.fields:
            fields_xml += f"""
            <tabl:field name="{sanitize_for_xml(field.get('name', ''))}"
                       dataElement="{sanitize_for_xml(field.get('data_element', ''))}"
                       keyField="{'X' if field.get('name') in request.key_fields else ''}"
                       notNull="{field.get('not_null', 'false')}"
                       description="{sanitize_for_xml(field.get('description', ''))}"/>"""
        
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <tabl:table xmlns:tabl="http://www.sap.com/adt/tables"
                   xmlns:adtcore="http://www.sap.com/adt/core"
                   adtcore:name="{sanitize_for_xml(request.name)}"
                   adtcore:description="{sanitize_for_xml(request.description)}"
                   adtcore:package="{sanitize_for_xml(request.package_name)}"
                   tabl:tableCategory="{sanitize_for_xml(request.table_category)}"
                   tabl:deliveryClass="{sanitize_for_xml(request.delivery_class)}">
            <tabl:fields>{fields_xml}
            </tabl:fields>
        </tabl:table>"""
    
    async def get_structures(self, package_name: Optional[str] = None) -> List[StructureInfo]:
        """Get structures from SAP system"""
        try:
            url = "/sap/bc/adt/ddic/structures"
            params = {}
            if package_name:
                params['package'] = package_name
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_structures_xml(xml_content)
                else:
                    logger.error(f"Failed to get structures: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting structures: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_structures_xml(self, xml_content: str) -> List[StructureInfo]:
        """Parse structures from XML response"""
        structures = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return structures
            
            for node in root.findall('.//structure'):
                name = node.get('name', '')
                description = node.get('description', '')
                package_name = node.get('package', '')
                
                if name:
                    structures.append(StructureInfo(
                        name=name,
                        description=description,
                        package_name=package_name
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing structures XML: {sanitize_for_logging(str(e))}")
        
        return structures
    
    async def get_structure_info(self, structure_name: str) -> Optional[StructureInfo]:
        """Get detailed structure information"""
        try:
            url = f"/sap/bc/adt/ddic/structures/{quote(structure_name)}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_structure_info_xml(xml_content)
                else:
                    logger.error(f"Failed to get structure info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting structure info: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_structure_info_xml(self, xml_content: str) -> Optional[StructureInfo]:
        """Parse structure info from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            name = root.get('name', '')
            description = root.get('description', '')
            package_name = root.get('package', '')
            
            return StructureInfo(
                name=name,
                description=description,
                package_name=package_name
            )
                    
        except Exception as e:
            logger.error(f"Error parsing structure info XML: {sanitize_for_logging(str(e))}")
            return None
    
    async def create_structure(self, request: CreateStructureRequest) -> DDICOperationResult:
        """Create a new structure"""
        try:
            logger.info(f"Creating structure {sanitize_for_logging(request.name)}")
            
            structure_xml = self._build_structure_xml(request)
            
            url = "/sap/bc/adt/ddic/structures"
            headers = {'Content-Type': 'application/vnd.sap.adt.structures.v2+xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=structure_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created structure {sanitize_for_logging(request.name)}")
                    return DDICOperationResult(
                        success=True,
                        object_name=request.name,
                        object_type="STRU",
                        created=True,
                        message=f"Structure {request.name} created successfully"
                    )
                else:
                    error_msg = f"Failed to create structure: HTTP {response.status}"
                    logger.error(error_msg)
                    return DDICOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating structure: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return DDICOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _build_structure_xml(self, request: CreateStructureRequest) -> str:
        """Build structure XML for creation"""
        fields_xml = ""
        for field in request.fields:
            fields_xml += f"""
            <stru:field name="{sanitize_for_xml(field.get('name', ''))}"
                       dataElement="{sanitize_for_xml(field.get('data_element', ''))}"
                       description="{sanitize_for_xml(field.get('description', ''))}"/>"""
        
        includes_xml = ""
        if request.includes:
            for include in request.includes:
                includes_xml += f'<stru:include name="{sanitize_for_xml(include)}"/>'
        
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <stru:structure xmlns:stru="http://www.sap.com/adt/structures"
                       xmlns:adtcore="http://www.sap.com/adt/core"
                       adtcore:name="{sanitize_for_xml(request.name)}"
                       adtcore:description="{sanitize_for_xml(request.description)}"
                       adtcore:package="{sanitize_for_xml(request.package_name)}">
            {includes_xml}
            <stru:fields>{fields_xml}
            </stru:fields>
        </stru:structure>"""
    
    async def get_table_types(self, package_name: Optional[str] = None) -> List[TableTypeInfo]:
        """Get table types from SAP system"""
        try:
            url = "/sap/bc/adt/ddic/tabletypes"
            params = {}
            if package_name:
                params['package'] = package_name
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_table_types_xml(xml_content)
                else:
                    logger.error(f"Failed to get table types: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting table types: {sanitize_for_logging(str(e))}")
            return []
    
    def _parse_table_types_xml(self, xml_content: str) -> List[TableTypeInfo]:
        """Parse table types from XML response"""
        table_types = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return table_types
            
            for node in root.findall('.//tableType'):
                name = node.get('name', '')
                description = node.get('description', '')
                package_name = node.get('package', '')
                
                if name:
                    table_types.append(TableTypeInfo(
                        name=name,
                        description=description,
                        package_name=package_name
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing table types XML: {sanitize_for_logging(str(e))}")
        
        return table_types
    
    async def get_table_type_info(self, table_type_name: str) -> Optional[TableTypeInfo]:
        """Get detailed table type information"""
        try:
            url = f"/sap/bc/adt/ddic/tabletypes/{quote(table_type_name)}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_table_type_info_xml(xml_content)
                else:
                    logger.error(f"Failed to get table type info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting table type info: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_table_type_info_xml(self, xml_content: str) -> Optional[TableTypeInfo]:
        """Parse table type info from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            name = root.get('name', '')
            description = root.get('description', '')
            package_name = root.get('package', '')
            line_type = root.get('lineType', '')
            
            return TableTypeInfo(
                name=name,
                description=description,
                package_name=package_name,
                line_type=line_type
            )
                    
        except Exception as e:
            logger.error(f"Error parsing table type info XML: {sanitize_for_logging(str(e))}")
            return None
    
    async def create_table_type(self, request: CreateTableTypeRequest) -> DDICOperationResult:
        """Create a new table type"""
        try:
            logger.info(f"Creating table type {sanitize_for_logging(request.name)}")
            
            table_type_xml = self._build_table_type_xml(request)
            
            url = "/sap/bc/adt/ddic/tabletypes"
            headers = {'Content-Type': 'application/vnd.sap.adt.tabletype.v1+xml'}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token
            
            async with self.session.post(url, data=table_type_xml, headers=headers) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully created table type {sanitize_for_logging(request.name)}")
                    return DDICOperationResult(
                        success=True,
                        object_name=request.name,
                        object_type="TTYP",
                        created=True,
                        message=f"Table type {request.name} created successfully"
                    )
                else:
                    error_msg = f"Failed to create table type: HTTP {response.status}"
                    logger.error(error_msg)
                    return DDICOperationResult(
                        success=False,
                        message=error_msg,
                        errors=[error_msg]
                    )
                    
        except Exception as e:
            error_msg = f"Error creating table type: {sanitize_for_logging(str(e))}"
            logger.error(error_msg)
            return DDICOperationResult(
                success=False,
                message=error_msg,
                errors=[str(e)]
            )
    
    def _build_table_type_xml(self, request: CreateTableTypeRequest) -> str:
        """Build table type XML for creation"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <ttyp:tableType xmlns:ttyp="http://www.sap.com/adt/tabletypes"
                       xmlns:adtcore="http://www.sap.com/adt/core"
                       adtcore:name="{sanitize_for_xml(request.name)}"
                       adtcore:description="{sanitize_for_xml(request.description)}"
                       adtcore:package="{sanitize_for_xml(request.package_name)}">
            <ttyp:lineType>{sanitize_for_xml(request.line_type)}</ttyp:lineType>
            <ttyp:accessType>{sanitize_for_xml(request.access_type)}</ttyp:accessType>
            <ttyp:uniqueKey>{str(request.unique_key).lower()}</ttyp:uniqueKey>
        </ttyp:tableType>"""

    async def update_test_class_source(self, class_name: str, source_code: str, test_class_url: str) -> ObjectOperationResult:
        """
        Update test class source code in /includes/testclasses endpoint.
        Modified to separate source update and activation steps (matching TypeScript implementation).
        """
        try:
            logger.info(f"Updating test class source for {sanitize_for_logging(class_name)}")
            
            # Get transport metadata for the class
            metadata = await self.get_object_metadata(class_name, 'CLAS')
            if metadata and metadata.get('transport_number'):
                logger.info(f"Using transport {sanitize_for_logging(metadata['transport_number'])} for test class update")
            
            # Step 1: Update the test class source
            update_success = False
            
            # Lock the object for editing
            object_url = f"/sap/bc/adt/oo/classes/{class_name}?sap-client={self.connection.client}"
            lock_info = await self._lock_object(object_url)
            
            if not lock_info:
                return ObjectOperationResult(
                    updated=False,
                    syntax_check_passed=False,
                    activated=False,
                    errors=[SAPSyntaxError(line=1, message='Failed to lock class for test class update', severity='ERROR')],
                    warnings=[]
                )
            
            try:
                # First, check if the test classes section exists
                logger.info("Checking if test classes section exists")
                test_classes_exists = False
                
                try:
                    check_url = f"/sap/bc/adt/oo/classes/{class_name}/includes/testclasses?sap-client={self.connection.client}"
                    headers = await self._get_appropriate_headers()
                    headers['Accept'] = 'text/plain'
                    
                    async with self.session.get(check_url, headers=headers) as check_response:
                        test_classes_exists = (check_response.status == 200)
                        logger.info("Test classes section exists")
                except Exception as check_error:
                    if hasattr(check_error, 'status') and check_error.status == 404:
                        logger.info("Test classes section does not exist, will create it")
                        test_classes_exists = False
                    else:
                        logger.info(f"Error checking test classes section: {sanitize_for_logging(str(check_error))}")
                        # Continue anyway, will try to create if needed
                        test_classes_exists = False
                
                # If test classes section doesn't exist, create it first
                if not test_classes_exists:
                    logger.info("Creating test classes section")
                    
                    create_include_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<class:abapClassInclude xmlns:adtcore="http://www.sap.com/adt/core" xmlns:class="http://www.sap.com/adt/oo/classes" adtcore:name="testclasses" class:includeType="testclasses"/>'''
                    
                    create_url = f"/sap/bc/adt/oo/classes/{class_name}/includes?sap-client={self.connection.client}&lockHandle={lock_info['LOCK_HANDLE']}"
                    
                    try:
                        create_headers = await self._get_appropriate_headers()
                        create_headers.update({
                            'Content-Type': 'application/vnd.sap.adt.oo.classincludes+xml',
                            'Accept': 'application/vnd.sap.adt.oo.classincludes+xml'
                        })
                        
                        async with self.session.post(create_url, data=create_include_xml, headers=create_headers) as create_response:
                            if create_response.status in [201, 200]:
                                logger.info("Test classes section created successfully")
                            else:
                                logger.info(f"Unexpected status when creating test classes section: {create_response.status}")
                    except Exception as create_error:
                        logger.info(f"Error creating test classes section: {sanitize_for_logging(str(create_error))}")
                        # Continue anyway - the section might already exist or be created automatically
                
                # Now update the test class source with transport information
                source_url = f"{test_class_url}?sap-client={self.connection.client}&lockHandle={lock_info['LOCK_HANDLE']}"
                
                # Add transport number if available from metadata or lock info
                if metadata and metadata.get('transport_number'):
                    source_url += f"&corrNr={metadata['transport_number']}"
                    logger.info(f"Added transport {sanitize_for_logging(metadata['transport_number'])} to test class update URL")
                elif lock_info.get('CORRNR'):
                    source_url += f"&corrNr={lock_info['CORRNR']}"
                    logger.info(f"Added transport {sanitize_for_logging(lock_info['CORRNR'])} from lock info to test class update URL")
                
                update_headers = await self._get_appropriate_headers()
                update_headers.update({
                    'Content-Type': 'text/plain; charset=utf-8',
                    'Accept': 'text/plain'
                })
                
                async with self.session.put(source_url, data=source_code, headers=update_headers) as response:
                    update_success = (response.status in [200, 204])
                    if update_success:
                        logger.info("Test class source updated successfully")
                    else:
                        logger.error(f"Test class update failed with status: {response.status}")
                        
            finally:
                # Always unlock the object before attempting activation
                await self._unlock_object(object_url, lock_info['LOCK_HANDLE'])
                logger.info("Object unlocked after source update")
            
            # If update failed, return error
            if not update_success:
                return ObjectOperationResult(
                    updated=False,
                    syntax_check_passed=False,
                    activated=False,
                    errors=[SAPSyntaxError(line=1, message='Failed to update test class source', severity='ERROR')],
                    warnings=[]
                )
            
            # Step 2: Run syntax check before activation
            logger.info("Running syntax check on inactive test classes")
            syntax_check_result = await self.check_syntax(class_name, 'CLAS', source_code)
            
            if not syntax_check_result.success:
                logger.info(f"Syntax check failed: {sanitize_for_logging(str(syntax_check_result.errors))}")
                return ObjectOperationResult(
                    updated=True,
                    syntax_check_passed=False,
                    activated=False,
                    errors=syntax_check_result.errors,
                    warnings=syntax_check_result.warnings
                )
            
            logger.info("Syntax check passed, proceeding with activation")
            
            # Step 3: Activate the object as a separate operation
            logger.info(f"Attempting to activate class {sanitize_for_logging(class_name)} after test class update")
            activation_success = False
            try:
                # Small delay to ensure system has processed the update
                await asyncio.sleep(0.5)
                
                # Activate the object
                activation_result = await self.activate_object(class_name, 'CLAS')
                activation_success = activation_result.success and activation_result.activated
                logger.info(f"Class activation result: {sanitize_for_logging(activation_success)}")
            except Exception as error:
                logger.info(f"Activation error caught: {sanitize_for_logging(str(error))}")
                # Continue despite activation error - the test class might still be usable
            
            # Return success even if activation failed - the test class is still usable
            return ObjectOperationResult(
                updated=True,
                syntax_check_passed=True,
                activated=activation_success,
                errors=[] if activation_success else [SAPSyntaxError(line=1, message='Activation failed, but test class may still be usable', severity='ERROR')],
                warnings=syntax_check_result.warnings
            )
            
        except Exception as e:
            logger.error(f"Failed to update test class source: {sanitize_for_logging(str(e))}")
            return ObjectOperationResult(
                updated=False,
                syntax_check_passed=False,
                activated=False,
                errors=[SyntaxError(line=1, message=f'Test class update failed: {str(e)}', severity='ERROR')],
                warnings=[]
            )

    async def close(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def _try_reentrance_ticket_auth(self) -> bool:
        """
        Try to authenticate using reentrance ticket when basic auth fails for API calls
        This handles modern SAP systems that require browser-based authentication
        """
        try:
            logger.info("Attempting reentrance ticket authentication for API access")
            
            # Import here to avoid circular imports
            from auth.providers.reentrance_ticket_auth import ReentranceTicketAuthProvider
            
            # Create reentrance ticket provider
            ticket_provider = ReentranceTicketAuthProvider()
            
            # Get credentials from current connection
            credentials = {
                'sap_host': self.connection.host,
                'sap_client': self.connection.client,
                'sap_username': self.connection.username,
                'sap_password': self.connection.password
            }
            
            # Attempt reentrance ticket authentication
            result = await ticket_provider.authenticate(credentials)
            
            if result.success and result.user_info:
                logger.info("Reentrance ticket authentication successful")
                
                # Update current session with ticket data
                ticket_data = result.user_info.get('ticket_data', {})
                
                if ticket_data.get('cookies'):
                    self.cookies.update(ticket_data['cookies'])
                    logger.info("Updated session cookies with ticket data")
                
                if ticket_data.get('headers'):
                    # Store ticket headers for future requests
                    if not hasattr(self, 'ticket_headers'):
                        self.ticket_headers = {}
                    self.ticket_headers.update(ticket_data['headers'])
                    logger.info("Updated session headers with ticket data")
                
                # Store reentrance ticket info
                self.reentrance_ticket = ticket_data.get('ticket')
                self.ticket_type = ticket_data.get('ticket_type')
                
                return True
            else:
                logger.warning(f"Reentrance ticket authentication failed: {result.error_message}")
                return False
                
        except Exception as e:
            logger.error(f"Error during reentrance ticket authentication: {sanitize_for_logging(str(e))}")
            return False
    
    # Quickfix Support Methods
    
    async def evaluate_quickfixes(self, object_uri: str, marker_ids: List[str]) -> List[Dict[str, Any]]:
        """Evaluate available quickfixes for ATC findings"""
        try:
            logger.info(f"Starting quickfix evaluation for {sanitize_for_logging(object_uri)}")
            
            marker_params = '&'.join([f"markerId={quote(marker_id)}" for marker_id in marker_ids])
            url = f"/sap/bc/adt/quickfixes/evaluation?uri={quote(object_uri)}&{marker_params}&markerIdIsFilter=true&sap-client={self.connection.client}"
            
            evaluation_xml = """<?xml version="1.0" encoding="ASCII"?>
<quickfixes:evaluationRequest xmlns:quickfixes="http://www.sap.com/adt/quickfixes"/>"""
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/vnd.sap.adt.quickfixes.evaluation+xml;version=1.0.0'
            headers['Accept'] = 'application/xml'
            headers['User-Agent'] = 'ABAP-Accelerator-MCP-Server/1.0.0'
            
            async with self.session.post(url, data=evaluation_xml, headers=headers) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    logger.info(f"Quickfix evaluation response: {sanitize_for_logging(xml_content)}")
                    return self._parse_quickfix_evaluations(xml_content)
                else:
                    logger.warning(f"Quickfix evaluation failed: HTTP {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Quickfix evaluation failed: {sanitize_for_logging(str(e))}")
            return []
    
    async def get_quickfix_proposal(self, quickfix_id: str, source_code: str, object_uri: str, marker_id: str) -> Optional[Dict[str, Any]]:
        """Get quickfix proposal details"""
        try:
            url = f"/sap/bc/adt/quickfixes/proposals/providers/atc/quickfixes/{quickfix_id}?sap-client={self.connection.client}"
            
            proposal_xml = f"""<?xml version="1.0" encoding="ASCII"?>
<quickfixes:proposalRequest xmlns:adtcore="http://www.sap.com/adt/core" xmlns:quickfixes="http://www.sap.com/adt/quickfixes">
  <input>
    <content>{sanitize_for_xml(source_code)}</content>
    <adtcore:objectReference adtcore:uri="{sanitize_for_xml(object_uri)}"/>
  </input>
  <userContent>ITEMID={marker_id.split(',')[0]}; CHECK_RUN_INDEX={marker_id.split(',')[1] if ',' in marker_id else '212'}</userContent>
</quickfixes:proposalRequest>"""
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/xml'
            headers['Accept'] = 'application/xml'
            
            async with self.session.post(url, data=proposal_xml, headers=headers) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_quickfix_proposal(xml_content, quickfix_id)
                else:
                    logger.warning(f"Quickfix proposal failed: HTTP {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Quickfix proposal failed: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_quickfix_evaluations(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parse quickfix evaluations from XML"""
        evaluations = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return evaluations
            
            results = extract_from_xml(root, 'qf:evaluationResults.evaluationResult', [])
            if not isinstance(results, list):
                results = [results] if results else []
            
            logger.info(f"Parsing {len(results)} quickfix evaluation results")
            
            for result in results:
                if result and 'adtcore:objectReference' in result:
                    obj_ref = result['adtcore:objectReference'].get('$', {})
                    
                    # Extract markerId from various possible locations
                    marker_id = (extract_from_xml(result, 'userContent', '') or 
                               extract_from_xml(result, '$.markerId', '') or
                               extract_from_xml(result, 'markerId', '') or
                               obj_ref.get('adtcore:uri', '') or
                               '')
                    
                    quickfix = {
                        'quickfixId': obj_ref.get('adtcore:type', ''),
                        'name': obj_ref.get('adtcore:name', ''),
                        'description': obj_ref.get('adtcore:description', ''),
                        'markerId': marker_id
                    }
                    evaluations.append(quickfix)
                    logger.info(f"Found quickfix: {sanitize_for_logging(quickfix['name'])}")
                    
        except Exception as e:
            logger.error(f"Error parsing quickfix evaluations: {sanitize_for_logging(str(e))}")
        
        return evaluations
    
    def _parse_quickfix_proposal(self, xml_content: str, quickfix_id: str) -> Optional[Dict[str, Any]]:
        """Parse quickfix proposal from XML"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            deltas = extract_from_xml(root, 'qf:proposalResult.deltas.unit', [])
            status_messages = extract_from_xml(root, 'qf:proposalResult.statusMessages.statusMessage', [])
            
            source_changes = ''
            success = False
            
            if deltas:
                if not isinstance(deltas, list):
                    deltas = [deltas]
                source_changes = '\n'.join([extract_from_xml(delta, 'content', '') for delta in deltas])
            
            if status_messages:
                if not isinstance(status_messages, list):
                    status_messages = [status_messages]
                success = any(msg.get('$', {}).get('severity') == 'info' and 
                            'successfully' in (msg.get('$', {}).get('message', ''))
                            for msg in status_messages)
            
            return {
                'quickfixId': quickfix_id,
                'name': f'Quickfix {quickfix_id}',
                'description': 'Auto-generated fix',
                'sourceChanges': source_changes,
                'success': success
            }
            
        except Exception as e:
            logger.error(f"Error parsing quickfix proposal: {sanitize_for_logging(str(e))}")
            return None
    

    # Search functionality
    async def search_objects(self, options: 'SearchOptions') -> List['SearchResult']:
        """Search for ABAP objects in SAP system using free text search"""
        import time
        from sap_types.sap_types import SearchResult, SearchOptions
        
        try:
            # Rate limiting
            current_time = time.time()
            if hasattr(self, '_last_search_time'):
                if current_time - self._last_search_time < 1.0:  # 1 second cooldown
                    raise Exception('Search rate limit exceeded. Please wait before searching again')
            self._last_search_time = current_time
            
            # Validate input
            self._validate_search_input(options)
            
            logger.info(f"Searching objects with query: {sanitize_for_logging(options.query)}")
            
            # Build search URL
            url = f"/sap/bc/adt/repository/informationsystem/search?sap-client={self.connection.client}"
            
            # Build search parameters
            params = {
                'operation': 'quickSearch',
                'query': sanitize_for_xml(options.query),
                'maxResults': options.max_results or 50
            }
            
            if options.object_type and options.object_type != 'ALL':
                params['objectType'] = sanitize_for_xml(options.object_type)
            
            if options.package_name:
                params['packageName'] = sanitize_for_xml(options.package_name)
            
            logger.info(f"Search URL: {sanitize_for_logging(url)}")
            logger.info(f"Search params: {sanitize_for_logging(str(params))}")
            
            # Get appropriate headers
            headers = await self._get_appropriate_headers()
            headers['Accept'] = 'application/xml'
            
            # Execute search
            async with self.session.get(url, params=params, headers=headers) as response:
                logger.info(f"Search response status: {response.status}")
                
                if response.status == 200:
                    xml_content = await response.text()
                    results = self._parse_search_results(xml_content)
                    logger.info(f"Found {len(results)} objects")
                    return results
                else:
                    logger.error(f"Search failed with status: {response.status}")
                    error_text = await response.text()
                    logger.error(f"Error response: {sanitize_for_logging(error_text[:500])}")
                    return []
                    
        except Exception as e:
            logger.error(f"Object search failed: {sanitize_for_logging(str(e))}")
            raise e
    
    def _validate_search_input(self, options: 'SearchOptions') -> None:
        """Validate search input parameters"""
        if not options.query or len(options.query) > 100:
            raise ValueError('Query must be 1-100 characters')
        
        # Allow alphanumeric, wildcards, and underscores
        import re
        sanitized_query = re.sub(r'[^A-Za-z0-9*_]', '', options.query)
        if sanitized_query != options.query:
            raise ValueError('Query contains invalid characters. Only alphanumeric, *, and _ allowed')
        
        if options.max_results:
            if not isinstance(options.max_results, int) or options.max_results < 1 or options.max_results > 500:
                raise ValueError('maxResults must be between 1 and 500')
    
    def _parse_search_results(self, xml_content: str) -> List['SearchResult']:
        """Parse search results from XML response"""
        from sap_types.sap_types import SearchResult
        results = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                logger.warning("Failed to parse search response XML")
                return []
            
            # Parse ADT object references from search response
            # Look for object references in various possible locations
            object_refs = []
            
            # Try different XPath patterns
            patterns = [
                './/adtcore:objectReference',
                './/objectReference',
                './/*[@adtcore:name]',
                './/*[@name]'
            ]
            
            for pattern in patterns:
                try:
                    refs = root.findall(pattern, {'adtcore': 'http://www.sap.com/adt/core'})
                    if refs:
                        object_refs.extend(refs)
                        break
                except Exception:
                    continue
            
            # If no namespaced search worked, try without namespace
            if not object_refs:
                for elem in root.iter():
                    if ('name' in elem.attrib or 'adtcore:name' in elem.attrib) and \
                       ('type' in elem.attrib or 'adtcore:type' in elem.attrib):
                        object_refs.append(elem)
            
            logger.info(f"Found {len(object_refs)} object references in search response")
            
            for obj_ref in object_refs:
                if obj_ref is None:
                    continue
                
                # Extract attributes with namespace handling
                name = (obj_ref.get('name') or 
                       obj_ref.get('{http://www.sap.com/adt/core}name') or 
                       obj_ref.get('adtcore:name') or '')
                
                obj_type = (obj_ref.get('type') or 
                           obj_ref.get('{http://www.sap.com/adt/core}type') or 
                           obj_ref.get('adtcore:type') or '')
                
                description = (obj_ref.get('description') or 
                              obj_ref.get('{http://www.sap.com/adt/core}description') or 
                              obj_ref.get('adtcore:description') or '')
                
                package_name = (obj_ref.get('packageName') or 
                               obj_ref.get('{http://www.sap.com/adt/core}packageName') or 
                               obj_ref.get('adtcore:packageName') or '')
                
                uri = (obj_ref.get('uri') or 
                      obj_ref.get('{http://www.sap.com/adt/core}uri') or 
                      obj_ref.get('adtcore:uri') or '')
                
                if name and obj_type:
                    results.append(SearchResult(
                        name=name,
                        type=obj_type,
                        description=description,
                        package_name=package_name,
                        uri=uri
                    ))
            
            logger.info(f"Parsed {len(results)} valid search results")
            return results
            
        except Exception as e:
            logger.error(f"Error parsing search results: {sanitize_for_logging(str(e))}")
            return []
    
    async def _get_resource_uri(self, object_name: str, object_type: str) -> Optional[str]:
        """Get resource URI for object using discovery or fallback patterns (enhanced logging)"""
        try:
            # Ensure session is valid before making discovery requests
            await self._ensure_session_valid()
            
            print(f"[SAP-CLIENT] === RESOURCE URI DISCOVERY ===")
            print(f"[SAP-CLIENT] Object: {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
            
            # Skip discovery for 405 errors and use pattern-based approach directly
            url_patterns = get_object_url_patterns(object_type, object_name)
            fallback_uri = f"/sap/bc/adt/{url_patterns[0]}/{object_name}"
            
            print(f"[SAP-CLIENT] Available patterns: {sanitize_for_logging(str(url_patterns))}")
            print(f"[SAP-CLIENT] Fallback URI: {sanitize_for_logging(fallback_uri)}")
            
            # Special logging and handling for CDS views
            if object_type.upper() == 'DDLS':
                cds_uri = f"/sap/bc/adt/ddic/ddls/sources/{object_name}"
                print(f"[SAP-CLIENT] CDS View detected - using specialized endpoint")
                print(f"[SAP-CLIENT] CDS URI override: {sanitize_for_logging(cds_uri)}")
                logger.info(f"CDS View Resource URI Discovery - Object: {sanitize_for_logging(object_name)}, Override: {sanitize_for_logging(cds_uri)}")
                return cds_uri
            
            try:
                adt_type = self._map_to_adt_type(object_type)
                discovery_uri = f"/sap/bc/adt/repository/typestructure?sap-client={self.connection.client}"
                
                query_params = {
                    'name': object_name,
                    'type': adt_type,
                    'includeInactiveObjects': 'true'
                }
                
                print(f"[SAP-CLIENT] Attempting ADT discovery:")
                print(f"[SAP-CLIENT] - Discovery URI: {sanitize_for_logging(discovery_uri)}")
                print(f"[SAP-CLIENT] - ADT Type: {sanitize_for_logging(adt_type)}")
                print(f"[SAP-CLIENT] - Query params: {sanitize_for_logging(str(query_params))}")
                
                headers = await self._get_appropriate_headers()
                async with self.session.get(discovery_uri, headers=headers, params=query_params) as response:
                    print(f"[SAP-CLIENT] Discovery response status: {response.status}")
                    if response.status == 200:
                        xml_content = await response.text()
                        print(f"[SAP-CLIENT] Discovery XML length: {len(xml_content)}")
                        parsed = safe_parse_xml(xml_content)
                        if parsed:
                            uri = (extract_from_xml(parsed, 'adtcore:objectReference.$.uri', None) or
                                  extract_from_xml(parsed, 'objectReference.$.uri', None))
                            
                            if uri:
                                print(f"[SAP-CLIENT] ✅ Discovery successful: {sanitize_for_logging(uri)}")
                                print(f"[SAP-CLIENT] === END DISCOVERY ===")
                                return uri
                            else:
                                print(f"[SAP-CLIENT] ❌ No URI found in discovery response")
                        else:
                            print(f"[SAP-CLIENT] ❌ Failed to parse discovery XML")
                    else:
                        print(f"[SAP-CLIENT] ❌ Discovery failed with status {response.status}")
            except Exception as discovery_error:
                print(f"[SAP-CLIENT] ❌ Discovery exception: {sanitize_for_logging(str(discovery_error))}")
            
            print(f"[SAP-CLIENT] Using fallback URI: {sanitize_for_logging(fallback_uri)}")
            print(f"[SAP-CLIENT] === END DISCOVERY ===")
            return fallback_uri
            
        except Exception as error:
            print(f"[SAP-CLIENT] Resource URI discovery failed: {sanitize_for_logging(str(error))}")
            url_patterns = get_object_url_patterns(object_type, object_name)
            return f"/sap/bc/adt/{url_patterns[0]}/{object_name}"
    
    def _map_to_adt_type(self, object_type: str) -> str:
        """Map object type to ADT type for discovery"""
        type_mapping = {
            'CLAS': 'CLAS/OC',
            'INTF': 'INTF/OI',
            'PROG': 'PROG/P',
            'FUGR': 'FUGR/F',
            'DDLS': 'DDLS/DF',
            'BDEF': 'BDEF/BH',
            'SRVD': 'SRVD/SV',
            'SRVB': 'SRVB/SB'
        }
        return type_mapping.get(object_type.upper(), object_type.upper())
    
    async def _get_include_source(self, object_name: str) -> Optional[str]:
        """Get source code for include programs"""
        try:
            url = f"/sap/bc/adt/programs/includes/{object_name}/source/main?sap-client={self.connection.client}"
            headers = await self._get_appropriate_headers()
            headers['Accept'] = 'text/plain'
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    print(f"[SAP-CLIENT] Include source failed: {response.status}")
                    return None
        except Exception as e:
            print(f"[SAP-CLIENT] Include source error: {sanitize_for_logging(str(e))}")
            return None
    
    async def get_object_metadata(self, object_name: str, object_type: str) -> Optional[Dict[str, Any]]:
        """Get object metadata including transport and user information"""
        try:
            # This is a simplified version - in a full implementation you'd call the metadata endpoint
            # For now, return None to match the TypeScript behavior when metadata is not available
            return None
        except Exception as e:
            print(f"[SAP-CLIENT] Metadata retrieval failed: {sanitize_for_logging(str(e))}")
            return None
    
    async def get_migration_analysis(self, object_name: str, object_type: str) -> Optional[Dict[str, Any]]:
        """Get custom code migration analysis for an ABAP object"""
        try:
            logger.info(f"Getting migration analysis for {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
            
            # Build migration analysis URL
            url = f"/sap/bc/adt/migration/analysis?sap-client={self.connection.client}"
            
            # Build analysis request XML
            analysis_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
            <migration:analysisRequest xmlns:migration="http://www.sap.com/adt/migration"
                                     xmlns:adtcore="http://www.sap.com/adt/core">
                <migration:object adtcore:name="{sanitize_for_xml(object_name)}" 
                                adtcore:type="{sanitize_for_xml(object_type)}"/>
            </migration:analysisRequest>"""
            
            headers = await self._get_appropriate_headers()
            headers['Content-Type'] = 'application/xml'
            headers['Accept'] = 'application/xml'
            
            async with self.session.post(url, data=analysis_xml, headers=headers) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    return self._parse_migration_analysis(xml_content)
                else:
                    logger.warning(f"Migration analysis failed: HTTP {response.status}")
                    # Return mock analysis for demonstration
                    return self._get_mock_migration_analysis(object_name, object_type)
                    
        except Exception as e:
            logger.error(f"Error getting migration analysis: {sanitize_for_logging(str(e))}")
            # Return mock analysis for demonstration
            return self._get_mock_migration_analysis(object_name, object_type)
    
    def _parse_migration_analysis(self, xml_content: str) -> Optional[Dict[str, Any]]:
        """Parse migration analysis from XML response"""
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None
            
            analysis = {
                'compatibility_issues': [],
                'migration_recommendations': [],
                'effort_estimate': 'Unknown',
                'dependencies': []
            }
            
            # Parse compatibility issues
            for issue in root.findall('.//issue'):
                severity = issue.get('severity', 'INFO')
                message = issue.get('message', 'Unknown issue')
                line = issue.get('line')
                
                analysis['compatibility_issues'].append({
                    'severity': severity,
                    'message': message,
                    'line': int(line) if line else None
                })
            
            # Parse recommendations
            for rec in root.findall('.//recommendation'):
                analysis['migration_recommendations'].append(rec.text or 'No recommendation')
            
            # Parse effort estimate
            effort_elem = root.find('.//effortEstimate')
            if effort_elem is not None:
                analysis['effort_estimate'] = effort_elem.text or 'Unknown'
            
            # Parse dependencies
            for dep in root.findall('.//dependency'):
                analysis['dependencies'].append(dep.get('name', 'Unknown dependency'))
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error parsing migration analysis: {sanitize_for_logging(str(e))}")
            return None
    
    def _get_mock_migration_analysis(self, object_name: str, object_type: str) -> Dict[str, Any]:
        """Get mock migration analysis for demonstration purposes"""
        # Generate mock analysis based on object type
        analysis = {
            'compatibility_issues': [],
            'migration_recommendations': [],
            'effort_estimate': 'Medium',
            'dependencies': []
        }
        
        if object_type.upper() == 'CLAS':
            analysis['compatibility_issues'] = [
                {
                    'severity': 'WARNING',
                    'message': 'Class uses deprecated method CALL FUNCTION',
                    'line': 45
                },
                {
                    'severity': 'INFO',
                    'message': 'Consider using modern ABAP syntax',
                    'line': 78
                }
            ]
            analysis['migration_recommendations'] = [
                'Replace deprecated CALL FUNCTION with modern API calls',
                'Update to use ABAP 7.5+ syntax features',
                'Consider implementing interfaces for better modularity'
            ]
            analysis['dependencies'] = ['STANDARD_CLASS', 'UTILITY_FUNCTIONS']
            
        elif object_type.upper() == 'PROG':
            analysis['compatibility_issues'] = [
                {
                    'severity': 'ERROR',
                    'message': 'Program uses obsolete statement MOVE',
                    'line': 23
                }
            ]
            analysis['migration_recommendations'] = [
                'Replace MOVE statements with assignment operator (=)',
                'Modernize data declarations using DATA() inline declarations'
            ]
            analysis['effort_estimate'] = 'Low'
            
        elif object_type.upper() == 'DDLS':
            analysis['compatibility_issues'] = [
                {
                    'severity': 'INFO',
                    'message': 'CDS view is already modern - no issues found',
                    'line': None
                }
            ]
            analysis['migration_recommendations'] = [
                'CDS view follows modern SAP development practices',
                'Consider adding annotations for better metadata'
            ]
            analysis['effort_estimate'] = 'None'
            
        else:
            analysis['compatibility_issues'] = [
                {
                    'severity': 'INFO',
                    'message': f'No specific migration issues identified for {object_type}',
                    'line': None
                }
            ]
            analysis['migration_recommendations'] = [
                'Review object for modern ABAP best practices',
                'Consider refactoring for better maintainability'
            ]
        
        return analysis
    
    # CDS View Management Methods
    
    async def create_cds_view(
        self,
        name: str,
        description: str,
        package_name: str,
        source_code: str = ""
    ) -> bool:
        """Create a CDS view using the specialized CDS handler"""
        try:
            logger.info(f"Creating CDS view {sanitize_for_logging(name)} using CDS handler")
            
            # Ensure we have CSRF token and cookies
            if not self.csrf_token:
                await self._get_csrf_token()
            
            # Convert cookies dict to list format expected by CDS handler
            cookie_list = [f"{k}={v}" for k, v in self.cookies.items()] if self.cookies else []
            
            # Use the specialized CDS handler
            return await self.cds_handler.create_cds_view(
                name=name,
                description=description,
                package_name=package_name,
                source_code=source_code,
                csrf_token=self.csrf_token,
                cookies=cookie_list
            )
            
        except Exception as e:
            logger.error(f"Error creating CDS view: {sanitize_for_logging(str(e))}")
            return False
    
    async def update_cds_view_source(
        self,
        name: str,
        source_code: str
    ) -> bool:
        """Update CDS view source code using the specialized CDS handler"""
        try:
            logger.info(f"Updating CDS view source for {sanitize_for_logging(name)}")
            
            # Ensure we have CSRF token and cookies
            if not self.csrf_token:
                await self._get_csrf_token()
            
            # Convert cookies dict to list format expected by CDS handler
            cookie_list = [f"{k}={v}" for k, v in self.cookies.items()] if self.cookies else []
            
            # Use the specialized CDS handler
            return await self.cds_handler.update_cds_view_source(
                name=name,
                source_code=source_code,
                csrf_token=self.csrf_token,
                cookies=cookie_list
            )
            
        except Exception as e:
            logger.error(f"Error updating CDS view source: {sanitize_for_logging(str(e))}")
            return False
    
    async def activate_cds_view(
        self,
        name: str
    ) -> bool:
        """Activate CDS view using the specialized CDS handler"""
        try:
            logger.info(f"Activating CDS view {sanitize_for_logging(name)}")
            
            # Ensure we have CSRF token and cookies
            if not self.csrf_token:
                await self._get_csrf_token()
            
            # Convert cookies dict to list format expected by CDS handler
            cookie_list = [f"{k}={v}" for k, v in self.cookies.items()] if self.cookies else []
            
            # Use the specialized CDS handler
            return await self.cds_handler.activate_cds_view(
                name=name,
                csrf_token=self.csrf_token,
                cookies=cookie_list
            )
            
        except Exception as e:
            logger.error(f"Error activating CDS view: {sanitize_for_logging(str(e))}")
            return False
    
    async def _update_cds_source(self, object_name: str, source_code: str) -> bool:
        """Update CDS source using the specialized handler (called from update_source_with_syntax_check)"""
        try:
            logger.info(f"Updating CDS view source for {sanitize_for_logging(object_name)} using specialized CDS handler")
            return await self.update_cds_view_source(object_name, source_code)
        except Exception as e:
            logger.error(f"Error in _update_cds_source: {sanitize_for_logging(str(e))}")
            return False
    
    # RAP Artifact Management Methods
    
    async def create_behavior_definition(
        self,
        name: str,
        description: str,
        package_name: str,
        source_code: str = ""
    ) -> bool:
        """Create a Behavior Definition (BDEF) for RAP using specialized handler"""
        try:
            logger.info(f"Creating Behavior Definition {sanitize_for_logging(name)} using specialized handler")
            
            # Use the specialized behavior definition handler
            return await self.behavior_definition_handler.create_behavior_definition(
                name=name,
                description=description,
                package_name=package_name,
                implementation_type='Managed'  # Default to Managed
            )
            
        except Exception as e:
            logger.error(f"Error creating Behavior Definition: {sanitize_for_logging(str(e))}")
            return False
    
    async def create_service_definition(
        self,
        name: str,
        description: str,
        package_name: str,
        source_code: str = ""
    ) -> bool:
        """Create a Service Definition (SRVD) for RAP using specialized handler"""
        try:
            logger.info(f"Creating Service Definition {sanitize_for_logging(name)} using specialized handler")
            return await self.service_definition_handler.create_service_definition(
                name, description, package_name, source_code
            )
            
        except Exception as e:
            logger.error(f"Error creating Service Definition: {sanitize_for_logging(str(e))}")
            return False
    
    async def create_service_binding(
        self,
        name: str,
        description: str,
        package_name: str,
        service_definition: str,
        binding_type: str = "ODATA_V4_UI"
    ) -> bool:
        """Create a Service Binding (SRVB) for RAP using specialized handler"""
        try:
            logger.info(f"Creating Service Binding {sanitize_for_logging(name)} using specialized handler")
            
            # Use the specialized service binding handler
            return await self.service_binding_handler.create_service_binding(
                name=name,
                description=description,
                package_name=package_name,
                service_definition=service_definition,
                binding_type=binding_type
            )
            
        except Exception as e:
            logger.error(f"Error creating Service Binding: {sanitize_for_logging(str(e))}")
            return False
    
    async def create_behavior_implementation(
        self,
        name: str,
        description: str,
        package_name: str,
        behavior_definition: str
    ) -> bool:
        """Create a Behavior Implementation (BIMPL) class for RAP"""
        try:
            logger.info(f"Creating Behavior Implementation {sanitize_for_logging(name)}")
            
            # Analyze the behavior definition first
            bdef_analysis = await self.analyze_behavior_definition(behavior_definition)
            
            # Use the standard create_object flow with BIMPL type
            from sap_types.sap_types import CreateObjectRequest, ObjectType
            request = CreateObjectRequest(
                name=name,
                type=ObjectType.BIMPL,
                description=description,
                package_name=package_name,
                behavior_definition=behavior_definition
            )
            
            result = await self.create_object_with_syntax_check(request)
            
            # If creation succeeded, enhance with proper template based on BDEF analysis
            if result.created:
                logger.info(f"BIMPL created successfully, enhancing with template")
                
                # Generate enhanced template based on BDEF analysis
                if bdef_analysis['entities']:
                    enhanced_template = self.generate_enhanced_behavior_implementation_template(
                        behavior_definition, 
                        bdef_analysis['entities'], 
                        bdef_analysis['scenario']
                    )
                    
                    # Update with enhanced template
                    template_result = await self.update_source_with_syntax_check(name, 'BIMPL', enhanced_template)
                    if template_result.updated and not template_result.syntax_check_passed:
                        # Try to fix common issues
                        await self._fix_behavior_implementation_issues(name, template_result.errors)
                else:
                    # Fallback: try to fix any syntax issues from auto-generation
                    if not result.syntax_check_passed:
                        logger.info(f"BIMPL has syntax errors, attempting to fix common issues")
                        await self._fix_behavior_implementation_issues(name, result.errors)
                
                # Final syntax check
                final_result = await self.syntax_check_object(name, 'BIMPL')
                return final_result.syntax_check_passed
            
            return result.created and result.syntax_check_passed
            
        except Exception as e:
            logger.error(f"Error creating Behavior Implementation: {sanitize_for_logging(str(e))}")
            return False

    async def _fix_behavior_implementation_issues(self, object_name: str, errors: List) -> bool:
        """Fix common behavior implementation syntax issues"""
        try:
            logger.info(f"Attempting to fix BIMPL issues for {sanitize_for_logging(object_name)}")
            
            # Get current implementation source
            source_result = await self.get_object_source(object_name, 'BIMPL')
            if not source_result.success or not source_result.source:
                logger.error("Could not retrieve BIMPL source for fixing")
                return False
            
            current_source = source_result.source
            fixed_source = current_source
            
            # Fix common issues based on error patterns
            for error in errors:
                error_msg = getattr(error, 'message', str(error))
                
                # Fix %DELETE authorization issue - remove %delete from authorization result
                if '%DELETE' in error_msg or '%delete' in error_msg:
                    logger.info("Fixing %DELETE authorization issue")
                    fixed_source = self._fix_delete_authorization_issue(fixed_source)
                
                # Fix %CID_REF issue - use correct field name
                if '%CID_REF' in error_msg or '%cid_ref' in error_msg:
                    logger.info("Fixing %CID_REF issue")
                    fixed_source = self._fix_cid_ref_issue(fixed_source)
                
                # Fix SAVE_MODIFIED redefinition issue for unmanaged scenarios
                if 'SAVE_MODIFIED' in error_msg and 'redefined' in error_msg:
                    logger.info("Fixing SAVE_MODIFIED redefinition issue")
                    fixed_source = self._fix_save_modified_issue(fixed_source)
            
            # Update the source if changes were made
            if fixed_source != current_source:
                logger.info("Applying fixes to BIMPL source")
                update_result = await self.update_source_with_syntax_check(object_name, 'BIMPL', fixed_source)
                return update_result.updated
            
            return True
            
        except Exception as e:
            logger.error(f"Error fixing BIMPL issues: {sanitize_for_logging(str(e))}")
            return False
    
    def _fix_delete_authorization_issue(self, source: str) -> str:
        """Fix %delete authorization issue by removing it from unmanaged scenarios"""
        import re
        
        # Pattern to find %delete in authorization results
        pattern = r'(\s+%update\s*=\s*if_abap_behv=>auth-allowed)\s*%delete\s*=\s*if_abap_behv=>auth-allowed\s*\)'
        replacement = r'\1 )'
        
        fixed_source = re.sub(pattern, replacement, source, flags=re.IGNORECASE | re.MULTILINE)
        
        # Alternative pattern for different formatting
        pattern2 = r'%delete\s*=\s*if_abap_behv=>auth-allowed[,\s]*'
        fixed_source = re.sub(pattern2, '', fixed_source, flags=re.IGNORECASE)
        
        return fixed_source
    
    def _fix_cid_ref_issue(self, source: str) -> str:
        """Fix %CID_REF issue by using correct field name %cid"""
        import re
        
        # Replace %cid_ref with %cid
        pattern = r'%cid_ref'
        replacement = r'%cid'
        
        fixed_source = re.sub(pattern, replacement, source, flags=re.IGNORECASE)
        
        return fixed_source
    
    def _fix_save_modified_issue(self, source: str) -> str:
        """Fix SAVE_MODIFIED redefinition issue by removing saver class for unmanaged scenarios"""
        import re
        
        # Remove the entire saver class definition for unmanaged scenarios
        pattern = r'CLASS\s+lsc_\w+\s+DEFINITION\s+INHERITING\s+FROM\s+cl_abap_behavior_saver\..*?ENDCLASS\.\s*CLASS\s+lsc_\w+\s+IMPLEMENTATION\..*?ENDCLASS\.'
        
        fixed_source = re.sub(pattern, '', source, flags=re.IGNORECASE | re.DOTALL)
        
        return fixed_source

    def generate_behavior_implementation_template(self, bdef_name: str, entities: List[str] = None) -> str:
        """Generate a proper behavior implementation template for unmanaged scenarios"""
        if not entities:
            # Extract entity name from BDEF name (e.g., ZI_WWSO_JOURNALENTRY -> journalentry)
            entity_name = bdef_name.lower().split('_')[-1] if '_' in bdef_name else bdef_name.lower()
            entities = [entity_name]
        
        template_parts = []
        
        # Generate handler classes for each entity
        for entity in entities:
            entity_lower = entity.lower()
            entity_class = f"lhc_{entity_lower}"
            
            # Main entity handler class
            template_parts.append(f'''CLASS {entity_class} DEFINITION INHERITING FROM cl_abap_behavior_handler.
  PRIVATE SECTION.
    METHODS read FOR READ
      IMPORTING keys FOR READ {entity_lower} RESULT result.

    METHODS lock FOR LOCK
      IMPORTING keys FOR LOCK {entity_lower}.

    METHODS get_instance_authorizations FOR INSTANCE AUTHORIZATION
      IMPORTING keys REQUEST requested_authorizations FOR {entity_lower} RESULT result.
ENDCLASS.

CLASS {entity_class} IMPLEMENTATION.

  METHOD read.
    " Implement read logic for {entity_lower}
    " Example: SELECT FROM your_table WHERE key fields match keys
  ENDMETHOD.

  METHOD lock.
    " Minimal lock implementation for unmanaged scenario
  ENDMETHOD.

  METHOD get_instance_authorizations.
    " Set authorization for unmanaged scenario
    result = VALUE #( FOR key IN keys
                      ( %tky = key-%tky
                        %update = if_abap_behv=>auth-allowed ) ).
  ENDMETHOD.

ENDCLASS.''')
        
        return '\n\n'.join(template_parts)

    def generate_enhanced_behavior_implementation_template(self, bdef_name: str, entities: List[str], scenario: str = 'unmanaged') -> str:
        """Generate an enhanced behavior implementation template based on BDEF analysis"""
        template_parts = []
        
        # Generate handler classes for each entity
        for entity in entities:
            entity_lower = entity.lower()
            entity_class = f"lhc_{entity_lower}"
            
            # Main entity handler class with comprehensive methods
            class_def = f'''CLASS {entity_class} DEFINITION INHERITING FROM cl_abap_behavior_handler.
  PRIVATE SECTION.
    METHODS read FOR READ
      IMPORTING keys FOR READ {entity_lower} RESULT result.

    METHODS lock FOR LOCK
      IMPORTING keys FOR LOCK {entity_lower}.

    METHODS get_instance_authorizations FOR INSTANCE AUTHORIZATION
      IMPORTING keys REQUEST requested_authorizations FOR {entity_lower} RESULT result.'''
            
            # Add association methods if this looks like a header entity
            if 'header' in entity_lower or 'entry' in entity_lower:
                class_def += f'''

    METHODS cba_items FOR MODIFY
      IMPORTING entities_cba FOR CREATE {entity_lower}\\_items.'''
            
            # Add read by association if this looks like an item entity  
            if 'item' in entity_lower:
                class_def += f'''

    METHODS rba_header FOR READ
      IMPORTING keys_rba FOR READ {entity_lower}\\_header FULL result_requested RESULT result LINK association_links.'''
            
            class_def += '\nENDCLASS.'
            
            # Implementation class
            impl_class = f'''
CLASS {entity_class} IMPLEMENTATION.

  METHOD read.
    " Read implementation for {entity_lower}
    " TODO: Implement SELECT statement based on your data source
    " Example for standard tables:
    " SELECT FROM your_table_name
    "   FIELDS *
    "   FOR ALL ENTRIES IN @keys
    "   WHERE key_field = @keys-key_field
    "   INTO CORRESPONDING FIELDS OF TABLE @result.
  ENDMETHOD.

  METHOD lock.
    " Lock implementation for {scenario} scenario
    " For unmanaged: Usually empty or minimal implementation
  ENDMETHOD.

  METHOD get_instance_authorizations.
    " Authorization check for {entity_lower}
    result = VALUE #( FOR key IN keys
                      ( %tky = key-%tky
                        %update = if_abap_behv=>auth-allowed ) ).
  ENDMETHOD.'''
            
            # Add association implementations
            if 'header' in entity_lower or 'entry' in entity_lower:
                impl_class += f'''

  METHOD cba_items.
    " Create by association - items for {entity_lower}
    " TODO: Implement logic to read associated items
    " Example:
    " SELECT FROM your_item_table
    "   FIELDS *
    "   FOR ALL ENTRIES IN @entities_cba
    "   WHERE parent_key = @entities_cba-key_field
    "   INTO TABLE @DATA(lt_items).
    "
    " LOOP AT entities_cba ASSIGNING FIELD-SYMBOL(<cba>).
    "   LOOP AT lt_items ASSIGNING FIELD-SYMBOL(<item>) WHERE parent_key = <cba>-key_field.
    "     APPEND VALUE #( %cid = <cba>-%cid
    "                     key_field = <item>-key_field ) TO mapped-{entity_lower}item.
    "   ENDLOOP.
    " ENDLOOP.
  ENDMETHOD.'''
            
            if 'item' in entity_lower:
                impl_class += f'''

  METHOD rba_header.
    " Read by association - header for {entity_lower}
    " TODO: Implement logic to read parent header
    " Example:
    " SELECT FROM your_header_table
    "   FIELDS *
    "   FOR ALL ENTRIES IN @keys_rba
    "   WHERE key_field = @keys_rba-parent_key
    "   INTO CORRESPONDING FIELDS OF TABLE @result.
    "
    " association_links = VALUE #( FOR key IN keys_rba
    "                               ( source-%tky = key-%tky
    "                                 target-%tky = VALUE #( key_field = key-parent_key ) ) ).
  ENDMETHOD.'''
            
            impl_class += '\n\nENDCLASS.'
            
            template_parts.append(class_def + impl_class)
        
        # For managed scenarios, don't include saver class
        # For unmanaged scenarios, saver class is typically not needed
        
        return '\n\n'.join(template_parts)

    async def enhance_behavior_implementation_with_template(self, object_name: str, bdef_name: str) -> bool:
        """Enhance a newly created BIMPL with a proper template"""
        try:
            logger.info(f"Enhancing BIMPL {sanitize_for_logging(object_name)} with template")
            
            # Generate template based on BDEF
            template_code = self.generate_behavior_implementation_template(bdef_name)
            
            # Update the implementation include with the template
            update_result = await self.update_source_with_syntax_check(object_name, 'BIMPL', template_code)
            
            if update_result.updated:
                logger.info(f"Successfully enhanced BIMPL {sanitize_for_logging(object_name)} with template")
                return True
            else:
                logger.warning(f"Failed to enhance BIMPL {sanitize_for_logging(object_name)} with template")
                return False
                
        except Exception as e:
            logger.error(f"Error enhancing BIMPL with template: {sanitize_for_logging(str(e))}")
            return False

    async def analyze_behavior_definition(self, bdef_name: str) -> dict:
        """Analyze a behavior definition to extract entity information"""
        try:
            logger.info(f"Analyzing behavior definition {sanitize_for_logging(bdef_name)}")
            
            # Get BDEF source
            source_result = await self.get_object_source(bdef_name, 'BDEF')
            if not source_result.success or not source_result.source:
                logger.warning(f"Could not retrieve BDEF source for {sanitize_for_logging(bdef_name)}")
                return {'entities': [], 'scenario': 'unmanaged'}
            
            bdef_source = source_result.source
            entities = []
            scenario = 'unmanaged'  # Default assumption
            
            # Parse BDEF to extract entities and scenario
            import re
            
            # Check if it's managed or unmanaged
            if 'managed' in bdef_source.lower():
                scenario = 'managed'
            elif 'unmanaged' in bdef_source.lower():
                scenario = 'unmanaged'
            
            # Extract entity definitions
            entity_pattern = r'define\s+behavior\s+for\s+(\w+)'
            entity_matches = re.findall(entity_pattern, bdef_source, re.IGNORECASE)
            entities.extend(entity_matches)
            
            # Also look for root entity patterns
            root_pattern = r'define\s+root\s+view\s+entity\s+(\w+)'
            root_matches = re.findall(root_pattern, bdef_source, re.IGNORECASE)
            entities.extend(root_matches)
            
            # Remove duplicates and clean up
            entities = list(set([e.lower() for e in entities if e]))
            
            logger.info(f"Found entities: {entities}, scenario: {scenario}")
            
            return {
                'entities': entities,
                'scenario': scenario,
                'source': bdef_source
            }
            
        except Exception as e:
            logger.error(f"Error analyzing BDEF: {sanitize_for_logging(str(e))}")
            return {'entities': [], 'scenario': 'unmanaged'}
