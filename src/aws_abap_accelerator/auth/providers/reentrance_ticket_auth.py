"""
Reentrance Ticket Authentication Provider
For SAP systems that require browser-based authentication with reentrance tickets
"""

import uuid
import logging
import aiohttp
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from urllib.parse import urlencode, parse_qs, urlparse

from .base import AuthenticationProvider
from ..types import AuthenticationResult, AuthenticationType, CredentialInfo
from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)


class ReentranceTicketAuthProvider(AuthenticationProvider):
    """Reentrance ticket authentication provider for modern SAP systems"""
    
    def __init__(self):
        self.name = "Reentrance Ticket Authentication"
        self.description = "Browser-based authentication with reentrance tickets"
        self.pending_requests = {}  # request_id -> request_info
    
    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """
        Complete reentrance ticket authentication
        
        Expected credentials:
        - request_id: Ticket request ID from initiate_ticket_flow
        - ticket_response: Response from browser authentication
        OR
        - sap_host: SAP system host
        - sap_client: SAP client
        - sap_username: Username
        - sap_password: Password (for automatic ticket retrieval)
        """
        try:
            # Check if this is a ticket completion
            request_id = credentials.get('request_id')
            ticket_response = credentials.get('ticket_response')
            
            if request_id and ticket_response:
                return await self._complete_ticket_authentication(request_id, ticket_response)
            
            # Check if this is automatic ticket retrieval
            sap_host = credentials.get('sap_host')
            sap_username = credentials.get('sap_username')
            sap_password = credentials.get('sap_password')
            
            if sap_host and sap_username and sap_password:
                return await self._automatic_ticket_authentication(credentials)
            
            return AuthenticationResult(
                success=False,
                error_message="Either 'request_id' + 'ticket_response' or SAP credentials required",
                auth_type=self.get_auth_type()
            )
            
        except Exception as e:
            logger.error(f"Reentrance ticket authentication error: {sanitize_for_logging(str(e))}")
            return AuthenticationResult(
                success=False,
                error_message=f"Authentication failed: {str(e)}",
                auth_type=self.get_auth_type()
            )
    
    async def _automatic_ticket_authentication(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """
        Automatically obtain reentrance ticket using credentials
        This simulates the browser authentication flow programmatically
        """
        try:
            sap_host = credentials['sap_host']
            sap_client = credentials.get('sap_client', '100')
            sap_username = credentials['sap_username']
            sap_password = credentials['sap_password']
            
            logger.info(f"Attempting automatic reentrance ticket authentication for {sap_username}@{sap_host}")
            
            # Step 1: Get reentrance ticket URL
            ticket_url = await self._get_reentrance_ticket_url(sap_host, sap_client)
            if not ticket_url:
                return AuthenticationResult(
                    success=False,
                    error_message="Failed to get reentrance ticket URL",
                    auth_type=self.get_auth_type()
                )
            
            # Step 2: Perform authentication and get ticket
            ticket_data = await self._authenticate_and_get_ticket(
                ticket_url, sap_username, sap_password
            )
            
            if not ticket_data:
                return AuthenticationResult(
                    success=False,
                    error_message="Failed to obtain reentrance ticket",
                    auth_type=self.get_auth_type()
                )
            
            # Step 3: Create SAP client with ticket
            sap_client_instance = await self._create_sap_client_with_ticket(
                sap_host, sap_client, sap_username, ticket_data
            )
            
            if not sap_client_instance:
                return AuthenticationResult(
                    success=False,
                    error_message="Failed to create SAP client with reentrance ticket",
                    auth_type=self.get_auth_type()
                )
            
            # Generate session token
            session_token = str(uuid.uuid4())
            
            # Prepare user info
            user_info = {
                'username': sap_username,
                'sap_host': sap_host,
                'sap_client': sap_client,
                'auth_type': self.get_auth_type().value,
                'sap_client_instance': sap_client_instance,
                'ticket_data': ticket_data,
                'authenticated_at': datetime.now().isoformat()
            }
            
            logger.info(f"Successfully authenticated {sap_username}@{sap_host} using reentrance ticket")
            
            return AuthenticationResult(
                success=True,
                session_token=session_token,
                user_info=user_info,
                auth_type=self.get_auth_type()
            )
            
        except Exception as e:
            # Use warning level when re-raising - caller handles the error
            logger.warning(f"Automatic ticket authentication failed: {sanitize_for_logging(str(e))}")
            return AuthenticationResult(
                success=False,
                error_message=f"Automatic authentication failed: {str(e)}",
                auth_type=self.get_auth_type()
            )
    
    async def _get_reentrance_ticket_url(self, sap_host: str, sap_client: str) -> Optional[str]:
        """Get the reentrance ticket URL for the SAP system"""
        try:
            # For modern SAP systems, we can try direct authentication URLs
            base_url = f"https://{sap_host}"
            
            # Try different authentication endpoints that modern SAP systems use
            auth_endpoints = [
                # Direct SAP login (most common for BTP/Cloud systems)
                f"{base_url}/sap/bc/ui2/start_up",
                # ADT specific login
                f"{base_url}/sap/bc/adt/",
                # Fiori launchpad login
                f"{base_url}/sap/bc/ui2/flp",
                # Classic SAP GUI login
                f"{base_url}/sap/bc/gui/sap/its/webgui"
            ]
            
            # For now, return the most common one for BTP systems
            auth_url = f"{base_url}/sap/bc/ui2/start_up?sap-client={sap_client}"
            
            logger.info(f"Generated SAP authentication URL: {auth_url}")
            return auth_url
            
        except Exception as e:
            logger.error(f"Failed to generate auth URL: {sanitize_for_logging(str(e))}")
            return None
    
    async def _authenticate_and_get_ticket(self, ticket_url: str, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate with SAP system and obtain reentrance ticket
        This simulates the browser authentication flow
        """
        try:
            async with aiohttp.ClientSession() as session:
                # Step 1: Access ticket URL (this will redirect to login)
                async with session.get(ticket_url, allow_redirects=True) as response:
                    if response.status != 200:
                        logger.error(f"Failed to access ticket URL: {response.status}")
                        return None
                    
                    # Check if we got redirected to login page
                    final_url = str(response.url)
                    response_text = await response.text()
                    
                    # Look for login form or authentication parameters
                    if 'login' in final_url.lower() or 'auth' in final_url.lower():
                        logger.info("Redirected to login page, attempting authentication")
                        
                        # Step 2: Submit credentials (this is system-specific)
                        auth_data = {
                            'sap-user': username,
                            'sap-password': password,
                            'sap-client': '100'  # Default client
                        }
                        
                        async with session.post(final_url, data=auth_data, allow_redirects=True) as auth_response:
                            if auth_response.status == 200:
                                # Check if we got redirected back with ticket
                                auth_final_url = str(auth_response.url)
                                if 'adt/redirect' in auth_final_url:
                                    # Extract ticket from URL or response
                                    ticket_data = self._extract_ticket_from_response(auth_response, await auth_response.text())
                                    return ticket_data
                    
                    # If no redirect, check if ticket is directly available
                    ticket_data = self._extract_ticket_from_response(response, response_text)
                    return ticket_data
                    
        except Exception as e:
            logger.error(f"Authentication and ticket retrieval failed: {sanitize_for_logging(str(e))}")
            return None
    
    def _extract_ticket_from_response(self, response, response_text: str) -> Optional[Dict[str, Any]]:
        """Extract reentrance ticket from response"""
        try:
            # Check URL parameters for ticket
            url_params = parse_qs(urlparse(str(response.url)).query)
            
            # Look for common ticket parameter names
            ticket_params = ['ticket', 'reentranceticket', 'sap-ticket', 'auth-ticket']
            
            for param in ticket_params:
                if param in url_params:
                    ticket_value = url_params[param][0]
                    logger.info(f"Found reentrance ticket in URL parameter: {param}")
                    return {
                        'ticket': ticket_value,
                        'ticket_type': param,
                        'cookies': dict(response.cookies),
                        'headers': dict(response.headers)
                    }
            
            # Check response headers for ticket
            for header_name, header_value in response.headers.items():
                if 'ticket' in header_name.lower():
                    logger.info(f"Found reentrance ticket in header: {header_name}")
                    return {
                        'ticket': header_value,
                        'ticket_type': 'header',
                        'ticket_header': header_name,
                        'cookies': dict(response.cookies),
                        'headers': dict(response.headers)
                    }
            
            # Check cookies for session information
            if response.cookies:
                logger.info("Found session cookies, using as ticket data")
                return {
                    'ticket': 'session_cookies',
                    'ticket_type': 'cookies',
                    'cookies': dict(response.cookies),
                    'headers': dict(response.headers)
                }
            
            logger.warning("No reentrance ticket found in response")
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract ticket: {sanitize_for_logging(str(e))}")
            return None
    
    async def _create_sap_client_with_ticket(self, sap_host: str, sap_client: str, 
                                           username: str, ticket_data: Dict[str, Any]):
        """Create SAP client configured with reentrance ticket"""
        try:
            from sap.sap_client import SAPADTClient
            from sap_types.sap_types import SAPConnection
            
            # Create connection (password not needed with ticket)
            connection = SAPConnection(
                host=sap_host,
                client=sap_client,
                username=username,
                password="",  # Not needed with ticket
                language="EN",
                secure=True
            )
            
            # Create SAP client
            sap_client_instance = SAPADTClient(connection)
            
            # Configure client with ticket data
            if ticket_data.get('cookies'):
                sap_client_instance.cookies = ticket_data['cookies']
            
            # Set any special headers from ticket
            if ticket_data.get('headers'):
                # Store ticket headers for use in requests
                sap_client_instance.ticket_headers = ticket_data['headers']
            
            # Store ticket information
            sap_client_instance.reentrance_ticket = ticket_data.get('ticket')
            sap_client_instance.ticket_type = ticket_data.get('ticket_type')
            
            logger.info(f"Created SAP client with reentrance ticket for {username}@{sap_host}")
            return sap_client_instance
            
        except Exception as e:
            logger.error(f"Failed to create SAP client with ticket: {sanitize_for_logging(str(e))}")
            return None
    
    async def initiate_ticket_flow(self, sap_host: str, sap_client: str = "100") -> Dict[str, str]:
        """
        Initiate reentrance ticket authentication flow
        Returns URL for browser authentication
        """
        try:
            request_id = str(uuid.uuid4())
            
            # Store request info
            self.pending_requests[request_id] = {
                'sap_host': sap_host,
                'sap_client': sap_client,
                'initiated_at': datetime.now(),
                'status': 'pending',
                'expires_at': datetime.now() + timedelta(minutes=15)
            }
            
            # Generate reentrance ticket URL
            ticket_url = await self._get_reentrance_ticket_url(sap_host, sap_client)
            
            logger.info(f"Initiated reentrance ticket flow for {sap_host}, request_id: {request_id}")
            
            return {
                'ticket_url': ticket_url,
                'request_id': request_id,
                'expires_in_minutes': 15,
                'instructions': 'Open the ticket URL in your browser, complete authentication, then provide the response'
            }
            
        except Exception as e:
            # Use warning level when re-raising - caller handles the error
            logger.warning(f"Failed to initiate ticket flow: {sanitize_for_logging(str(e))}")
            raise Exception(f"Ticket flow initiation failed: {str(e)}")
    
    async def _complete_ticket_authentication(self, request_id: str, ticket_response: str) -> AuthenticationResult:
        """Complete authentication using ticket response from browser"""
        # Implementation for manual ticket completion
        # This would be used when user manually provides ticket from browser
        pass
    
    def get_required_credentials(self) -> List[CredentialInfo]:
        """Get required credential fields"""
        return [
            CredentialInfo(
                field_name="sap_host",
                description="SAP system hostname",
                required=True,
                example="system.company.com"
            ),
            CredentialInfo(
                field_name="sap_client",
                description="SAP client number",
                required=False,
                example="100"
            ),
            CredentialInfo(
                field_name="sap_username",
                description="SAP username",
                required=True,
                example="user@company.com"
            ),
            CredentialInfo(
                field_name="sap_password",
                description="SAP password",
                required=True,
                sensitive=True,
                example="password123"
            )
        ]
    
    def get_auth_type(self) -> AuthenticationType:
        """Get authentication type"""
        return AuthenticationType.REENTRANCE_TICKET
    
    def get_display_name(self) -> str:
        """Get display name"""
        return "Reentrance Ticket Authentication"
    
    def supports_refresh(self) -> bool:
        """Reentrance tickets typically need re-authentication"""
        return False
    
    async def validate_session(self, session_token: str) -> bool:
        """Validate reentrance ticket session token"""
        # Reentrance tickets are typically short-lived and tied to the session
        # For now, we'll assume they're valid if they exist
        return len(session_token) > 0
    
    async def refresh_session(self, session_token: str) -> str:
        """Refresh reentrance ticket session (typically requires re-authentication)"""
        # Reentrance tickets usually can't be refreshed - need new authentication
        # Return None to indicate refresh not supported
        return None