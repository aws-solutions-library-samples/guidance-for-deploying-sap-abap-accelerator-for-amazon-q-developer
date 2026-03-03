"""
Principal Propagation Middleware for ABAP-Accelerator MCP Server

This middleware intercepts requests and:
1. Extracts IAM Identity Center user identity
2. Maps to SAP username
3. Generates ephemeral certificate
4. Attaches credentials to request context
"""

import logging
import asyncio
from typing import Dict, Any, Optional, Callable
from datetime import datetime
from functools import wraps

from .iam_identity_validator import iam_identity_validator
from .principal_propagation import principal_propagation_service
from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)


class PrincipalPropagationContext:
    """Context object holding principal propagation data for a request"""
    
    def __init__(self):
        self.iam_identity: Optional[str] = None
        self.login_identifier: Optional[str] = None  # Pass-through for certificate CN
        self.sap_username: Optional[str] = None
        self.sap_system_id: Optional[str] = None
        self.cert_pem: Optional[str] = None
        self.key_pem: Optional[str] = None
        self.sap_host: Optional[str] = None
        self.sap_port: Optional[int] = None
        self.sap_client: Optional[str] = None
        self.validated: bool = False
        self.error: Optional[str] = None
        self.generated_at: Optional[datetime] = None


class PrincipalPropagationMiddleware:
    """
    Middleware for handling principal propagation in MCP tool calls.
    
    Usage:
        middleware = PrincipalPropagationMiddleware()
        await middleware.initialize()
        
        # For each tool call:
        context = await middleware.process_request(headers, sap_system_id)
        if context.validated:
            # Use context.cert_pem, context.key_pem for SAP authentication
    """
    
    def __init__(self):
        self._initialized = False
    
    async def initialize(self) -> bool:
        """Initialize the middleware and underlying services"""
        try:
            success = await principal_propagation_service.initialize()
            self._initialized = success
            logger.info(f"Principal Propagation Middleware initialized: {success}")
            return success
        except Exception as e:
            logger.error(f"Failed to initialize middleware: {sanitize_for_logging(str(e))}")
            return False
    
    async def process_request(
        self,
        headers: Dict[str, str],
        sap_system_id: str
    ) -> PrincipalPropagationContext:
        """
        Process a request and generate principal propagation context.
        
        Args:
            headers: HTTP request headers containing IAM identity
            sap_system_id: Target SAP system identifier
            
        Returns:
            PrincipalPropagationContext with credentials or error
        """
        context = PrincipalPropagationContext()
        context.sap_system_id = sap_system_id
        
        try:
            # Step 1: Extract and validate IAM identity
            identity = iam_identity_validator.extract_identity_from_headers(headers)
            if not identity:
                context.error = "No valid IAM identity found in request headers"
                logger.warning(context.error)
                return context
            
            context.iam_identity = identity.get('email')
            context.login_identifier = identity.get('login_identifier')  # Pass-through for certificate CN
            
            if not context.login_identifier:
                # Fallback to email if login_identifier not available
                context.login_identifier = context.iam_identity
            
            if not context.login_identifier:
                context.error = "IAM identity missing login identifier"
                logger.warning(context.error)
                return context
            
            # Step 2: Check if principal propagation service is ready
            if not principal_propagation_service.is_ready():
                context.error = "Principal propagation service not ready (CA not loaded)"
                logger.error(context.error)
                return context
            
            # Step 3: Get SAP credentials (generates certificate with login_identifier as CN)
            credentials = await principal_propagation_service.get_sap_credentials_for_request(
                iam_identity=context.iam_identity,
                login_identifier=context.login_identifier,  # Pass-through for certificate CN
                sap_system_id=sap_system_id
            )
            
            # Step 4: Populate context
            context.sap_username = credentials['sap_username']
            context.cert_pem = credentials['cert_pem']
            context.key_pem = credentials['key_pem']
            context.sap_host = credentials['sap_host']
            context.sap_port = credentials['sap_port']
            context.sap_client = credentials['sap_client']
            context.generated_at = datetime.utcnow()
            context.validated = True
            
            logger.info(
                f"Principal propagation successful: {context.iam_identity} -> "
                f"{context.sap_username}@{context.sap_system_id}"
            )
            
            return context
            
        except Exception as e:
            context.error = f"Principal propagation failed: {str(e)}"
            logger.error(f"Principal propagation error: {sanitize_for_logging(str(e))}")
            return context
    
    def is_ready(self) -> bool:
        """Check if middleware is ready"""
        return self._initialized and principal_propagation_service.is_ready()


# Global middleware instance
principal_propagation_middleware = PrincipalPropagationMiddleware()


def with_principal_propagation(sap_system_param: str = 'sap_system'):
    """
    Decorator for MCP tool functions to add principal propagation.
    
    Usage:
        @mcp.tool()
        @with_principal_propagation(sap_system_param='sap_system_id')
        async def my_tool(param1: str, sap_system_id: str, pp_context: PrincipalPropagationContext):
            # pp_context contains SAP credentials
            pass
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract headers from request context (implementation depends on framework)
            headers = kwargs.pop('_headers', {})
            sap_system_id = kwargs.get(sap_system_param)
            
            if not sap_system_id:
                raise ValueError(f"Missing required parameter: {sap_system_param}")
            
            # Process principal propagation
            context = await principal_propagation_middleware.process_request(
                headers=headers,
                sap_system_id=sap_system_id
            )
            
            if not context.validated:
                raise ValueError(f"Principal propagation failed: {context.error}")
            
            # Add context to kwargs
            kwargs['pp_context'] = context
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator
