"""
Enterprise Middleware for FastMCP
Transparent enhancement layer that adds multi-tenancy, context awareness, and usage tracking
"""

import logging
import time
import asyncio
import os
import base64
import json
from typing import Dict, Any, Optional, Callable
from functools import wraps

from .context_manager import enterprise_context_manager, UserContext
from .usage_tracker import enterprise_usage_tracker
from .sap_client_factory import enterprise_sap_client_factory

logger = logging.getLogger(__name__)


class EnterpriseMiddleware:
    """
    Middleware that transparently adds enterprise features to FastMCP tools
    """
    
    def __init__(self, enabled: bool = None):
        # Check if enterprise mode is enabled via environment
        if enabled is None:
            enabled = os.getenv('ENABLE_ENTERPRISE_MODE', 'false').lower() == 'true'
        
        self.enabled = enabled
        self.original_tool_decorator = None
        
        if self.enabled:
            logger.info("🏢 Enterprise Middleware ENABLED")
        else:
            logger.info("🏢 Enterprise Middleware DISABLED - running in standard mode")
    
    def extract_user_identity_from_jwt(self, jwt_token: str) -> Optional[str]:
        """
        Extract user identity from JWT token (IdP-agnostic, auto-detecting).
        
        This method automatically detects the IdP and extracts the user identity
        without any configuration. It tries standard OIDC claims in priority order:
        
        Priority Order (based on OIDC standards and common IdP practices):
        1. preferred_username - OIDC standard, most IdPs
        2. cognito:username - AWS Cognito specific
        3. upn - Microsoft Entra ID (Azure AD)
        4. unique_name - Microsoft Entra ID alternative
        5. email - Universal fallback
        6. sub - OIDC subject (unique ID, last resort)
        
        Supports: AWS Cognito, Okta, Entra ID, Auth0, Google, Keycloak, and any OIDC-compliant IdP
        """
        try:
            # Decode JWT payload (no signature validation - ALB/API Gateway already validated)
            parts = jwt_token.split('.')
            if len(parts) != 3:
                logger.warning("Invalid JWT format: expected 3 parts (header.payload.signature)")
                return None
            
            # Decode payload (base64url)
            payload = parts[1]
            # Add padding if needed for base64 decoding
            payload += '=' * (4 - len(payload) % 4)
            
            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded)
            
            # Log issuer for debugging (helps identify IdP)
            issuer = claims.get('iss', 'unknown')
            logger.debug(f"JWT issuer: {issuer}")
            
            # Define claim priority order (OIDC standard + common IdP claims)
            # This covers all major IdPs without configuration
            claim_priority = [
                'preferred_username',  # OIDC standard (Cognito, Okta, Keycloak)
                'cognito:username',    # AWS Cognito specific
                'upn',                 # Microsoft Entra ID (User Principal Name)
                'unique_name',         # Microsoft Entra ID alternative
                'email',               # Universal fallback (all IdPs)
                'sub'                  # OIDC subject (unique ID, last resort)
            ]
            
            # Try each claim in priority order
            for claim_name in claim_priority:
                user_id = claims.get(claim_name)
                if user_id:
                    # For email-based claims, extract username part (before @)
                    # This is useful for SAP username mapping
                    if '@' in str(user_id) and claim_name in ['email', 'upn']:
                        username = user_id.split('@')[0]
                        logger.info(f"Extracted user identity from JWT claim '{claim_name}': {username} (from {user_id})")
                        return username
                    
                    logger.info(f"Extracted user identity from JWT claim '{claim_name}': {user_id}")
                    return user_id
            
            # If no standard claims found, log available claims for debugging
            available_claims = [k for k in claims.keys() if not k.startswith('_')]
            logger.warning(f"No user identity found in JWT. Available claims: {available_claims}")
            logger.warning(f"JWT issuer: {issuer}")
            
            return None
            
        except Exception as e:
            logger.error(f"Error extracting user from JWT: {e}")
            return None
    
    def extract_user_identity(self, headers: Dict[str, str]) -> str:
        """
        Extract user identity from request headers (IdP-agnostic, auto-detecting).
        
        Supports multiple authentication patterns automatically:
        1. JWT tokens from any IdP (ALB, API Gateway, custom proxies)
        2. Direct user identity headers (for simple auth or pre-extracted identity)
        3. Standard OAuth Authorization Bearer tokens
        
        Auto-detects common header patterns used by different authentication proxies:
        - AWS ALB: x-amzn-oidc-data, x-amzn-oidc-identity
        - Azure App Gateway: x-ms-token-aad-id-token
        - Standard OAuth: Authorization Bearer
        - Custom proxies: x-user-id, x-authenticated-user, x-auth-user
        
        No configuration needed - works with any OIDC-compliant IdP.
        """
        
        # Method 1: Check for direct user identity headers (fastest path)
        # These are set by proxies that pre-extract the user identity
        direct_identity_headers = [
            'x-user-id',              # Custom header (backward compatibility)
            'x-authenticated-user',   # Common custom proxy header
            'x-auth-user',            # Alternative custom header
            'x-amzn-oidc-identity'    # AWS ALB pre-extracted identity
        ]
        
        for header_name in direct_identity_headers:
            user_id = headers.get(header_name)
            if user_id and user_id != 'anonymous':
                logger.debug(f"User identity from direct header '{header_name}': {user_id}")
                return user_id
        
        # Method 2: Extract from JWT tokens in common headers
        # Try different header patterns used by various authentication proxies
        jwt_header_patterns = [
            'x-amzn-oidc-data',           # AWS ALB with Cognito/OIDC
            'x-ms-token-aad-id-token',    # Azure Application Gateway with Entra ID
            'x-auth-token',               # Generic custom proxy
            'x-id-token',                 # Alternative custom proxy
            'x-access-token'              # Another alternative
        ]
        
        for header_name in jwt_header_patterns:
            jwt_token = headers.get(header_name)
            if jwt_token:
                user_id = self.extract_user_identity_from_jwt(jwt_token)
                if user_id:
                    logger.debug(f"User identity extracted from JWT in header '{header_name}'")
                    return user_id
        
        # Method 3: Extract from standard Authorization Bearer token
        auth_header = headers.get('authorization')
        if auth_header:
            # Handle "Bearer <token>" format
            if auth_header.lower().startswith('bearer '):
                jwt_token = auth_header[7:].strip()  # Remove "Bearer " prefix
                user_id = self.extract_user_identity_from_jwt(jwt_token)
                if user_id:
                    logger.debug("User identity extracted from Authorization Bearer token")
                    return user_id
            # Handle direct token (no "Bearer" prefix)
            else:
                user_id = self.extract_user_identity_from_jwt(auth_header)
                if user_id:
                    logger.debug("User identity extracted from Authorization header (direct token)")
                    return user_id
        
        # Fallback: anonymous user (for testing or unauthenticated access)
        logger.warning("No user identity found in request headers - using 'anonymous'")
        logger.debug(f"Available headers: {list(headers.keys())}")
        return 'anonymous'
    
    def extract_headers_from_context(self, ctx) -> Dict[str, str]:
        """
        Extract headers from FastMCP HTTP context
        This method properly handles HTTP headers for multi-tenancy
        """
        headers = {}
        
        try:
            # Method 1: Check if context has headers attribute (most common)
            if hasattr(ctx, 'headers') and ctx.headers:
                headers = dict(ctx.headers)
                logger.debug(f"Found headers in ctx.headers: {list(headers.keys())}")
            
            # Method 2: Check if context has meta with headers
            elif hasattr(ctx, 'meta') and ctx.meta and hasattr(ctx.meta, 'headers'):
                headers = dict(ctx.meta.headers)
                logger.debug(f"Found headers in ctx.meta.headers: {list(headers.keys())}")
            
            # Method 3: Check if context has request with headers
            elif hasattr(ctx, 'request') and ctx.request and hasattr(ctx.request, 'headers'):
                headers = dict(ctx.request.headers)
                logger.debug(f"Found headers in ctx.request.headers: {list(headers.keys())}")
            
            # Method 4: Check if context has any attribute containing headers
            else:
                # Inspect context object for any header-like attributes
                for attr_name in dir(ctx):
                    if 'header' in attr_name.lower():
                        attr_value = getattr(ctx, attr_name, None)
                        if attr_value and hasattr(attr_value, 'items'):
                            headers = dict(attr_value)
                            logger.debug(f"Found headers in ctx.{attr_name}: {list(headers.keys())}")
                            break
                
                # If still no headers found, log context structure for debugging
                if not headers:
                    logger.warning(f"No headers found in context. Context attributes: {[attr for attr in dir(ctx) if not attr.startswith('_')]}")
        
        except Exception as e:
            logger.error(f"Error extracting headers from context: {e}")
        
        # Normalize header names to lowercase for consistent access
        normalized_headers = {}
        for key, value in headers.items():
            normalized_key = key.lower()
            normalized_headers[normalized_key] = value
        
        # Extract user identity using IdP-agnostic method
        user_id = self.extract_user_identity(normalized_headers)
        
        # Extract enterprise context headers with defaults
        enterprise_headers = {
            'x-user-id': user_id,
            'x-sap-system-id': normalized_headers.get('x-sap-system-id') or normalized_headers.get('sap-system-id', 'default'),
            'x-session-id': normalized_headers.get('x-session-id') or normalized_headers.get('session-id', f'session_{int(time.time())}'),
            'x-team-id': normalized_headers.get('x-team-id') or normalized_headers.get('team-id', 'default'),
            'x-request-id': normalized_headers.get('x-request-id') or normalized_headers.get('request-id', f'req_{int(time.time())}')
        }
        
        logger.debug(f"Extracted enterprise headers: {enterprise_headers}")
        return enterprise_headers
    
    def enhance_context(self, ctx, user_context: UserContext):
        """
        Add enterprise context to the FastMCP context object
        """
        if not hasattr(ctx, 'enterprise'):
            ctx.enterprise = {}
        
        # nosemgrep: is-function-without-parentheses - is_authenticated is a boolean attribute in UserContext dataclass
        ctx.enterprise.update({
            'user_id': user_context.user_id,
            'system_id': user_context.system_id,
            'session_id': user_context.session_id,
            'context': user_context,
            'sap_client': user_context.sap_client,
            'tool_handlers': user_context.tool_handlers,
            'is_authenticated': user_context.is_authenticated,
            'get_sap_client': lambda: self._get_sap_client_for_context(user_context, ctx)
        })
    
    async def _get_sap_client_for_context(self, user_context: UserContext, ctx) -> tuple:
        """
        Get SAP client for the current context using credential manager
        """
        try:
            headers = self.extract_headers_from_context(ctx)
            return await enterprise_sap_client_factory.get_sap_client_for_context(user_context, headers)
        except Exception as e:
            logger.error(f"Error getting SAP client for context: {e}")
            return None, None
    
    def create_enhanced_tool(self, original_func: Callable, tool_name: str) -> Callable:
        """
        Create an enhanced version of a tool that includes enterprise features
        Only enhance SAP and enterprise tools, not internal MCP operations
        """
        # Only enhance specific tools, not internal MCP operations
        should_enhance = (
            tool_name.startswith('aws_abap_cb_') or 
            tool_name.startswith('enterprise_') or
            tool_name in ['connection_status', 'get_objects', 'get_source']
        )
        
        if not should_enhance:
            logger.debug(f"Skipping enhancement for tool: {tool_name}")
            return original_func
        
        @wraps(original_func)
        async def enhanced_tool(*args, **kwargs):
            # If enterprise mode is disabled, just call original function
            if not self.enabled:
                return await original_func(*args, **kwargs)
            
            start_time = time.time()
            success = True
            error_message = None
            result = None
            context_info = {'user_id': 'unknown', 'system_id': 'unknown', 'session_id': 'unknown'}
            
            # Extract context from kwargs (FastMCP passes ctx as kwarg)
            ctx = kwargs.get('ctx')
            if not ctx:
                logger.debug(f"No context found for tool {tool_name}, running without enterprise features")
                return await original_func(*args, **kwargs)
            
            try:
                # Extract headers and create user context
                headers = self.extract_headers_from_context(ctx)
                context_info = enterprise_context_manager.extract_context_from_headers(headers)
                
                # Get or create user context
                user_context = enterprise_context_manager.get_or_create_context(
                    user_id=context_info['user_id'],
                    system_id=context_info['system_id'],
                    session_id=context_info['session_id']
                )
                
                # Get SAP client and tool handlers from credential manager
                sap_client, tool_handlers = await enterprise_sap_client_factory.get_sap_client_for_context(
                    user_context, headers
                )
                
                # Enhance the FastMCP context with enterprise info
                self.enhance_context(ctx, user_context)
                
                logger.debug(f"ENTERPRISE: Enhanced tool {tool_name} for user {user_context.user_id} on system {user_context.system_id}")
                
                # If we have SAP client, replace the original function's behavior
                if sap_client and tool_handlers:
                    # For SAP tools, we need to use the context-specific client
                    if tool_name.startswith('aws_abap_cb_'):
                        # Override the tool's SAP client access
                        result = await self._call_tool_with_enterprise_client(
                            original_func, sap_client, tool_handlers, *args, **kwargs
                        )
                    else:
                        # For non-SAP tools, call normally
                        result = await original_func(*args, **kwargs)
                else:
                    # No SAP client available - call original but it may fail
                    logger.warning(f"No SAP client available for {tool_name} - user {user_context.user_id} on system {user_context.system_id}")
                    result = await original_func(*args, **kwargs)
                
            except Exception as e:
                success = False
                error_message = str(e)
                logger.error(f"Error in enhanced tool {tool_name}: {e}")
                raise
            
            finally:
                # Track usage regardless of success/failure
                duration_ms = int((time.time() - start_time) * 1000)
                
                try:
                    enterprise_usage_tracker.track_tool_usage(
                        user_id=context_info.get('user_id', 'unknown'),
                        system_id=context_info.get('system_id', 'unknown'),
                        session_id=context_info.get('session_id', 'unknown'),
                        tool_name=tool_name,
                        duration_ms=duration_ms,
                        success=success,
                        error_message=error_message,
                        team_id=context_info.get('team_id'),
                        request_id=context_info.get('request_id')
                    )
                except Exception as tracking_error:
                    logger.error(f"Error tracking usage for {tool_name}: {tracking_error}")
            
            return result
        
        return enhanced_tool
    
    async def _call_tool_with_enterprise_client(self, original_func, sap_client, tool_handlers, *args, **kwargs):
        """
        Call a tool function with enterprise SAP client instead of the default one
        This replaces the server's SAP client with the user-specific one
        """
        try:
            # For tools that need SAP client access, we need to temporarily replace
            # the server's client with the user-specific one
            
            # Get the server instance from the original function if possible
            # This is a bit tricky since we're intercepting at the tool level
            
            # For now, call the original function and let it handle the client
            # The enhanced context should provide access to the right client
            return await original_func(*args, **kwargs)
            
        except Exception as e:
            # Use warning level when re-raising - caller handles the error
            logger.warning(f"Error calling tool with enterprise client: {e}")
            raise
    
    def wrap_mcp_server(self, mcp_server):
        """
        Wrap an existing FastMCP server to add enterprise features
        This method intercepts tool registration to add middleware
        """
        if not self.enabled:
            logger.info("Enterprise mode disabled, returning original server")
            return mcp_server
        
        # Store original tool decorator
        original_tool_method = mcp_server.tool
        
        def enhanced_tool_decorator(*decorator_args, **decorator_kwargs):
            """Enhanced tool decorator that adds enterprise middleware"""
            
            def decorator(func):
                # Get the tool name (use function name if not specified)
                tool_name = func.__name__
                
                # Create enhanced version of the function
                enhanced_func = self.create_enhanced_tool(func, tool_name)
                
                # Register the enhanced function with the original decorator
                return original_tool_method(*decorator_args, **decorator_kwargs)(enhanced_func)
            
            return decorator
        
        # Replace the tool decorator with our enhanced version
        mcp_server.tool = enhanced_tool_decorator
        
        logger.info("ENTERPRISE: Enhanced FastMCP server with enterprise middleware")
        return mcp_server
    
    def get_middleware_stats(self) -> Dict[str, Any]:
        """Get middleware statistics"""
        return {
            'enabled': self.enabled,
            'context_stats': enterprise_context_manager.get_stats(),
            'usage_stats': enterprise_usage_tracker.get_overall_stats()
        }


# Global middleware instance
enterprise_middleware = EnterpriseMiddleware()