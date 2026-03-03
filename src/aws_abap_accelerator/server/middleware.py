"""
Middleware components for the FastAPI application.
"""

import uuid
import time
import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Middleware to add correlation ID to requests"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate or extract correlation ID
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        
        # Add to request state
        request.state.correlation_id = correlation_id
        
        # Process request
        response = await call_next(request)
        
        # Add correlation ID to response headers
        response.headers["X-Correlation-ID"] = correlation_id
        
        return response


class ShutdownMiddleware(BaseHTTPMiddleware):
    """Middleware to handle graceful shutdown"""
    
    def __init__(self, app, server):
        super().__init__(app)
        self.server = server
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check if server is shutting down
        if self.server.is_shutting_down():
            return Response(
                content="Server is shutting down",
                status_code=503,
                headers={"Retry-After": "30"}
            )
        
        return await call_next(request)


class SAPKeychainMiddleware(BaseHTTPMiddleware):
    """Middleware to capture SAP keychain identifier from headers"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Extract SAP keychain identifier from headers
        keychain_id = request.headers.get("X-SAP-Keychain-Identifier")
        
        if keychain_id:
            # Store in request state for use by authentication tools
            request.state.sap_keychain_identifier = keychain_id
            
            # Also set as environment variable for compatibility
            import os
            os.environ['X_SAP_KEYCHAIN_IDENTIFIER'] = keychain_id
            
            logger.info(f"SAP keychain identifier from headers: {keychain_id}")
        
        return await call_next(request)


class MCPAcceptHeaderMiddleware(BaseHTTPMiddleware):
    """Middleware to ensure MCP clients have proper Accept header for SSE"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check if this is an MCP request (has MCP protocol version header)
        is_mcp_request = (
            request.headers.get("mcp-protocol-version") or
            request.path.startswith("/mcp") or
            request.path.startswith("/sse")
        )
        
        if is_mcp_request:
            # Get current Accept header
            accept_header = request.headers.get("accept", "")
            
            # If Accept header doesn't include text/event-stream, add it
            if "text/event-stream" not in accept_header:
                # Create mutable headers
                mutable_headers = dict(request.headers)
                
                # Add or update Accept header
                if accept_header:
                    mutable_headers["accept"] = f"{accept_header}, text/event-stream"
                else:
                    mutable_headers["accept"] = "text/event-stream, application/json"
                
                # Update request headers
                request._headers = mutable_headers
                
                logger.debug(f"Added text/event-stream to Accept header for MCP request: {request.path}")
        
        return await call_next(request)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        # Log request
        logger.info(
            f"Request: {request.method} {request.url.path}",
            extra={
                "method": request.method,
                "path": request.url.path,
                "query_params": str(request.query_params),
                "correlation_id": getattr(request.state, "correlation_id", None)
            }
        )
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Log response
        logger.info(
            f"Response: {response.status_code} in {duration:.3f}s",
            extra={
                "status_code": response.status_code,
                "duration": duration,
                "correlation_id": getattr(request.state, "correlation_id", None)
            }
        )
        
        return response