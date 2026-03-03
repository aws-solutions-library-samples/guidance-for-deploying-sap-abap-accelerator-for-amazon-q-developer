"""
Health check endpoints for the FastAPI application.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    timestamp: str
    version: str
    details: Dict[str, Any] = {}


def create_health_router() -> APIRouter:
    """Create health check router"""
    router = APIRouter(prefix="/health", tags=["health"])
    
    @router.get("/", response_model=HealthResponse)
    async def health_check():  # nosemgrep: useless-inner-function - FastAPI route handler registered via decorator
        """Basic health check endpoint"""
        from datetime import datetime
        
        return HealthResponse(
            status="healthy",
            timestamp=datetime.utcnow().isoformat(),
            version="1.0.0",
            details={
                "service": "ABAP-Accelerator MCP Server",
                "transport": "HTTP"
            }
        )
    
    @router.get("/ready", response_model=HealthResponse)
    async def readiness_check():  # nosemgrep: useless-inner-function - FastAPI route handler registered via decorator
        """Readiness check endpoint"""
        from datetime import datetime
        
        # Add more sophisticated readiness checks here
        # e.g., database connectivity, external service availability
        
        return HealthResponse(
            status="ready",
            timestamp=datetime.utcnow().isoformat(),
            version="1.0.0",
            details={
                "service": "ABAP-Accelerator MCP Server",
                "transport": "HTTP",
                "ready": True
            }
        )
    
    @router.get("/live", response_model=HealthResponse)
    async def liveness_check():  # nosemgrep: useless-inner-function - FastAPI route handler registered via decorator
        """Liveness check endpoint"""
        from datetime import datetime
        
        return HealthResponse(
            status="alive",
            timestamp=datetime.utcnow().isoformat(),
            version="1.0.0",
            details={
                "service": "ABAP-Accelerator MCP Server",
                "transport": "HTTP",
                "alive": True
            }
        )
    
    return router