#!/usr/bin/env python3
"""
Multi-System Context Manager
Handles multiple SAP system connections with isolated contexts
"""

import logging
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import asyncio
from threading import Lock

logger = logging.getLogger(__name__)

@dataclass
class SystemContext:
    """Represents a single SAP system context"""
    system_id: str
    keychain_identifier: str
    sap_client: Any = None
    tool_handlers: Any = None
    session_id: str = None
    authenticated_user: str = None
    last_used: datetime = None
    expires_at: datetime = None
    
    def is_expired(self) -> bool:
        """Check if the context has expired"""
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at
    
    def is_active(self) -> bool:
        """Check if the context is active and not expired"""
        return (self.sap_client is not None and 
                self.session_id is not None and 
                not self.is_expired())
    
    def update_last_used(self):
        """Update the last used timestamp"""
        self.last_used = datetime.now()

class MultiSystemManager:
    """
    Manages multiple SAP system contexts with proper isolation
    Each system gets its own authentication session and SAP client
    """
    
    def __init__(self):
        self._contexts: Dict[str, SystemContext] = {}
        self._lock = Lock()
        self._cleanup_interval = 3600  # 1 hour
        self._session_timeout = 28800  # 8 hours
        
    def _generate_system_id(self, keychain_identifier: str, mcp_session_id: str = None) -> str:
        """
        Generate a unique system ID based on keychain identifier and MCP session
        This ensures each Q Developer MCP server gets its own context
        """
        if mcp_session_id:
            return f"{keychain_identifier}_{mcp_session_id}"
        return keychain_identifier
    
    def get_context(self, keychain_identifier: str, mcp_session_id: str = None) -> Optional[SystemContext]:
        """Get existing context for a system"""
        system_id = self._generate_system_id(keychain_identifier, mcp_session_id)
        
        with self._lock:
            context = self._contexts.get(system_id)
            
            if context and context.is_expired():
                logger.info(f"Context for {system_id} has expired, removing")
                self._cleanup_context(system_id)
                return None
            
            if context and context.is_active():
                context.update_last_used()
                logger.info(f"Retrieved active context for {system_id}")
                return context
            
            return None
    
    def create_context(self, keychain_identifier: str, mcp_session_id: str = None) -> SystemContext:
        """Create a new context for a system"""
        system_id = self._generate_system_id(keychain_identifier, mcp_session_id)
        
        with self._lock:
            # Clean up any existing context for this system
            if system_id in self._contexts:
                self._cleanup_context(system_id)
            
            # Create new context
            context = SystemContext(
                system_id=system_id,
                keychain_identifier=keychain_identifier,
                last_used=datetime.now(),
                expires_at=datetime.now() + timedelta(seconds=self._session_timeout)
            )
            
            self._contexts[system_id] = context
            logger.info(f"Created new context for {system_id}")
            return context
    
    def update_context(self, context: SystemContext, sap_client: Any, tool_handlers: Any, 
                      session_id: str, authenticated_user: str):
        """Update context with authentication details"""
        with self._lock:
            context.sap_client = sap_client
            context.tool_handlers = tool_handlers
            context.session_id = session_id
            context.authenticated_user = authenticated_user
            context.update_last_used()
            
            logger.info(f"Updated context for {context.system_id} with user {authenticated_user}")
    
    def _cleanup_context(self, system_id: str):
        """Clean up a specific context"""
        if system_id in self._contexts:
            context = self._contexts[system_id]
            
            # Close SAP client if exists
            if context.sap_client and hasattr(context.sap_client, 'close'):
                try:
                    # Schedule cleanup for async clients
                    if hasattr(context.sap_client, 'session') and context.sap_client.session:
                        if not context.sap_client.session.closed:
                            asyncio.create_task(context.sap_client.close())
                except Exception as e:
                    logger.warning(f"Error closing SAP client for {system_id}: {e}")
            
            del self._contexts[system_id]
            logger.info(f"Cleaned up context for {system_id}")
    
    def cleanup_expired_contexts(self):
        """Clean up all expired contexts"""
        with self._lock:
            expired_systems = [
                system_id for system_id, context in self._contexts.items()
                if context.is_expired()
            ]
            
            for system_id in expired_systems:
                self._cleanup_context(system_id)
            
            if expired_systems:
                logger.info(f"Cleaned up {len(expired_systems)} expired contexts")
    
    def get_active_contexts(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all active contexts"""
        with self._lock:
            active_contexts = {}
            
            for system_id, context in self._contexts.items():
                if context.is_active():
                    active_contexts[system_id] = {
                        'keychain_identifier': context.keychain_identifier,
                        'authenticated_user': context.authenticated_user,
                        'last_used': context.last_used.isoformat() if context.last_used else None,
                        'expires_at': context.expires_at.isoformat() if context.expires_at else None,
                        'session_id': context.session_id
                    }
            
            return active_contexts
    
    def force_cleanup_all(self):
        """Force cleanup of all contexts (for shutdown)"""
        with self._lock:
            system_ids = list(self._contexts.keys())
            for system_id in system_ids:
                self._cleanup_context(system_id)
            
            logger.info(f"Force cleaned up all {len(system_ids)} contexts")

# Global instance
multi_system_manager = MultiSystemManager()