"""
Enterprise Context Manager
Manages user sessions and SAP system contexts for multi-tenant MCP server
"""

import logging
import time
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)


@dataclass
class UserContext:
    """Represents a user's context for a specific SAP system"""
    user_id: str
    system_id: str
    session_id: str
    sap_credentials: Dict[str, str]
    sap_client: Optional[Any] = None
    tool_handlers: Optional[Any] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    request_count: int = 0
    is_authenticated: bool = False
    
    def update_last_used(self):
        """Update last used timestamp and increment request count"""
        self.last_used = datetime.now()
        self.request_count += 1
    
    def is_expired(self, timeout_minutes: int = 60) -> bool:
        """Check if context has expired"""
        return datetime.now() - self.last_used > timedelta(minutes=timeout_minutes)
    
    def get_context_key(self) -> str:
        """Get unique key for this context"""
        return f"{self.user_id}:{self.system_id}:{self.session_id}"


class EnterpriseContextManager:
    """
    Manages user contexts across multiple SAP systems
    Thread-safe context storage and retrieval
    """
    
    def __init__(self, session_timeout_minutes: int = 60):
        self.contexts: Dict[str, UserContext] = {}
        self.session_timeout = session_timeout_minutes
        self._lock = threading.RLock()
        logger.info(f"Enterprise Context Manager initialized with {session_timeout_minutes}min timeout")
    
    def extract_context_from_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Extract user and system context from request headers
        
        Expected headers:
        - x-user-id: User identifier
        - x-sap-system-id: SAP system identifier (e.g., 'S4H-DEV', 'BTP-PRD')
        - x-session-id: Session identifier (optional, generated if missing)
        - x-team-id: Team identifier (optional)
        """
        context = {
            'user_id': headers.get('x-user-id', 'anonymous'),
            'system_id': headers.get('x-sap-system-id', 'default'),
            'session_id': headers.get('x-session-id', f"session_{int(time.time())}"),
            'team_id': headers.get('x-team-id', 'default'),
            'request_id': headers.get('x-request-id', f"req_{int(time.time())}")
        }
        
        logger.debug(f"Extracted context: user={context['user_id']}, system={context['system_id']}")
        return context
    
    def get_or_create_context(self, user_id: str, system_id: str, session_id: str, 
                            sap_credentials: Optional[Dict[str, str]] = None) -> UserContext:
        """
        Get existing context or create new one
        """
        context_key = f"{user_id}:{system_id}:{session_id}"
        
        with self._lock:
            # Check if context exists and is not expired
            if context_key in self.contexts:
                context = self.contexts[context_key]
                if not context.is_expired(self.session_timeout):
                    context.update_last_used()
                    logger.debug(f"Retrieved existing context: {context_key}")
                    return context
                else:
                    # Context expired, remove it
                    logger.info(f"Context expired, removing: {context_key}")
                    del self.contexts[context_key]
            
            # Create new context
            new_context = UserContext(
                user_id=user_id,
                system_id=system_id,
                session_id=session_id,
                sap_credentials=sap_credentials or {}
            )
            
            self.contexts[context_key] = new_context
            logger.info(f"Created new context: {context_key}")
            return new_context
    
    def update_context_credentials(self, context: UserContext, sap_credentials: Dict[str, str]):
        """Update SAP credentials for a context"""
        with self._lock:
            context.sap_credentials = sap_credentials
            logger.debug(f"Updated credentials for context: {context.get_context_key()}")
    
    def update_context_clients(self, context: UserContext, sap_client: Any, tool_handlers: Any):
        """Update SAP client and tool handlers for a context"""
        with self._lock:
            context.sap_client = sap_client
            context.tool_handlers = tool_handlers
            # nosemgrep: is-function-without-parentheses - is_authenticated is a boolean attribute in UserContext dataclass
            context.is_authenticated = True
            logger.debug(f"Updated clients for context: {context.get_context_key()}")
    
    def get_context(self, user_id: str, system_id: str, session_id: str) -> Optional[UserContext]:
        """Get existing context if it exists and is not expired"""
        context_key = f"{user_id}:{system_id}:{session_id}"
        
        with self._lock:
            if context_key in self.contexts:
                context = self.contexts[context_key]
                if not context.is_expired(self.session_timeout):
                    context.update_last_used()
                    return context
                else:
                    # Context expired, remove it
                    del self.contexts[context_key]
                    logger.info(f"Removed expired context: {context_key}")
            
            return None
    
    def remove_context(self, user_id: str, system_id: str, session_id: str) -> bool:
        """Remove a specific context"""
        context_key = f"{user_id}:{system_id}:{session_id}"
        
        with self._lock:
            if context_key in self.contexts:
                del self.contexts[context_key]
                logger.info(f"Removed context: {context_key}")
                return True
            return False
    
    def cleanup_expired_contexts(self):
        """Remove all expired contexts"""
        with self._lock:
            expired_keys = []
            for key, context in self.contexts.items():
                if context.is_expired(self.session_timeout):
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.contexts[key]
                logger.info(f"Cleaned up expired context: {key}")
            
            if expired_keys:
                logger.info(f"Cleaned up {len(expired_keys)} expired contexts")
    
    def get_active_contexts(self) -> Dict[str, Dict[str, Any]]:
        """Get summary of all active contexts"""
        with self._lock:
            active_contexts = {}
            for key, context in self.contexts.items():
                if not context.is_expired(self.session_timeout):
                    # nosemgrep: is-function-without-parentheses - is_authenticated is a boolean attribute in UserContext dataclass
                    active_contexts[key] = {
                        'user_id': context.user_id,
                        'system_id': context.system_id,
                        'session_id': context.session_id,
                        'created_at': context.created_at.isoformat(),
                        'last_used': context.last_used.isoformat(),
                        'request_count': context.request_count,
                        'is_authenticated': context.is_authenticated
                    }
            
            return active_contexts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get context manager statistics"""
        with self._lock:
            total_contexts = len(self.contexts)
            active_contexts = len([c for c in self.contexts.values() 
                                 if not c.is_expired(self.session_timeout)])
            # nosemgrep: is-function-without-parentheses - is_authenticated is a boolean attribute in UserContext dataclass
            authenticated_contexts = len([c for c in self.contexts.values() 
                                        if c.is_authenticated and not c.is_expired(self.session_timeout)])
            
            return {
                'total_contexts': total_contexts,
                'active_contexts': active_contexts,
                'authenticated_contexts': authenticated_contexts,
                'session_timeout_minutes': self.session_timeout
            }


# Global context manager instance
enterprise_context_manager = EnterpriseContextManager()