"""
Base authentication provider interface
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from ..types import AuthenticationResult, AuthenticationType, CredentialInfo


class AuthenticationProvider(ABC):
    """Abstract base class for all authentication providers"""
    
    @abstractmethod
    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate user with provided credentials
        
        Args:
            credentials: Dictionary containing authentication credentials
            
        Returns:
            AuthenticationResult with success status and session info
        """
        pass
    
    @abstractmethod
    async def validate_session(self, session_token: str) -> bool:
        """
        Validate existing session token
        
        Args:
            session_token: Session token to validate
            
        Returns:
            True if session is valid, False otherwise
        """
        pass
    
    @abstractmethod
    async def refresh_session(self, session_token: str) -> str:
        """
        Refresh session token if supported
        
        Args:
            session_token: Current session token
            
        Returns:
            New session token or None if refresh not supported
        """
        pass
    
    @abstractmethod
    def get_required_credentials(self) -> List[CredentialInfo]:
        """
        Get list of required credential fields
        
        Returns:
            List of CredentialInfo objects describing required fields
        """
        pass
    
    @abstractmethod
    def get_auth_type(self) -> AuthenticationType:
        """
        Get authentication type
        
        Returns:
            AuthenticationType enum value
        """
        pass
    
    @abstractmethod
    def get_display_name(self) -> str:
        """
        Get human-readable display name for this auth type
        
        Returns:
            Display name string
        """
        pass
    
    def supports_refresh(self) -> bool:
        """
        Check if this provider supports session refresh
        
        Returns:
            True if refresh is supported, False otherwise
        """
        return False
    
    def get_session_duration_hours(self) -> int:
        """
        Get session duration in hours
        
        Returns:
            Session duration in hours (default: 9)
        """
        return 9