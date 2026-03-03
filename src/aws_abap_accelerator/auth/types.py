"""
Authentication types and data structures
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional
from datetime import datetime


class AuthenticationType(Enum):
    """Supported authentication types"""
    BASIC = "basic"
    SAML_SSO = "saml_sso"
    CERTIFICATE = "certificate"
    REENTRANCE_TICKET = "reentrance_ticket"
    PRINCIPAL_PROPAGATION = "principal_propagation"


@dataclass
class AuthenticationResult:
    """Result of authentication attempt"""
    success: bool
    session_token: Optional[str] = None
    user_info: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    auth_type: Optional[AuthenticationType] = None


@dataclass
class UserAuthSession:
    """User authentication session information - stores tokens, not credentials"""
    session_id: str
    mcp_session_id: str
    session_name: str
    auth_type: AuthenticationType
    user_info: Dict[str, Any]
    sap_tokens: Dict[str, Any]  # Store SAP session tokens/cookies
    keychain_identifier: Optional[str]  # For token refresh
    created_at: datetime
    last_used: datetime
    expires_at: datetime
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.now() > self.expires_at
    
    def refresh_usage(self):
        """Update last used timestamp"""
        self.last_used = datetime.now()


@dataclass
class CredentialInfo:
    """Information about required credentials for auth type"""
    field_name: str
    description: str
    required: bool = True
    sensitive: bool = False
    example: Optional[str] = None