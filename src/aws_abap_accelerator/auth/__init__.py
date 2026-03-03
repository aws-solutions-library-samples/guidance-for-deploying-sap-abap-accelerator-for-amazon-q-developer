# Authentication module

from .types import AuthenticationType, AuthenticationResult, UserAuthSession, CredentialInfo
from .keychain_manager import keychain_manager
from .session_manager import auth_session_manager
from .sap_auth_helper import sap_auth_helper, get_sap_client_for_request

# Principal Propagation (optional - requires AWS configuration)
try:
    from .principal_propagation import principal_propagation_service
    from .principal_propagation_middleware import principal_propagation_middleware
    from .iam_identity_validator import iam_identity_validator
    PRINCIPAL_PROPAGATION_AVAILABLE = True
except ImportError:
    PRINCIPAL_PROPAGATION_AVAILABLE = False

__all__ = [
    'AuthenticationType',
    'AuthenticationResult', 
    'UserAuthSession',
    'CredentialInfo',
    'keychain_manager',
    'auth_session_manager',
    'sap_auth_helper',
    'get_sap_client_for_request',
    'PRINCIPAL_PROPAGATION_AVAILABLE'
]