"""
Certificate-based authentication provider
"""

import uuid
import logging
from typing import Dict, Any, List
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .base import AuthenticationProvider
from ..types import AuthenticationResult, AuthenticationType, CredentialInfo
from sap_types.sap_types import SAPConnection, AuthType
from sap.sap_client import SAPADTClient
from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)


class CertificateAuthProvider(AuthenticationProvider):
    """Certificate-based authentication provider"""
    
    def __init__(self):
        self.name = "Certificate Authentication"
        self.description = "X.509 certificate-based authentication"
    
    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate using X.509 certificate
        
        Expected credentials:
        - certificate_pem: X.509 certificate in PEM format
        - private_key_pem: Private key in PEM format (optional if cert includes key)
        - sap_host: SAP system hostname
        - sap_client: SAP client number
        """
        try:
            # Validate required fields
            required_fields = ['certificate_pem', 'sap_host', 'sap_client']
            for field in required_fields:
                if field not in credentials:
                    return AuthenticationResult(
                        success=False,
                        error_message=f"Missing required field: {field}",
                        auth_type=self.get_auth_type()
                    )
            
            cert_pem = credentials['certificate_pem']
            private_key_pem = credentials.get('private_key_pem')
            
            # Validate certificate
            cert_info = await self._validate_certificate(cert_pem)
            if not cert_info:
                return AuthenticationResult(
                    success=False,
                    error_message="Invalid or expired certificate",
                    auth_type=self.get_auth_type()
                )
            
            # Create SAP connection using certificate
            sap_client = await self._create_sap_cert_connection(credentials, cert_info)
            if not sap_client:
                return AuthenticationResult(
                    success=False,
                    error_message="Failed to create SAP connection with certificate",
                    auth_type=self.get_auth_type()
                )
            
            # Generate session token
            session_token = str(uuid.uuid4())
            
            # Prepare user info
            user_info = {
                'username': cert_info['subject_cn'],
                'certificate_subject': cert_info['subject'],
                'certificate_issuer': cert_info['issuer'],
                'certificate_serial': cert_info['serial_number'],
                'certificate_expires': cert_info['not_valid_after'],
                'sap_host': credentials['sap_host'],
                'sap_client': credentials['sap_client'],
                'auth_type': self.get_auth_type().value,
                'sap_client_instance': sap_client,
                'authenticated_at': datetime.now().isoformat()
            }
            
            logger.info(f"Successfully authenticated {cert_info['subject_cn']} via certificate")
            
            return AuthenticationResult(
                success=True,
                session_token=session_token,
                user_info=user_info,
                auth_type=self.get_auth_type()
            )
            
        except Exception as e:
            logger.error(f"Certificate authentication error: {sanitize_for_logging(str(e))}")
            return AuthenticationResult(
                success=False,
                error_message=f"Certificate authentication failed: {str(e)}",
                auth_type=self.get_auth_type()
            )
    
    async def _validate_certificate(self, cert_pem: str) -> Dict[str, Any]:
        """
        Validate X.509 certificate and extract information
        
        Args:
            cert_pem: Certificate in PEM format
            
        Returns:
            Dictionary with certificate information or None if invalid
        """
        try:
            # Parse certificate
            cert_bytes = cert_pem.encode('utf-8')
            certificate = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            
            # Check if certificate is currently valid
            now = datetime.now()
            if now < certificate.not_valid_before or now > certificate.not_valid_after:
                logger.error("Certificate is not currently valid (expired or not yet valid)")
                return None
            
            # Extract certificate information
            subject = certificate.subject
            issuer = certificate.issuer
            
            # Get Common Name from subject
            subject_cn = None
            for attribute in subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    subject_cn = attribute.value
                    break
            
            if not subject_cn:
                logger.error("Certificate does not contain Common Name in subject")
                return None
            
            cert_info = {
                'subject_cn': subject_cn,
                'subject': subject.rfc4514_string(),
                'issuer': issuer.rfc4514_string(),
                'serial_number': str(certificate.serial_number),
                'not_valid_before': certificate.not_valid_before.isoformat(),
                'not_valid_after': certificate.not_valid_after.isoformat(),
                'signature_algorithm': certificate.signature_algorithm_oid._name,
                'version': certificate.version.name
            }
            
            logger.info(f"Validated certificate for: {subject_cn}")
            return cert_info
            
        except Exception as e:
            logger.error(f"Certificate validation failed: {sanitize_for_logging(str(e))}")
            return None
    
    async def _create_sap_cert_connection(self, credentials: Dict[str, Any], 
                                        cert_info: Dict[str, Any]):
        """
        Create SAP connection using certificate authentication
        
        Note: This depends on SAP system supporting certificate authentication.
        Many SAP systems require additional configuration for cert auth.
        """
        try:
            # Check if SAP system supports certificate authentication
            # This is a placeholder - actual implementation depends on SAP configuration
            
            # Option 1: Direct certificate authentication (if SAP supports it)
            if self._sap_supports_cert_auth(credentials['sap_host']):
                sap_connection = SAPConnection(
                    host=credentials['sap_host'],
                    client=credentials['sap_client'],
                    certificate_pem=credentials['certificate_pem'],
                    private_key_pem=credentials.get('private_key_pem'),
                    auth_type=AuthType.CERTIFICATE,
                    secure=True
                )
                
                sap_client = SAPADTClient(sap_connection)
                connected = await sap_client.connect()
                
                if connected:
                    logger.info(f"Created SAP certificate connection for {cert_info['subject_cn']}")
                    return sap_client
            
            # Option 2: Certificate-to-username mapping (more common)
            username = await self._map_certificate_to_username(cert_info, credentials)
            if username:
                # This would require a service account or other authentication method
                # to create the actual SAP connection on behalf of the certificate user
                logger.info(f"Mapped certificate to SAP username: {username}")
                
                # TODO: Implement service account connection with user context
                # This is a placeholder for the actual implementation
                return None
            
            logger.error("Failed to create SAP connection with certificate")
            return None
            
        except Exception as e:
            logger.error(f"Failed to create SAP certificate connection: {sanitize_for_logging(str(e))}")
            return None
    
    def _sap_supports_cert_auth(self, sap_host: str) -> bool:
        """
        Check if SAP system supports direct certificate authentication
        
        This would typically involve:
        1. Checking SAP system configuration
        2. Testing certificate authentication endpoint
        3. Verifying trust store configuration
        """
        # Placeholder implementation
        # In production, this would check actual SAP capabilities
        return False
    
    async def _map_certificate_to_username(self, cert_info: Dict[str, Any], 
                                         credentials: Dict[str, Any]) -> str:
        """
        Map certificate to SAP username
        
        This could involve:
        1. LDAP lookup using certificate subject
        2. Database mapping table
        3. Certificate attribute extraction
        4. Active Directory integration
        """
        try:
            # Option 1: Use Common Name as username
            username = cert_info['subject_cn']
            
            # Option 2: Extract from certificate attributes
            # Parse subject for specific attributes like employeeID
            
            # Option 3: LDAP/AD lookup
            # Query directory service using certificate information
            
            # For now, use Common Name
            logger.info(f"Mapped certificate CN '{username}' to SAP username")
            return username
            
        except Exception as e:
            logger.error(f"Certificate to username mapping failed: {sanitize_for_logging(str(e))}")
            return None
    
    async def validate_session(self, session_token: str) -> bool:
        """Validate certificate session token"""
        # Certificate sessions might have different validation logic
        return len(session_token) > 0
    
    async def refresh_session(self, session_token: str) -> str:
        """Certificate auth typically doesn't support refresh"""
        return None
    
    def get_required_credentials(self) -> List[CredentialInfo]:
        """Get required credential fields for certificate authentication"""
        return [
            CredentialInfo(
                field_name="certificate_pem",
                description="X.509 certificate in PEM format",
                required=True,
                sensitive=True,
                example="<PEM-ENCODED-CERTIFICATE>"
            ),
            CredentialInfo(
                field_name="private_key_pem",
                description="Private key in PEM format (optional if certificate includes key)",
                required=False,
                sensitive=True,
                example="<PEM-ENCODED-PRIVATE-KEY>"
            ),
            CredentialInfo(
                field_name="sap_host",
                description="SAP system hostname or IP address",
                required=True,
                example="sap.company.com"
            ),
            CredentialInfo(
                field_name="sap_client",
                description="SAP client number (usually 3 digits)",
                required=True,
                example="100"
            ),
            CredentialInfo(
                field_name="sap_language",
                description="SAP language code",
                required=False,
                example="EN"
            )
        ]
    
    def get_auth_type(self) -> AuthenticationType:
        """Get authentication type"""
        return AuthenticationType.CERTIFICATE
    
    def get_display_name(self) -> str:
        """Get display name"""
        return "Certificate Authentication (X.509)"
    
    def supports_refresh(self) -> bool:
        """Certificate auth doesn't support refresh"""
        return False