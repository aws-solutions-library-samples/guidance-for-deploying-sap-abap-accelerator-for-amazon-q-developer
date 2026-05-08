"""
Certificate-Based Authentication Provider with Dynamic Certificate Generation
Implements Principal Propagation for SAP systems using ephemeral X.509 certificates
"""

import logging
import tempfile
import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from .base import AuthenticationProvider
from ..types import AuthenticationResult, AuthenticationType, CredentialInfo
from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)


class CertificateAuthProvider(AuthenticationProvider):
    """
    Certificate-based authentication provider with dynamic certificate generation.
    
    This provider implements Principal Propagation by:
    1. Receiving verified user identity from IAM Identity Center
    2. Mapping IAM identity to SAP username
    3. Generating ephemeral X.509 certificate with SAP username in CN
    4. Using certificate for SAP ADT API authentication
    5. Discarding certificate after use
    """
    
    def __init__(self, ca_certificate_pem: str = None, ca_private_key_pem: str = None):
        self.name = "Certificate Authentication"
        self.description = "Dynamic X.509 certificate generation for SAP authentication"
        self._ca_certificate_pem = ca_certificate_pem
        self._ca_private_key_pem = ca_private_key_pem
        self._ca_certificate = None
        self._ca_private_key = None
        
        # Initialize CA if provided
        if ca_certificate_pem and ca_private_key_pem:
            self._load_ca_credentials(ca_certificate_pem, ca_private_key_pem)
    
    def _load_ca_credentials(self, ca_cert_pem: str, ca_key_pem: str) -> bool:
        """Load CA certificate and private key from PEM strings"""
        try:
            # Load CA certificate
            self._ca_certificate = x509.load_pem_x509_certificate(
                ca_cert_pem.encode('utf-8'),
                default_backend()
            )
            
            # Load CA private key
            self._ca_private_key = serialization.load_pem_private_key(
                ca_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            logger.info(f"CA credentials loaded successfully. CA Subject: {self._ca_certificate.subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load CA credentials: {sanitize_for_logging(str(e))}")
            return False
    
    def set_ca_credentials(self, ca_cert_pem: str, ca_key_pem: str) -> bool:
        """Set CA credentials after initialization"""
        self._ca_certificate_pem = ca_cert_pem
        self._ca_private_key_pem = ca_key_pem
        return self._load_ca_credentials(ca_cert_pem, ca_key_pem)
    
    # OIDs inherited from the CA subject when building the leaf subject.
    # We deliberately whitelist standard DN components and drop anything else
    # (serialNumber, DC, emailAddress, custom OIDs) so a quirky CA subject
    # cannot surprise SAP CERTRULE matching.
    _INHERITABLE_SUBJECT_OIDS = (
        NameOID.COUNTRY_NAME,
        NameOID.STATE_OR_PROVINCE_NAME,
        NameOID.LOCALITY_NAME,
        NameOID.ORGANIZATION_NAME,
        NameOID.ORGANIZATIONAL_UNIT_NAME,
    )

    def _build_leaf_subject(
        self,
        sap_username: str,
        fallback_country: str,
        fallback_organization: str,
        fallback_organizational_unit: str,
    ) -> x509.Name:
        """
        Build the leaf certificate subject by inheriting DN attributes from the
        loaded CA certificate and appending CN=<sap_username>.

        Attribute order follows the CA's subject order so the rendered DN is
        consistent with the CA chain SAP already trusts. If the CA subject
        lacks any of C/O/OU, we fall back to the provided defaults so local
        development with a minimal CA still works.
        """
        inherited: list = []
        present_oids: set = set()
        for attr in self._ca_certificate.subject:
            if attr.oid == NameOID.COMMON_NAME:
                continue
            if attr.oid in self._INHERITABLE_SUBJECT_OIDS and attr.oid not in present_oids:
                inherited.append(x509.NameAttribute(attr.oid, attr.value))
                present_oids.add(attr.oid)

        # Fallbacks for CAs that don't carry the full standard set.
        if NameOID.COUNTRY_NAME not in present_oids and fallback_country:
            inherited.append(x509.NameAttribute(NameOID.COUNTRY_NAME, fallback_country))
        if NameOID.ORGANIZATION_NAME not in present_oids and fallback_organization:
            inherited.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, fallback_organization)
            )
        if (
            NameOID.ORGANIZATIONAL_UNIT_NAME not in present_oids
            and fallback_organizational_unit
        ):
            inherited.append(
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, fallback_organizational_unit
                )
            )

        inherited.append(x509.NameAttribute(NameOID.COMMON_NAME, sap_username))
        return x509.Name(inherited)

    def generate_ephemeral_certificate(
        self,
        sap_username: str,
        sap_system_id: str = None,
        organization: str = "ABAP-Accelerator",
        organizational_unit: str = "Principal-Propagation",
        country: str = "US",
        validity_minutes: int = 5
    ) -> tuple[str, str]:
        """
        Generate an ephemeral X.509 certificate for SAP authentication.

        The leaf subject's C/ST/L/O/OU attributes are inherited from the CA
        certificate loaded from Secrets Manager so rotating the CA (e.g. to a
        different organization) does not require a code change. CN is the only
        per-request component and carries the login identifier.

        Args:
            sap_username: Value placed in the certificate CN (pass-through from
                the login identifier; SAP CERTRULE maps it to a SAP user).
            sap_system_id: SAP system identifier (not used in subject, kept for logging).
            organization: Fallback O value if the CA subject has no O.
            organizational_unit: Fallback OU value if the CA subject has no OU.
            country: Fallback C value if the CA subject has no C.
            validity_minutes: Certificate validity in minutes (default 5).

        Returns:
            Tuple of (certificate_pem, private_key_pem)

        Note:
            Resulting subject mirrors the CA's DN with CN replaced by
            sap_username. The matching SAP CERTRULE must therefore reference
            the CA's DN components, not the legacy hardcoded values.
        """
        if not self._ca_certificate or not self._ca_private_key:
            raise ValueError("CA credentials not loaded. Call set_ca_credentials() first.")

        try:
            # Generate new RSA key pair for this certificate
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            # Build leaf subject by inheriting non-CN attributes from the CA.
            subject = self._build_leaf_subject(
                sap_username=sap_username,
                fallback_country=country,
                fallback_organization=organization,
                fallback_organizational_unit=organizational_unit,
            )

            # Calculate validity period
            now = datetime.utcnow()
            not_valid_before = now - timedelta(minutes=1)  # Small buffer for clock skew
            not_valid_after = now + timedelta(minutes=validity_minutes)
            
            # Build certificate
            cert_builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self._ca_certificate.subject)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(not_valid_before)
                .not_valid_after(not_valid_after)
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True
                )
                .add_extension(
                    x509.ExtendedKeyUsage([
                        ExtendedKeyUsageOID.CLIENT_AUTH
                    ]),
                    critical=False
                )
            )
            
            # Sign certificate with CA private key
            certificate = cert_builder.sign(
                private_key=self._ca_private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
            
            # Serialize to PEM format
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            logger.info(
                f"Generated ephemeral certificate: subject={subject.rfc4514_string()}, "
                f"issuer={self._ca_certificate.subject.rfc4514_string()}, "
                f"valid: {not_valid_before.isoformat()} to {not_valid_after.isoformat()}"
            )
            
            return cert_pem, key_pem
            
        except Exception as e:
            logger.error(f"Failed to generate ephemeral certificate: {sanitize_for_logging(str(e))}")
            raise
    
    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate using dynamically generated certificate.
        
        Expected credentials:
        - iam_identity: Verified IAM Identity Center email
        - sap_username: Mapped SAP username
        - sap_system_id: Target SAP system identifier
        - sap_host: SAP system hostname
        - sap_client: SAP client number
        """
        try:
            # Validate required fields
            required_fields = ['iam_identity', 'sap_username', 'sap_system_id', 'sap_host', 'sap_client']
            for field in required_fields:
                if field not in credentials:
                    return AuthenticationResult(
                        success=False,
                        error_message=f"Missing required field: {field}",
                        auth_type=self.get_auth_type()
                    )
            
            iam_identity = credentials['iam_identity']
            sap_username = credentials['sap_username']
            sap_system_id = credentials['sap_system_id']
            sap_host = credentials['sap_host']
            sap_client = credentials['sap_client']
            
            logger.info(
                f"Certificate authentication: IAM={iam_identity} -> SAP={sap_username}@{sap_system_id}"
            )
            
            # Generate ephemeral certificate
            cert_pem, key_pem = self.generate_ephemeral_certificate(
                sap_username=sap_username,
                sap_system_id=sap_system_id,
                validity_minutes=5
            )
            
            # Create SAP client with certificate authentication
            sap_client_instance = await self._create_sap_client_with_certificate(
                sap_host=sap_host,
                sap_client=sap_client,
                sap_username=sap_username,
                cert_pem=cert_pem,
                key_pem=key_pem
            )
            
            if not sap_client_instance:
                return AuthenticationResult(
                    success=False,
                    error_message="Failed to create SAP client with certificate",
                    auth_type=self.get_auth_type()
                )
            
            # Prepare user info with tokens (certificate data for session)
            user_info = {
                'iam_identity': iam_identity,
                'username': sap_username,
                'sap_host': sap_host,
                'sap_client': sap_client,
                'sap_system_id': sap_system_id,
                'auth_type': self.get_auth_type().value,
                'sap_tokens': {
                    'cert_pem': cert_pem,
                    'key_pem': key_pem,
                    'sap_host': sap_host,
                    'sap_client': sap_client,
                    'sap_username': sap_username
                },
                'authenticated_at': datetime.now().isoformat()
            }
            
            logger.info(
                f"Certificate authentication successful: {iam_identity} -> {sap_username}@{sap_host}"
            )
            
            return AuthenticationResult(
                success=True,
                session_token=f"cert-{sap_username}-{sap_system_id}-{datetime.now().timestamp()}",
                user_info=user_info,
                auth_type=self.get_auth_type()
            )
            
        except Exception as e:
            # Use warning level when re-raising - caller handles the error
            logger.warning(f"Certificate authentication failed: {sanitize_for_logging(str(e))}")
            return AuthenticationResult(
                success=False,
                error_message=f"Certificate authentication failed: {str(e)}",
                auth_type=self.get_auth_type()
            )
    
    async def _create_sap_client_with_certificate(
        self,
        sap_host: str,
        sap_client: str,
        sap_username: str,
        cert_pem: str,
        key_pem: str
    ):
        """Create SAP ADT client configured with certificate authentication"""
        try:
            from sap.sap_client import SAPADTClient
            from sap_types.sap_types import SAPConnection, AuthType
            
            # Create connection with certificate auth type
            connection = SAPConnection(
                host=sap_host,
                client=sap_client,
                username=sap_username,
                password="",  # Not needed for certificate auth
                language="EN",
                secure=True,
                auth_type=AuthType.CERTIFICATE
            )
            
            # Create SAP client
            sap_client_instance = SAPADTClient(connection)
            
            # Store certificate data for use in requests
            sap_client_instance.client_certificate_pem = cert_pem
            sap_client_instance.client_private_key_pem = key_pem
            sap_client_instance.use_certificate_auth = True
            
            logger.info(f"Created SAP client with certificate auth for {sap_username}@{sap_host}")
            return sap_client_instance
            
        except Exception as e:
            logger.error(f"Failed to create SAP client with certificate: {sanitize_for_logging(str(e))}")
            return None
    
    def get_auth_type(self) -> AuthenticationType:
        """Get authentication type"""
        return AuthenticationType.CERTIFICATE
    
    def get_display_name(self) -> str:
        """Get display name"""
        return "Certificate Authentication (Dynamic X.509)"
    
    def get_required_credentials(self) -> List[CredentialInfo]:
        """Get required credential fields"""
        return [
            CredentialInfo(
                field_name="iam_identity",
                description="Verified IAM Identity Center email",
                required=True,
                example="user@company.com"
            ),
            CredentialInfo(
                field_name="sap_username",
                description="Mapped SAP username",
                required=True,
                example="DEV_USER"
            ),
            CredentialInfo(
                field_name="sap_system_id",
                description="SAP system identifier",
                required=True,
                example="S4H-100"
            ),
            CredentialInfo(
                field_name="sap_host",
                description="SAP system hostname",
                required=True,
                example="sap.company.com"
            ),
            CredentialInfo(
                field_name="sap_client",
                description="SAP client number",
                required=True,
                example="100"
            )
        ]
    
    async def validate_session(self, session_token: str) -> bool:
        """Validate certificate session token"""
        return session_token.startswith("cert-")
    
    async def refresh_session(self, session_token: str) -> str:
        """Certificate sessions don't support refresh - generate new certificate"""
        return None
    
    def supports_refresh(self) -> bool:
        """Certificate auth doesn't support refresh"""
        return False
    
    def get_session_duration_hours(self) -> int:
        """Certificate sessions are very short-lived"""
        return 1  # 1 hour max, but certificates are only valid for 5 minutes
