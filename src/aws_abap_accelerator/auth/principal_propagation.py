"""
Principal Propagation Service for ABAP-Accelerator MCP Server

This module handles the complete principal propagation flow:
1. Extract and validate IAM Identity Center user identity
2. Map IAM identity to SAP username (algorithmic or exception-based)
3. Generate ephemeral certificate for SAP authentication
4. Provide certificate for SAP ADT API calls
"""

import os
import json
import logging
import boto3
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import yaml

from .providers.certificate_auth_provider import CertificateAuthProvider
from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)


class PrincipalPropagationService:
    """
    Service for handling principal propagation from IAM Identity Center to SAP.
    
    Features:
    - IAM Identity Center token validation
    - Pass-through login identifier to certificate CN (SAP CERTRULE handles mapping)
    - Dynamic certificate generation
    - SAP endpoint management
    - Audit logging
    
    NOTE: User mapping is now handled by SAP CERTRULE, not this service.
    The login identifier (whatever the user typed to login) is passed directly
    to the certificate CN, and SAP maps it to the SAP username.
    """
    
    def __init__(self):
        self._certificate_provider: Optional[CertificateAuthProvider] = None
        self._user_exceptions: Dict[str, Dict[str, str]] = {}
        self._sap_endpoints: Dict[str, Dict[str, Any]] = {}
        self._ca_loaded = False
        self._config_loaded = False
        
        # AWS clients (lazy initialization)
        self._secrets_client = None
        self._ssm_client = None
        
        # Configuration
        self._secrets_manager_ca_secret = os.getenv(
            'CA_SECRET_NAME', 
            'abap-accelerator/ca-certificate'
        )
        self._parameter_store_exceptions = os.getenv(
            'USER_EXCEPTIONS_PARAMETER',
            '/abap-accelerator/user-exceptions'
        )
        self._parameter_store_endpoints = os.getenv(
            'SAP_ENDPOINTS_PARAMETER',
            '/abap-accelerator/sap-endpoints'
        )
    
    @property
    def secrets_client(self):
        """Lazy initialization of Secrets Manager client"""
        if self._secrets_client is None:
            region = os.getenv('AWS_REGION') or os.getenv('AWS_DEFAULT_REGION') or 'us-east-1'
            self._secrets_client = boto3.client('secretsmanager', region_name=region)
            logger.info(f"Initialized Secrets Manager client for region: {region}")
        return self._secrets_client
    
    @property
    def ssm_client(self):
        """Lazy initialization of SSM client"""
        if self._ssm_client is None:
            region = os.getenv('AWS_REGION') or os.getenv('AWS_DEFAULT_REGION') or 'us-east-1'
            self._ssm_client = boto3.client('ssm', region_name=region)
            logger.info(f"Initialized SSM client for region: {region}")
        return self._ssm_client
    
    async def initialize(self) -> bool:
        """
        Initialize the principal propagation service.
        Loads CA certificate and configuration from AWS.
        """
        try:
            logger.info("Initializing Principal Propagation Service...")
            
            # Load CA certificate from Secrets Manager
            ca_loaded = await self._load_ca_certificate()
            if not ca_loaded:
                logger.warning("CA certificate not loaded - certificate auth will not work")
            
            # Load user exceptions and SAP endpoints from Parameter Store
            config_loaded = await self._load_configuration()
            if not config_loaded:
                logger.warning("Configuration not loaded - using defaults")
            
            logger.info(
                f"Principal Propagation Service initialized: "
                f"CA={self._ca_loaded}, Config={self._config_loaded}"
            )
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Principal Propagation Service: {e}")
            return False
    
    async def _load_ca_certificate(self) -> bool:
        """Load CA certificate and private key from AWS Secrets Manager"""
        try:
            logger.info(f"Loading CA certificate from Secrets Manager: {self._secrets_manager_ca_secret}")
            
            response = self.secrets_client.get_secret_value(
                SecretId=self._secrets_manager_ca_secret
            )
            
            secret_data = json.loads(response['SecretString'])
            ca_cert_pem = secret_data.get('ca_certificate')
            ca_key_pem = secret_data.get('ca_private_key')
            
            if not ca_cert_pem or not ca_key_pem:
                logger.error("CA certificate or private key missing from secret")
                return False
            
            # Initialize certificate provider
            self._certificate_provider = CertificateAuthProvider()
            success = self._certificate_provider.set_ca_credentials(ca_cert_pem, ca_key_pem)
            
            if success:
                self._ca_loaded = True
                logger.info("CA certificate loaded successfully")
            
            return success
            
        except self.secrets_client.exceptions.ResourceNotFoundException:
            logger.warning(f"CA secret not found: {self._secrets_manager_ca_secret}")
            return False
        except Exception as e:
            logger.error(f"Failed to load CA certificate: {sanitize_for_logging(str(e))}")
            return False
    
    async def _load_configuration(self) -> bool:
        """Load user exceptions and SAP endpoints from Parameter Store"""
        try:
            # Load user exceptions
            try:
                logger.info(f"Loading user exceptions from: {self._parameter_store_exceptions}")
                response = self.ssm_client.get_parameter(
                    Name=self._parameter_store_exceptions
                )
                exceptions_yaml = response['Parameter']['Value']
                exceptions_data = yaml.safe_load(exceptions_yaml)
                self._user_exceptions = exceptions_data.get('exceptions', {})
                logger.info(f"Loaded {len(self._user_exceptions)} user exception mappings")
            except self.ssm_client.exceptions.ParameterNotFound:
                logger.info("No user exceptions parameter found - using algorithmic mapping only")
                self._user_exceptions = {}
            
            # Load SAP endpoints
            try:
                logger.info(f"Loading SAP endpoints from: {self._parameter_store_endpoints}")
                response = self.ssm_client.get_parameter(
                    Name=self._parameter_store_endpoints
                )
                endpoints_yaml = response['Parameter']['Value']
                endpoints_data = yaml.safe_load(endpoints_yaml)
                self._sap_endpoints = endpoints_data.get('endpoints', {})
                logger.info(f"Loaded {len(self._sap_endpoints)} SAP endpoint configurations")
            except self.ssm_client.exceptions.ParameterNotFound:
                logger.warning("No SAP endpoints parameter found")
                self._sap_endpoints = {}
            
            self._config_loaded = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {sanitize_for_logging(str(e))}")
            return False
    
    def set_local_configuration(
        self,
        user_exceptions: Dict[str, Dict[str, str]] = None,
        sap_endpoints: Dict[str, Dict[str, Any]] = None
    ):
        """
        Set configuration locally (for testing or non-AWS environments).
        
        Args:
            user_exceptions: Dict mapping IAM email to {sap_system: sap_username}
            sap_endpoints: Dict mapping sap_system_id to {host, port, client}
        """
        if user_exceptions:
            self._user_exceptions = user_exceptions
            logger.info(f"Set {len(user_exceptions)} local user exception mappings")
        
        if sap_endpoints:
            self._sap_endpoints = sap_endpoints
            logger.info(f"Set {len(sap_endpoints)} local SAP endpoint configurations")
        
        self._config_loaded = True
    
    def set_ca_credentials_local(self, ca_cert_pem: str, ca_key_pem: str) -> bool:
        """
        Set CA credentials locally (for testing or non-AWS environments).
        
        Args:
            ca_cert_pem: CA certificate in PEM format
            ca_key_pem: CA private key in PEM format
        """
        self._certificate_provider = CertificateAuthProvider()
        success = self._certificate_provider.set_ca_credentials(ca_cert_pem, ca_key_pem)
        if success:
            self._ca_loaded = True
        return success
    
    def map_iam_to_sap_user(self, iam_identity: str, sap_system_id: str) -> str:
        """
        DEPRECATED: User mapping is now handled by SAP CERTRULE.
        
        This method is kept for backward compatibility but is no longer used
        in the main flow. The login identifier is passed directly to the
        certificate CN, and SAP CERTRULE handles the mapping.
        
        Args:
            iam_identity: IAM Identity Center email (e.g., alice@company.com)
            sap_system_id: Target SAP system (e.g., S4H-100)
            
        Returns:
            SAP username (legacy behavior)
        """
        logger.warning(
            "DEPRECATED: map_iam_to_sap_user() is no longer used. "
            "SAP CERTRULE now handles user mapping via pass-through CN."
        )
        
        # Legacy behavior kept for backward compatibility
        # Check for exception mapping
        if iam_identity in self._user_exceptions:
            user_systems = self._user_exceptions[iam_identity]
            if sap_system_id in user_systems:
                sap_username = user_systems[sap_system_id]
                logger.info(
                    f"User mapping (exception): {iam_identity} -> {sap_username} "
                    f"for system {sap_system_id}"
                )
                return sap_username
        
        # Algorithmic mapping: use email prefix
        sap_username = iam_identity.split('@')[0]
        logger.info(
            f"User mapping (algorithmic): {iam_identity} -> {sap_username} "
            f"for system {sap_system_id}"
        )
        return sap_username
    
    def get_sap_endpoint(self, sap_system_id: str) -> Optional[Dict[str, Any]]:
        """
        Get SAP endpoint configuration for a system.
        
        Args:
            sap_system_id: SAP system identifier (e.g., S4H-100)
            
        Returns:
            Dict with host, port, client or None if not found
        """
        return self._sap_endpoints.get(sap_system_id)
    
    def generate_certificate_for_user(
        self,
        login_identifier: str,
        sap_system_id: str,
        validity_minutes: int = 5
    ) -> Tuple[str, str]:
        """
        Generate ephemeral certificate for a user using pass-through CN.
        
        The login_identifier is used directly as the certificate CN.
        SAP CERTRULE handles the mapping to SAP username.
        
        Args:
            login_identifier: The actual login ID from IdP (email, username, employee ID, etc.)
            sap_system_id: Target SAP system (for logging only)
            validity_minutes: Certificate validity in minutes
            
        Returns:
            Tuple of (cert_pem, key_pem)
        """
        if not self._ca_loaded or not self._certificate_provider:
            raise ValueError("CA certificate not loaded. Cannot generate certificates.")
        
        # Pass-through: use login_identifier directly as CN
        # SAP CERTRULE will handle the mapping to SAP username
        # Note: CN has 64 char limit, truncate if needed
        cn_value = login_identifier
        if len(cn_value) > 64:
            logger.warning(f"Login identifier exceeds 64 char CN limit, truncating: {cn_value}")
            cn_value = cn_value[:64]
        
        # Generate certificate with login identifier as CN
        # Format: CN=<login_identifier>,OU=Principal-Propagation,O=ABAP-Accelerator,C=US
        cert_pem, key_pem = self._certificate_provider.generate_ephemeral_certificate(
            sap_username=cn_value,  # Using login_identifier as CN (param name kept for compatibility)
            sap_system_id=sap_system_id,
            organizational_unit="Principal-Propagation",
            organization="ABAP-Accelerator",
            country="US",
            validity_minutes=validity_minutes
        )
        
        logger.info(
            f"Generated certificate with pass-through CN: {cn_value} for system {sap_system_id}"
        )
        
        return cert_pem, key_pem
    
    async def get_sap_credentials_for_request(
        self,
        iam_identity: str,
        login_identifier: str,
        sap_system_id: str
    ) -> Dict[str, Any]:
        """
        Get complete SAP credentials for a request.
        
        This is the main method to call for each tool invocation.
        Uses pass-through CN approach - login_identifier goes directly to certificate CN.
        
        Args:
            iam_identity: IAM Identity Center email (for logging/audit)
            login_identifier: The actual login ID from IdP (used as certificate CN)
            sap_system_id: Target SAP system
            
        Returns:
            Dict with login_identifier, cert_pem, key_pem, host, port, client
        """
        # Get SAP endpoint
        endpoint = self.get_sap_endpoint(sap_system_id)
        if not endpoint:
            raise ValueError(f"SAP endpoint not configured for system: {sap_system_id}")
        
        # Generate certificate with pass-through CN
        cert_pem, key_pem = self.generate_certificate_for_user(
            login_identifier=login_identifier,
            sap_system_id=sap_system_id
        )
        
        return {
            'iam_identity': iam_identity,
            'login_identifier': login_identifier,  # What was used as CN
            'sap_username': login_identifier,  # For backward compatibility (SAP will map via CERTRULE)
            'sap_system_id': sap_system_id,
            'cert_pem': cert_pem,
            'key_pem': key_pem,
            'sap_host': endpoint.get('host'),
            'sap_port': endpoint.get('port', 443),
            'sap_client': endpoint.get('client', '100'),
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def is_ready(self) -> bool:
        """Check if service is ready for certificate generation"""
        return self._ca_loaded
    
    def get_status(self) -> Dict[str, Any]:
        """Get service status"""
        return {
            'ca_loaded': self._ca_loaded,
            'config_loaded': self._config_loaded,
            'user_exceptions_count': len(self._user_exceptions),
            'sap_endpoints_count': len(self._sap_endpoints),
            'sap_systems': list(self._sap_endpoints.keys())
        }


# Global instance
principal_propagation_service = PrincipalPropagationService()
