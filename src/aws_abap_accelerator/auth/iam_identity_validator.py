"""
IAM Identity Center Token Validator

Validates and extracts user identity from IAM Identity Center tokens
passed by Amazon Q Developer.
"""

import os
import logging
import jwt
import requests
from typing import Dict, Any, Optional
from datetime import datetime

from utils.security import sanitize_for_logging

logger = logging.getLogger(__name__)


class IAMIdentityValidator:
    """
    Validates IAM Identity Center tokens and extracts user identity.
    
    Amazon Q Developer authenticates users via IAM Identity Center and
    passes identity information to MCP servers. This class validates
    that identity and extracts user attributes.
    
    IMPORTANT: This class now extracts the actual login identifier
    (whatever the user typed to login) for pass-through to SAP CERTRULE.
    SAP handles the mapping to SAP username, not the MCP server.
    """
    
    def __init__(self):
        self._jwks_url = os.getenv('IAM_IDENTITY_CENTER_JWKS_URL')
        self._issuer = os.getenv('IAM_IDENTITY_CENTER_ISSUER')
        self._audience = os.getenv('IAM_IDENTITY_CENTER_AUDIENCE')
        self._jwks_cache = None
        self._jwks_cache_time = None

    def _extract_login_identifier(self, claims: Dict[str, Any]) -> str:
        """
        Extract the actual login identifier from JWT claims.
        
        This returns whatever the user typed to login (email, username, 
        employee ID, etc.) for pass-through to SAP CERTRULE.
        
        Priority order (most specific to least specific):
        1. login (Okta-specific: actual login used)
        2. upn (Entra: User Principal Name)
        3. preferred_username (Standard OIDC)
        4. unique_name (Entra fallback)
        5. email (Common fallback)
        6. sub (Last resort - unique ID)
        
        Returns:
            The login identifier string (pass-through, no transformation)
        """
        # Okta uses 'login' for the actual login identifier
        if claims.get('login'):
            return claims['login']
        
        # Entra uses 'upn' (User Principal Name)
        if claims.get('upn'):
            return claims['upn']
        
        # Standard OIDC claim
        if claims.get('preferred_username'):
            return claims['preferred_username']
        
        # Entra fallback
        if claims.get('unique_name'):
            return claims['unique_name']
        
        # Email as fallback
        if claims.get('email'):
            return claims['email']
        
        # Last resort: subject ID
        return claims.get('sub', 'unknown')

    def extract_identity_from_headers(self, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Extract user identity from request headers.
        
        Amazon Q Developer passes identity in headers. This method extracts
        and validates the identity information.
        
        Args:
            headers: HTTP request headers
            
        Returns:
            Dict with user identity or None if not found/invalid
        """
        try:
            # Check for IAM Identity Center token in Authorization header
            auth_header = headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                return self._validate_jwt_token(token)
            
            # Check for identity in custom headers (Q Developer specific)
            iam_identity = headers.get('x-amzn-oidc-identity')
            if iam_identity:
                return self._parse_oidc_identity(iam_identity)
            
            # Check for user context headers (fallback for development)
            user_id = headers.get('x-user-id')
            if user_id:
                logger.info(f"Using x-user-id header for identity: {sanitize_for_logging(user_id)}")
                return {
                    'login_identifier': user_id,  # Pass-through for certificate CN
                    'email': user_id if '@' in user_id else f"{user_id}@unknown.com",
                    'user_id': user_id,
                    'source': 'x-user-id-header',
                    'validated': False  # Not cryptographically validated
                }
            
            logger.warning("No identity information found in headers")
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract identity from headers: {sanitize_for_logging(str(e))}")
            return None
    
    def _validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token and extract claims"""
        try:
            # Decode without verification first to get header
            unverified_header = jwt.get_unverified_header(token)
            
            # Track whether token was cryptographically validated
            is_validated = False
            
            # For production, verify signature with JWKS
            if self._jwks_url:
                # Get signing key from JWKS
                signing_key = self._get_signing_key(unverified_header.get('kid'))
                if signing_key:
                    decoded = jwt.decode(
                        token,
                        signing_key,
                        algorithms=['RS256', 'ES256'],
                        issuer=self._issuer,
                        audience=self._audience
                    )
                    is_validated = True
                else:
                    # SECURITY: In production (JWKS configured), fail if key retrieval fails
                    # rather than silently falling back to unverified decoding
                    logger.error("SECURITY: JWKS URL configured but signing key retrieval failed. "
                                "Rejecting token to prevent potential token forgery.")
                    return None
            else:
                # SECURITY: No JWKS URL configured - reject token
                # In production, IAM_IDENTITY_CENTER_JWKS_URL must be configured
                logger.error("SECURITY: JWT verification failed - JWKS URL not configured. "
                            "Set IAM_IDENTITY_CENTER_JWKS_URL environment variable.")
                return None
            
            # Extract user identity from claims
            # Use login_identifier for pass-through to SAP CERTRULE
            login_identifier = self._extract_login_identifier(decoded)
            
            return {
                'login_identifier': login_identifier,  # Pass-through for certificate CN
                'email': decoded.get('email') or decoded.get('preferred_username'),
                'user_id': decoded.get('sub'),
                'name': decoded.get('name'),
                'groups': decoded.get('groups', []),
                'roles': decoded.get('roles', []),
                'source': 'jwt',
                'validated': is_validated,  # Accurately reflects validation status
                'expires_at': decoded.get('exp'),
                'issued_at': decoded.get('iat')
            }
            
        except jwt.ExpiredSignatureError:
            logger.error("JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid JWT token: {sanitize_for_logging(str(e))}")
            return None
        except Exception as e:
            logger.error(f"JWT validation failed: {sanitize_for_logging(str(e))}")
            return None
    
    def _get_signing_key(self, kid: str) -> Optional[str]:
        """Get signing key from JWKS"""
        try:
            # Cache JWKS for 1 hour
            if self._jwks_cache and self._jwks_cache_time:
                cache_age = (datetime.now() - self._jwks_cache_time).total_seconds()
                if cache_age < 3600:
                    for key in self._jwks_cache.get('keys', []):
                        if key.get('kid') == kid:
                            return self._jwk_to_pem(key)
            
            # Fetch JWKS
            response = requests.get(self._jwks_url, timeout=10)
            if response.status_code == 200:
                self._jwks_cache = response.json()
                self._jwks_cache_time = datetime.now()
                
                for key in self._jwks_cache.get('keys', []):
                    if key.get('kid') == kid:
                        return self._jwk_to_pem(key)
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get signing key: {sanitize_for_logging(str(e))}")
            return None
    
    def _jwk_to_pem(self, jwk: Dict[str, Any]) -> Optional[str]:
        """Convert JWK to PEM format"""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization
            import base64
            
            if jwk.get('kty') != 'RSA':
                logger.warning(f"Unsupported key type: {jwk.get('kty')}")
                return None
            
            # Decode RSA components
            n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + '=='), 'big')
            e = int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + '=='), 'big')
            
            # Create public key
            public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
            
            # Convert to PEM
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return pem.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to convert JWK to PEM: {sanitize_for_logging(str(e))}")
            return None
    
    def _parse_oidc_identity(self, identity_data: str) -> Optional[Dict[str, Any]]:
        """Parse OIDC identity data from ALB/API Gateway"""
        try:
            import base64
            import json
            
            # OIDC identity is typically base64 encoded JSON
            decoded = base64.b64decode(identity_data)
            identity = json.loads(decoded)
            
            # Extract login identifier for pass-through
            login_identifier = self._extract_login_identifier(identity)
            
            return {
                'login_identifier': login_identifier,  # Pass-through for certificate CN
                'email': identity.get('email'),
                'user_id': identity.get('sub'),
                'name': identity.get('name'),
                'groups': identity.get('groups', []),
                'source': 'oidc-header',
                'validated': True  # ALB/API Gateway validated it
            }
            
        except Exception as e:
            logger.error(f"Failed to parse OIDC identity: {sanitize_for_logging(str(e))}")
            return None


# Global instance
iam_identity_validator = IAMIdentityValidator()
