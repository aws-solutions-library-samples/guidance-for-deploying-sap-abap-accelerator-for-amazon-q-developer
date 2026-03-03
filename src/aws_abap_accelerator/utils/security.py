"""
Security utilities for input sanitization and validation.
Python equivalent of security-utils.ts
"""

import re
import json
import secrets
import hashlib
from typing import Any, Dict, Union
from cryptography.fernet import Fernet
import base64


# Global memory key for encryption - generated once per application instance
_memory_key = Fernet.generate_key()
_fernet = Fernet(_memory_key)

# Pre-compiled regex patterns for performance
CONTROL_CHARS_REGEX = re.compile(r'[\r\n\t]')
XML_SPECIAL_CHARS = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;'
}


def sanitize_for_logging(input_data: Any) -> str:
    """
    Sanitizes input for logging to prevent log injection attacks.
    Removes or encodes newline characters and other control characters.
    Masks sensitive credentials in objects.
    """
    if input_data is None:
        return 'null'

    # Handle objects - mask sensitive keys
    if isinstance(input_data, (dict, list)):
        sensitive_keys = ['password', 'token', 'authorization', 'cookie', 'secret', 'csrf', 'auth']
        
        def mask_sensitive_data(obj: Any) -> Any:
            if not isinstance(obj, (dict, list)):
                return obj
            
            if isinstance(obj, list):
                return [mask_sensitive_data(item) for item in obj]
            
            if isinstance(obj, dict):
                result = {}
                for key, value in obj.items():
                    key_lower = key.lower()
                    if any(sensitive in key_lower for sensitive in sensitive_keys):
                        result[key] = '[REDACTED]'
                    elif isinstance(value, (dict, list)):
                        result[key] = mask_sensitive_data(value)
                    else:
                        result[key] = value
                return result
            
            return obj
        
        masked_input = mask_sensitive_data(input_data)
        str_input = json.dumps(masked_input, default=str)
    else:
        str_input = str(input_data)
    
    # Replace control characters
    return re.sub(r'[\x00-\x1F\x7F]', 
                  lambda m: f'\\x{ord(m.group(0)):02x}', 
                  str_input.replace('\r\n', '\\r\\n')
                           .replace('\n', '\\n')
                           .replace('\r', '\\r')
                           .replace('\t', '\\t'))


def sanitize_for_xml(input_str: str) -> str:
    """
    Sanitizes input for XML to prevent XML injection attacks.
    Encodes XML special characters and removes control characters.
    """
    if not input_str:
        return ''
    
    # Replace XML special characters
    result = input_str
    for char, replacement in XML_SPECIAL_CHARS.items():
        result = result.replace(char, replacement)
    
    # Remove control characters
    return re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', result)


# Alias for backward compatibility
encode_xml = sanitize_for_xml


def validate_object_name(name: str) -> str:
    """Validates and sanitizes object names for SAP operations"""
    if not name or not isinstance(name, str):
        raise ValueError('Object name must be a non-empty string')
    
    # Remove any potentially dangerous characters
    sanitized = re.sub(r'[^A-Za-z0-9_]', '', name)
    
    if not sanitized:
        raise ValueError('Object name contains no valid characters')
    
    return sanitized


def validate_numeric_input(value: Any, field_name: str) -> int:
    """Validates numeric input to prevent NaN issues"""
    try:
        num_value = int(value)
        if num_value < 0:
            raise ValueError(f'{field_name} must be non-negative')
        return num_value
    except (ValueError, TypeError):
        raise ValueError(f'Invalid numeric value for {field_name}: {value}')


def validate_sap_host(host: str) -> bool:
    """Validates SAP host for security"""
    if not host or not isinstance(host, str):
        return False
    
    # Remove protocol prefix if present
    clean_host = re.sub(r'^https?://', '', host)
    
    # Basic validation - allow hostnames, IPs, and ports
    # This is a simplified validation - adjust based on your security requirements
    if re.match(r'^[a-zA-Z0-9.-]+(?::\d+)?$', clean_host):
        return True
    
    return False


def sanitize_file_path(path: str) -> str:
    """Sanitizes file paths to prevent directory traversal attacks"""
    if not path:
        return ''
    
    # Remove dangerous path components
    sanitized = re.sub(r'\.\./', '', path)
    sanitized = re.sub(r'\.\.\\', '', sanitized)
    
    return sanitized


def sanitize_command_args(args: list) -> list:
    """Sanitizes command line arguments"""
    if not args:
        return []
    
    sanitized = []
    for arg in args:
        if isinstance(arg, str):
            # Remove potentially dangerous characters
            clean_arg = re.sub(r'[;&|`$()]', '', str(arg))
            sanitized.append(clean_arg)
        else:
            sanitized.append(str(arg))
    
    return sanitized


def encrypt_in_memory(data: str) -> str:
    """Encrypts data for in-memory storage"""
    if not data:
        return ''
    
    encrypted = _fernet.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')


def decrypt_from_memory(encrypted_data: str) -> str:
    """Decrypts data from in-memory storage"""
    if not encrypted_data:
        return ''
    
    try:
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        decrypted = _fernet.decrypt(encrypted_bytes)
        return decrypted.decode('utf-8')
    except Exception:
        return ''


def generate_session_id() -> str:
    """Generates a secure session ID"""
    return secrets.token_urlsafe(32)


def hash_password(password: str, salt: str = None) -> tuple:
    """Hashes a password with salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    
    # Use PBKDF2 with SHA-256
    hashed = hashlib.pbkdf2_hmac('sha256', 
                                password.encode('utf-8'), 
                                salt.encode('utf-8'), 
                                100000)  # 100,000 iterations
    
    return base64.b64encode(hashed).decode('utf-8'), salt


def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    """Verifies a password against its hash"""
    try:
        new_hash, _ = hash_password(password, salt)
        return secrets.compare_digest(new_hash, hashed_password)
    except Exception:
        return False