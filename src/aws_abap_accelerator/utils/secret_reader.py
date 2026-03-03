"""
Secret reader utility for Docker secrets and environment variables.
Python equivalent of secret-reader.ts
"""

import os
from pathlib import Path
from typing import Optional

from .security import sanitize_for_logging


class SecretReader:
    """Utility class for reading Docker secrets and environment variables"""
    
    DOCKER_SECRETS_PATH = Path("/run/secrets")
    
    @classmethod
    def read_secret(cls, secret_name: str) -> Optional[str]:
        """
        Read a Docker secret from the filesystem.
        
        Args:
            secret_name: Name of the secret file
            
        Returns:
            Secret content or None if not found
        """
        try:
            secret_file = cls.DOCKER_SECRETS_PATH / secret_name
            if secret_file.exists() and secret_file.is_file():
                content = secret_file.read_text(encoding='utf-8').strip()
                return content if content else None
        except Exception as e:
            print(f"Warning: Failed to read Docker secret '{sanitize_for_logging(secret_name)}': {sanitize_for_logging(str(e))}")
        
        return None
    
    @classmethod
    def get_secret_or_env(cls, secret_name: str, env_var_name: str) -> Optional[str]:
        """
        Get value from Docker secret first, fallback to environment variable.
        
        Args:
            secret_name: Name of the Docker secret file
            env_var_name: Name of the environment variable
            
        Returns:
            Secret/environment value or None if not found
        """
        # Try Docker secret first
        secret_value = cls.read_secret(secret_name)
        if secret_value:
            return secret_value
        
        # Fallback to environment variable
        return os.getenv(env_var_name)
    
    @classmethod
    def list_available_secrets(cls) -> list:
        """
        List all available Docker secrets.
        
        Returns:
            List of secret names
        """
        try:
            if cls.DOCKER_SECRETS_PATH.exists():
                return [f.name for f in cls.DOCKER_SECRETS_PATH.iterdir() if f.is_file()]
        except Exception as e:
            print(f"Warning: Failed to list Docker secrets: {sanitize_for_logging(str(e))}")
        
        return []