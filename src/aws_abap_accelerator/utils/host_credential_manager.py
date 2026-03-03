"""
Host credential manager for Windows Credential Manager integration.
Python equivalent of host-credential-manager.ts
"""

import platform
from typing import Optional, Dict
import logging

from .security import sanitize_for_logging

logger = logging.getLogger(__name__)


class HostCredentialManager:
    """Utility class for managing host credentials via Windows Credential Manager"""
    
    @classmethod
    def get_credentials_by_host(cls, host: str) -> Optional[Dict[str, str]]:
        """
        Get credentials for a specific host from Windows Credential Manager.
        
        Args:
            host: SAP host to look up credentials for
            
        Returns:
            Dictionary with username and password, or None if not found
        """
        if platform.system() != "Windows":
            logger.warning("Credential Manager is only supported on Windows")
            return None
        
        try:
            # Try to import keyring for Windows Credential Manager access
            import keyring
            import keyring.backends.Windows
            
            # Set Windows backend
            keyring.set_keyring(keyring.backends.Windows.WinVaultKeyring())
            
            # Try to get credentials for the host
            # Common credential naming patterns for SAP systems
            credential_names = [
                f"SAP_{host}",
                f"sap_{host}",
                host,
                f"SAP-{host}",
                f"sap-{host}"
            ]
            
            for cred_name in credential_names:
                try:
                    password = keyring.get_password("SAP", cred_name)
                    if password:
                        # For Windows Credential Manager, username might be stored as part of the credential
                        # or we might need to look it up separately
                        username = keyring.get_password("SAP_USER", cred_name)
                        if not username:
                            # Try common username patterns
                            username = keyring.get_password("SAP", f"{cred_name}_USER")
                        
                        if username:
                            logger.info(f"Found credentials for host {sanitize_for_logging(host)} using pattern {sanitize_for_logging(cred_name)}")
                            return {
                                "username": username,
                                "password": password
                            }
                except Exception as e:
                    logger.debug(f"Failed to get credentials for pattern {sanitize_for_logging(cred_name)}: {sanitize_for_logging(str(e))}")
                    continue
            
            logger.info(f"No credentials found for host {sanitize_for_logging(host)}")
            return None
            
        except ImportError:
            logger.warning("keyring library not available. Install with: pip install keyring")
            return None
        except Exception as e:
            logger.error(f"Error accessing Windows Credential Manager: {sanitize_for_logging(str(e))}")
            return None
    
    @classmethod
    def store_credentials(cls, host: str, username: str, password: str) -> bool:
        """
        Store credentials for a host in Windows Credential Manager.
        
        Args:
            host: SAP host
            username: Username
            password: Password
            
        Returns:
            True if successful, False otherwise
        """
        if platform.system() != "Windows":
            logger.warning("Credential Manager is only supported on Windows")
            return False
        
        try:
            import keyring
            import keyring.backends.Windows
            
            # Set Windows backend
            keyring.set_keyring(keyring.backends.Windows.WinVaultKeyring())
            
            # Store credentials
            cred_name = f"SAP_{host}"
            keyring.set_password("SAP", cred_name, password)
            keyring.set_password("SAP_USER", cred_name, username)
            
            logger.info(f"Stored credentials for host {sanitize_for_logging(host)}")
            return True
            
        except ImportError:
            logger.warning("keyring library not available. Install with: pip install keyring")
            return False
        except Exception as e:
            logger.error(f"Error storing credentials in Windows Credential Manager: {sanitize_for_logging(str(e))}")
            return False
    
    @classmethod
    def delete_credentials(cls, host: str) -> bool:
        """
        Delete credentials for a host from Windows Credential Manager.
        
        Args:
            host: SAP host
            
        Returns:
            True if successful, False otherwise
        """
        if platform.system() != "Windows":
            logger.warning("Credential Manager is only supported on Windows")
            return False
        
        try:
            import keyring
            import keyring.backends.Windows
            
            # Set Windows backend
            keyring.set_keyring(keyring.backends.Windows.WinVaultKeyring())
            
            # Delete credentials
            cred_name = f"SAP_{host}"
            try:
                keyring.delete_password("SAP", cred_name)
                keyring.delete_password("SAP_USER", cred_name)
                logger.info(f"Deleted credentials for host {sanitize_for_logging(host)}")
                return True
            except keyring.errors.PasswordDeleteError:
                logger.info(f"No credentials found to delete for host {sanitize_for_logging(host)}")
                return True
            
        except ImportError:
            logger.warning("keyring library not available. Install with: pip install keyring")
            return False
        except Exception as e:
            logger.error(f"Error deleting credentials from Windows Credential Manager: {sanitize_for_logging(str(e))}")
            return False