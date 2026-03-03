"""
Cross-platform OS Keychain integration for secure credential storage
"""

import os
import sys
import json
import hashlib
import logging
import getpass
from typing import Optional, Dict, Any, List
import platform
from datetime import datetime

logger = logging.getLogger(__name__)


def _get_masked_password(prompt: str = "Password: ") -> str:
    """
    Get password input with masking (shows * for each character).
    Works in Docker containers where getpass may not work properly.
    
    Args:
        prompt: The prompt to display
        
    Returns:
        The entered password
    """
    # For Linux/Docker - try multiple approaches
    if sys.platform != 'win32':
        # Approach 1: Try using stty command to disable echo (most compatible)
        try:
            import subprocess
            
            # Test if stty is available and works
            result = subprocess.run(['stty', '-echo'], capture_output=True)
            if result.returncode == 0:
                print(prompt, end='', flush=True)
                password = []
                try:
                    # Read character by character
                    import select
                    while True:
                        # Read one character
                        char = sys.stdin.read(1)
                        if char == '\n' or char == '\r' or char == '':
                            print()  # New line
                            break
                        elif char == '\x7f' or char == '\x08':  # Backspace
                            if password:
                                password.pop()
                                # Erase the last asterisk
                                sys.stdout.write('\b \b')
                                sys.stdout.flush()
                        elif char == '\x03':  # Ctrl+C
                            print()
                            subprocess.run(['stty', 'echo'], capture_output=True)
                            raise KeyboardInterrupt
                        elif ord(char) >= 32:  # Printable characters
                            password.append(char)
                            sys.stdout.write('*')
                            sys.stdout.flush()
                finally:
                    # Re-enable echo
                    subprocess.run(['stty', 'echo'], capture_output=True)
                
                return ''.join(password)
        except Exception as e:
            logger.debug(f"stty masking failed: {type(e).__name__}: {e}")
            # Make sure echo is re-enabled
            try:
                subprocess.run(['stty', 'echo'], capture_output=True)
            except:
                pass
        
        # Approach 2: Try tty/termios (standard but may not work in minimal containers)
        try:
            import tty
            import termios
            
            print(prompt, end='', flush=True)
            password = []
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                while True:
                    char = sys.stdin.read(1)
                    if char == '\r' or char == '\n':
                        print()
                        break
                    elif char == '\x7f' or char == '\x08':
                        if password:
                            password.pop()
                            sys.stdout.write('\b \b')
                            sys.stdout.flush()
                    elif char == '\x03':
                        print()
                        raise KeyboardInterrupt
                    elif ord(char) >= 32:
                        password.append(char)
                        sys.stdout.write('*')
                        sys.stdout.flush()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ''.join(password)
        except Exception as e:
            logger.debug(f"TTY masking failed: {type(e).__name__}: {e}")
    
    # For Windows
    if sys.platform == 'win32':
        try:
            import msvcrt
            print(prompt, end='', flush=True)
            password = []
            while True:
                char = msvcrt.getwch()
                if char == '\r' or char == '\n':
                    print()
                    break
                elif char == '\x08':
                    if password:
                        password.pop()
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                elif char == '\x03':
                    raise KeyboardInterrupt
                else:
                    password.append(char)
                    sys.stdout.write('*')
                    sys.stdout.flush()
            return ''.join(password)
        except ImportError:
            pass
    
    # Final fallback: regular input with warning
    print(f"\n[Warning: Password will be visible]")
    return input(prompt)


class KeychainManager:
    """Cross-platform keychain manager for secure credential storage"""
    
    def __init__(self):
        self.service_name = "sap-abap-accelerator-mcp"
        self._keyring = None
        self._initialize_keyring()
    
    def _initialize_keyring(self):
        """Initialize keyring library with fallback handling"""
        
        # Skip keyring in Docker containers - use in-memory storage
        # Keyring still works on Windows/Mac for local development
        if os.path.exists('/.dockerenv') or os.environ.get('DOCKER_CONTAINER'):
            logger.info("Running in Docker container - using in-memory credential storage")
            logger.info("Keyring support available for local Windows/Mac development")
            self._keyring = None
            self._memory_store = {}
            return
        
        try:
            import keyring
            self._keyring = keyring
            
            # Test keyring functionality
            test_key = "test_key_sap_mcp"
            test_value = "test_value"
            
            # Try to set and get a test value
            self._keyring.set_password(self.service_name, test_key, test_value)
            retrieved = self._keyring.get_password(self.service_name, test_key)
            
            if retrieved == test_value:
                # Clean up test
                self._keyring.delete_password(self.service_name, test_key)
                logger.info(f"Keyring initialized successfully on {platform.system()}")
            else:
                logger.warning("Keyring test failed - falling back to in-memory storage")
                self._keyring = None
                
        except ImportError:
            logger.warning("keyring library not available - install with: pip install keyring")
            self._keyring = None
        except Exception as e:
            logger.warning(f"Keyring initialization failed: {e} - falling back to in-memory storage")
            self._keyring = None
        
        # Fallback to in-memory storage if keyring fails
        if self._keyring is None:
            self._memory_store = {}
            logger.info("Using in-memory credential storage (not persistent)")
    
    def _generate_credential_key(self, user_id: str, sap_host: str, sap_client: str, sap_username: str) -> str:
        """Generate unique key for credential storage"""
        credential_data = f"{user_id}:{sap_host}:{sap_client}:{sap_username}"
        return hashlib.sha256(credential_data.encode()).hexdigest()[:32]
    
    def store_sap_credentials(self, user_id: str, sap_host: str, sap_client: str, 
                            sap_username: str, sap_password: str, sap_language: str = "EN") -> str:
        """
        Store SAP credentials securely and return credential token
        
        Args:
            user_id: System user ID (from OS)
            sap_host: SAP system hostname
            sap_client: SAP client number
            sap_username: SAP username
            sap_password: SAP password
            sap_language: SAP language code
            
        Returns:
            Credential token for later retrieval
        """
        try:
            credential_token = self._generate_credential_key(user_id, sap_host, sap_client, sap_username)
            
            credential_data = {
                "sap_host": sap_host,
                "sap_client": sap_client,
                "sap_username": sap_username,
                "sap_password": sap_password,
                "sap_language": sap_language,
                "user_id": user_id,
                "stored_at": str(datetime.now())
            }
            
            credential_json = json.dumps(credential_data)
            
            if self._keyring:
                # Store in OS keychain
                self._keyring.set_password(self.service_name, credential_token, credential_json)
                logger.info(f"Stored SAP credentials in OS keychain for {sap_username}@{sap_host}")
            else:
                # Store in memory (fallback)
                self._memory_store[credential_token] = credential_json
                logger.warning(f"Stored SAP credentials in memory (not persistent) for {sap_username}@{sap_host}")
            
            return credential_token
            
        except Exception as e:
            # Use warning level when re-raising - caller handles the error
            logger.warning(f"Failed to store SAP credentials: {e}")
            raise Exception(f"Failed to store credentials: {str(e)}")
    
    def get_sap_credentials_by_identifier(self, keychain_identifier: str) -> Optional[Dict[str, str]]:
        """
        Retrieve SAP credentials using keychain identifier
        
        Args:
            keychain_identifier: User-defined identifier (e.g., 'my-sap-dev', 'sap-prod')
            
        Returns:
            Dictionary with SAP credentials or None if not found
        """
        try:
            credential_json = None
            
            if self._keyring:
                # Retrieve from OS keychain using service name and identifier as account
                credential_json = self._keyring.get_password(self.service_name, keychain_identifier)
            else:
                # Retrieve from memory (fallback) - use identifier as key
                credential_json = self._memory_store.get(keychain_identifier)
            
            if credential_json:
                credentials = json.loads(credential_json)
                logger.info(f"Retrieved SAP credentials for identifier '{keychain_identifier}' -> {credentials.get('sap_username')}@{credentials.get('sap_host')}")
                return credentials
            else:
                logger.warning(f"No credentials found for identifier: {keychain_identifier}")
                return None
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in stored credentials for '{keychain_identifier}': {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve SAP credentials for '{keychain_identifier}': {e}")
            return None
    
    def delete_sap_credentials(self, credential_token: str) -> bool:
        """
        Delete SAP credentials
        
        Args:
            credential_token: Token of credentials to delete
            
        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            if self._keyring:
                # Delete from OS keychain
                self._keyring.delete_password(self.service_name, credential_token)
            else:
                # Delete from memory (fallback)
                if credential_token in self._memory_store:
                    del self._memory_store[credential_token]
            
            logger.info(f"Deleted SAP credentials for token: {credential_token[:8]}...")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete SAP credentials: {e}")
            return False
    
    def list_stored_credentials(self, user_id: str) -> list[Dict[str, str]]:
        """
        List all stored credentials for a user (metadata only, no passwords)
        
        Args:
            user_id: System user ID
            
        Returns:
            List of credential metadata
        """
        try:
            credentials_list = []
            
            if self._keyring:
                # For keyring, we can't easily list all keys, so this is limited
                logger.info("Keyring doesn't support listing - use specific credential tokens")
                return []
            else:
                # For memory store, we can list all
                for token, credential_json in self._memory_store.items():
                    try:
                        credentials = json.loads(credential_json)
                        if credentials.get('user_id') == user_id:
                            credentials_list.append({
                                'token': token,
                                'sap_host': credentials.get('sap_host'),
                                'sap_client': credentials.get('sap_client'),
                                'sap_username': credentials.get('sap_username'),
                                'stored_at': credentials.get('stored_at')
                            })
                    except Exception:
                        continue
            
            return credentials_list
            
        except Exception as e:
            logger.error(f"Failed to list credentials: {e}")
            return []
    
    def is_keyring_available(self) -> bool:
        """Check if OS keyring is available"""
        return self._keyring is not None
    
    def get_storage_info(self) -> Dict[str, Any]:
        """Get information about credential storage"""
        return {
            "keyring_available": self.is_keyring_available(),
            "storage_type": "OS Keychain" if self.is_keyring_available() else "In-Memory (Not Persistent)",
            "platform": platform.system(),
            "service_name": self.service_name,
            "security_note": "Credentials are encrypted by OS" if self.is_keyring_available() else "Credentials lost on restart"
        }
    
    def prompt_credentials_interactive(self, system_id: str = "default") -> Optional[str]:
        """
        Prompt user for SAP credentials interactively at startup.
        Credentials are stored in memory only (not persisted).
        
        This is designed for local Docker deployment where users cannot
        use OS keychain and don't want to pass credentials via env vars.
        
        Args:
            system_id: Identifier for the SAP system (used as keychain identifier)
            
        Returns:
            The keychain identifier if successful, None otherwise
        """
        try:
            print("\n" + "=" * 60)
            print("  SAP CREDENTIALS INPUT (Stored in memory only)")
            print("  Credentials will be cleared when container stops")
            print("=" * 60 + "\n")
            
            # Prompt for each field
            sap_host = input("SAP Host (e.g., sap.company.com:44300): ").strip()
            if not sap_host:
                print("ERROR: SAP Host is required")
                return None
            
            sap_client = input("SAP Client (e.g., 100): ").strip() or "100"
            
            sap_username = input("SAP Username: ").strip()
            if not sap_username:
                print("ERROR: SAP Username is required")
                return None
            
            # Use masked password input (shows * for each character)
            sap_password = _get_masked_password("SAP Password: ")
            if not sap_password:
                print("ERROR: SAP Password is required")
                return None
            
            sap_language = input("SAP Language (default: EN): ").strip() or "EN"
            
            # Store credentials in memory
            keychain_identifier = f"interactive-{system_id}"
            credential_data = {
                "sap_host": sap_host,
                "sap_client": sap_client,
                "sap_username": sap_username,
                "sap_password": sap_password,
                "sap_language": sap_language,
                "user_id": "interactive",
                "stored_at": str(datetime.now()),
                "credential_provider": "interactive"
            }
            
            credential_json = json.dumps(credential_data)
            self._memory_store[keychain_identifier] = credential_json
            
            print(f"\n✓ Credentials stored for {sap_username}@{sap_host} (identifier: {keychain_identifier})")
            logger.info(f"Interactive credentials stored for identifier: {keychain_identifier}")
            
            return keychain_identifier
            
        except KeyboardInterrupt:
            print("\n\nCredential input cancelled by user")
            return None
        except Exception as e:
            logger.error(f"Error during interactive credential prompt: {e}")
            print(f"\nERROR: Failed to store credentials: {e}")
            return None
    
    def prompt_credentials_multi_system(self, config_path: str) -> List[str]:
        """
        Prompt user for credentials for multiple SAP systems defined in a config file.
        The config file contains non-sensitive info (host, client), user provides passwords.
        
        Config file format (YAML):
        ```
        systems:
          S4H-DEV:
            host: s4h-dev.company.com
            client: 100
            description: Development System
          S4H-PROD:
            host: s4h-prod.company.com
            client: 200
            description: Production System
        ```
        
        Args:
            config_path: Path to the SAP systems YAML configuration file
            
        Returns:
            List of keychain identifiers for successfully stored credentials
        """
        try:
            import yaml
        except ImportError:
            logger.error("PyYAML not installed. Install with: pip install pyyaml")
            print("ERROR: PyYAML is required for multi-system configuration")
            return []
        
        try:
            # Load systems configuration
            if not os.path.exists(config_path):
                logger.error(f"SAP systems config file not found: {config_path}")
                print(f"ERROR: Config file not found: {config_path}")
                return []
            
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            systems = config.get('systems', {})
            if not systems:
                logger.error("No systems defined in config file")
                print("ERROR: No systems defined in configuration file")
                return []
            
            print("\n" + "=" * 60)
            print("  MULTI-SYSTEM SAP CREDENTIALS INPUT")
            print("  Credentials are stored in memory only")
            print("=" * 60)
            print(f"\nFound {len(systems)} SAP system(s) in configuration:\n")
            
            # List all systems
            for i, (system_id, system_config) in enumerate(systems.items(), 1):
                desc = system_config.get('description', 'No description')
                host = system_config.get('host', 'Unknown')
                print(f"  [{i}] {system_id}: {host} - {desc}")
            
            print("\n" + "-" * 60)
            
            stored_identifiers = []
            
            for system_id, system_config in systems.items():
                host = system_config.get('host')
                client = system_config.get('client', '100')
                description = system_config.get('description', '')
                
                if not host:
                    print(f"\nWARNING: Skipping {system_id} - no host configured")
                    continue
                
                print(f"\n[{system_id}] {host}")
                if description:
                    print(f"  {description}")
                
                # Ask if user wants to configure this system
                configure = input(f"  Configure credentials for {system_id}? (Y/n): ").strip().lower()
                if configure == 'n':
                    print(f"  Skipped {system_id}")
                    continue
                
                # Prompt for credentials
                sap_username = input(f"  SAP Username: ").strip()
                if not sap_username:
                    print(f"  Skipped {system_id} - no username provided")
                    continue
                
                sap_password = _get_masked_password(f"  SAP Password: ")
                if not sap_password:
                    print(f"  Skipped {system_id} - no password provided")
                    continue
                
                sap_language = input(f"  SAP Language (default: EN): ").strip() or "EN"
                
                # Store credentials
                keychain_identifier = system_id  # Use system_id directly as identifier
                credential_data = {
                    "sap_host": host,
                    "sap_client": str(client),
                    "sap_username": sap_username,
                    "sap_password": sap_password,
                    "sap_language": sap_language,
                    "user_id": "interactive",
                    "stored_at": str(datetime.now()),
                    "credential_provider": "interactive-multi",
                    "system_id": system_id,
                    "description": description
                }
                
                credential_json = json.dumps(credential_data)
                self._memory_store[keychain_identifier] = credential_json
                stored_identifiers.append(keychain_identifier)
                
                print(f"  ✓ Credentials stored for {system_id}")
                logger.info(f"Multi-system credentials stored for: {keychain_identifier}")
            
            print("\n" + "=" * 60)
            print(f"  Configured {len(stored_identifiers)} of {len(systems)} system(s)")
            print("=" * 60 + "\n")
            
            return stored_identifiers
            
        except KeyboardInterrupt:
            print("\n\nCredential input cancelled by user")
            return []
        except Exception as e:
            logger.error(f"Error during multi-system credential prompt: {e}")
            print(f"\nERROR: Failed to process multi-system credentials: {e}")
            return []
    
    def get_configured_systems(self) -> List[Dict[str, str]]:
        """
        Get list of all configured SAP systems (from memory store).
        Returns metadata only, no passwords.
        
        Returns:
            List of system info dictionaries
        """
        systems = []
        for identifier, credential_json in self._memory_store.items():
            try:
                credentials = json.loads(credential_json)
                systems.append({
                    'identifier': identifier,
                    'sap_host': credentials.get('sap_host'),
                    'sap_client': credentials.get('sap_client'),
                    'sap_username': credentials.get('sap_username'),
                    'description': credentials.get('description', ''),
                    'credential_provider': credentials.get('credential_provider', 'unknown')
                })
            except Exception:
                continue
        return systems


# Global keychain manager instance
keychain_manager = KeychainManager()