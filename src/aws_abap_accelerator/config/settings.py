"""
Configuration settings for the ABAP-Accelerator MCP Server.
Python equivalent of config.ts
"""

import os
from typing import Optional, List
from pydantic import Field, field_validator, ConfigDict
from pydantic_settings import BaseSettings
from enum import Enum

from utils.security import sanitize_for_logging, validate_sap_host
from utils.secret_reader import SecretReader
from utils.host_credential_manager import HostCredentialManager


class AuthType(str, Enum):
    BASIC = "basic"


class CredentialProvider(str, Enum):
    """Credential provider types for different deployment scenarios"""
    ENV = "env"                      # Environment variables (default)
    KEYCHAIN = "keychain"            # OS keychain (Windows Credential Manager/macOS Keychain)
    INTERACTIVE = "interactive"       # Interactive prompt at startup (single system)
    INTERACTIVE_MULTI = "interactive-multi"  # Interactive prompt with multi-system config file
    AWS_SECRETS = "aws_secrets"      # AWS Secrets Manager (for ECS/AgentCore)


class SAPConnectionSettings(BaseSettings):
    """SAP connection configuration"""
    host: str = Field(..., description="SAP host")
    instance_number: Optional[str] = Field(None, description="SAP instance number")
    client: str = Field("100", description="SAP client")
    username: Optional[str] = Field(None, description="SAP username")
    password: Optional[str] = Field(None, description="SAP password")
    language: str = Field("EN", description="SAP language")
    secure: bool = Field(True, description="Use HTTPS")
    auth_type: AuthType = Field(AuthType.BASIC, description="Authentication type (basic only)")
    
    model_config = ConfigDict(env_prefix="SAP_", case_sensitive=False)

    @field_validator('host')
    @classmethod
    def validate_host(cls, v):
        if not validate_sap_host(v):
            raise ValueError(f"Invalid or potentially unsafe SAP host: {sanitize_for_logging(v)}")
        return v

    @field_validator('instance_number')
    @classmethod
    def validate_instance_number(cls, v):
        if v is not None:
            try:
                instance_num = int(v)
                if instance_num < 0 or instance_num > 99:
                    raise ValueError(f"Invalid instance number: {v}. Must be between 00-99.")
            except ValueError:
                raise ValueError(f"Invalid instance number format: {v}")
        return v


class ServerSettings(BaseSettings):
    """HTTP server configuration"""
    host: str = Field("localhost", description="Server host")
    port: int = Field(8000, description="Server port")
    
    model_config = ConfigDict(env_prefix="SERVER_", case_sensitive=False)


class CORSSettings(BaseSettings):
    """CORS configuration"""
    cors_enabled: bool = Field(True, description="Enable CORS")
    allowed_origins: str = Field("*", description="Allowed origins (comma-separated)")
    
    model_config = ConfigDict(env_prefix="CORS_", case_sensitive=False)
    
    def get_origins_list(self) -> List[str]:
        """Get origins as a list"""
        if self.allowed_origins == "*":
            return ["*"]
        return [origin.strip() for origin in self.allowed_origins.split(",")]


class LoggingSettings(BaseSettings):
    """Logging configuration"""
    level: str = Field("INFO", description="Log level")
    file: Optional[str] = Field("mcp-server.log", description="Log file path")
    
    model_config = ConfigDict(env_prefix="LOG_", case_sensitive=False)


class SSLSettings(BaseSettings):
    """SSL/TLS configuration for SAP connections"""
    verify: bool = Field(True, description="Verify SSL certificates (set to false for testing only)")
    custom_ca_cert_path: Optional[str] = Field(None, description="Path to custom CA certificate file")
    
    model_config = ConfigDict(env_prefix="SSL_", case_sensitive=False)


class LocalDeploymentSettings(BaseSettings):
    """Settings for local Docker deployment"""
    credential_provider: str = Field("env", description="Credential provider: env, keychain, interactive, interactive-multi, aws_secrets")
    sap_systems_config_path: Optional[str] = Field(None, description="Path to SAP systems YAML config file for multi-system mode")
    
    model_config = ConfigDict(case_sensitive=False)


class Settings(BaseSettings):
    """Main application settings"""
    sap: SAPConnectionSettings = Field(default_factory=SAPConnectionSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    cors: CORSSettings = Field(default_factory=CORSSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    ssl: SSLSettings = Field(default_factory=SSLSettings)
    local_deployment: LocalDeploymentSettings = Field(default_factory=LocalDeploymentSettings)
    
    # Additional settings
    use_credential_manager: bool = Field(False, description="Use Windows Credential Manager")
    
    model_config = ConfigDict(env_file=".env", case_sensitive=False, extra='ignore')


def load_config() -> SAPConnectionSettings:
    """
    Load SAP connection configuration from environment variables.
    Python equivalent of loadConfig() from config.ts
    """
    # Check if we should use credential manager
    host = os.getenv("SAP_HOST")
    if host and os.getenv("USE_CREDENTIAL_MANAGER", "").lower() == "true":
        print(f"Looking up credentials for host: {sanitize_for_logging(host)}")
        
        credentials = HostCredentialManager.get_credentials_by_host(host)
        if credentials:
            print("Credentials loaded successfully from Windows Credential Manager")
            return SAPConnectionSettings(
                host=host,
                instance_number=os.getenv("SAP_INSTANCE_NUMBER"),
                client=os.getenv("SAP_CLIENT", "100"),
                username=credentials["username"],
                password=credentials["password"],
                language=os.getenv("SAP_LANGUAGE", "EN"),
                secure=os.getenv("SAP_SECURE", "true").lower() == "true",
                auth_type=AuthType.BASIC
            )
        print("No credentials found in Windows Credential Manager, falling back to environment variables")

    # Only support basic authentication
    auth_type = AuthType.BASIC

    # Validate required variables for basic auth
    required_vars = ["SAP_HOST", "SAP_CLIENT"]
    
    if not os.getenv("USE_CREDENTIAL_MANAGER"):
        required_vars.append("SAP_USERNAME")

    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

    # Get password from Docker secret or environment variable
    password = SecretReader.get_secret_or_env("sap_password", "SAP_PASSWORD") or ""
    
    return SAPConnectionSettings(
        host=os.getenv("SAP_HOST"),
        instance_number=os.getenv("SAP_INSTANCE_NUMBER"),
        client=os.getenv("SAP_CLIENT", "100"),
        username=os.getenv("SAP_USERNAME", ""),
        password=password,
        language=os.getenv("SAP_LANGUAGE", "EN"),
        secure=os.getenv("SAP_SECURE", "true").lower() == "true",
        auth_type=auth_type
    )


def validate_config(config: SAPConnectionSettings) -> None:
    """
    Validate SAP connection configuration.
    Python equivalent of validateConfig() from config.ts
    """
    print("Validating SAP connection configuration")
    
    if not config.host:
        raise ValueError("SAP host is required")
    
    if not config.client:
        raise ValueError("SAP client is required")
    
    # Only basic authentication is supported
    config.auth_type = AuthType.BASIC
    print("Using basic authentication")
    
    # For basic auth, we need username and password (skip check if using credential manager)
    if not os.getenv("USE_CREDENTIAL_MANAGER") and (not config.username or not config.password):
        raise ValueError("Basic authentication requires username and password")
    
    print(f"SAP connection configuration validated: {sanitize_for_logging(config.host)}"
          f"{f' (Instance: {sanitize_for_logging(config.instance_number)})' if config.instance_number else ''}, "
          f"Client: {sanitize_for_logging(config.client)}, "
          f"Auth: {sanitize_for_logging(config.auth_type.value)}")


def get_settings() -> Settings:
    """Get application settings"""
    return Settings()