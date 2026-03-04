#!/usr/bin/env python3
"""
Enterprise MCP Server Entry Point
Wraps the existing ABAP-Accelerator server with enterprise features

Supports two authentication modes:
1. Principal Propagation (ENABLE_PRINCIPAL_PROPAGATION=true)
   - Uses IAM Identity Center for user identity
   - Generates ephemeral X.509 certificates for SAP authentication
   - Maps IAM identity to SAP username (algorithmic or exception-based)

2. Keychain-based (default)
   - Uses AWS Secrets Manager for SAP credentials
   - Service account authentication
"""

import asyncio
import logging
import sys
import os
import time
from pathlib import Path
from dotenv import load_dotenv
from typing import Optional, Any, Dict, Tuple
from datetime import datetime

# Load environment variables
load_dotenv()

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import existing server components (only settings, not the full server)
from config.settings import get_settings
from utils.logger import setup_logging

# Import enterprise components
from enterprise.middleware import enterprise_middleware
from enterprise.context_manager import enterprise_context_manager
from enterprise.usage_tracker import enterprise_usage_tracker
from auth.keychain_manager import keychain_manager

logger = logging.getLogger(__name__)

# OAuth manager (feature-flagged) - DEPRECATED, use FastMCP OAuth instead
_oauth_manager = None


def get_oauth_manager():
    """Get OAuth manager instance (lazy initialization) - DEPRECATED"""
    global _oauth_manager
    if _oauth_manager is None:
        from server.oauth_manager import oauth_manager

        _oauth_manager = oauth_manager
    return _oauth_manager


# FastMCP OAuth integration (NEW)
def get_fastmcp_oauth_provider():
    """Get FastMCP OAuth provider if configured"""
    try:
        from server.fastmcp_oauth_integration import create_oauth_provider

        return create_oauth_provider()
    except Exception as e:
        logger.error(f"OAuth: Error creating FastMCP OAuth provider: {e}")
        return None


class EnterpriseABAPAcceleratorServer:
    """
    Enterprise-enhanced ABAP Accelerator Server
    Supports both Principal Propagation (certificate-based) and Keychain authentication
    """

    def __init__(self, settings=None):
        # Don't initialize parent server to avoid loading .env SAP connection
        self.settings = settings
        self.mcp: Optional[Any] = None
        self.connected = False
        self.shutdown_event = asyncio.Event()

        # Enterprise-specific initialization
        self.enterprise_enabled = (
            os.getenv("ENABLE_ENTERPRISE_MODE", "false").lower() == "true"
        )

        # Principal Propagation configuration
        self.principal_propagation_enabled = (
            os.getenv("ENABLE_PRINCIPAL_PROPAGATION", "false").lower() == "true"
        )
        self._principal_propagation_service = None
        self._ca_loaded = False

        if self.enterprise_enabled:
            logger.info("ENTERPRISE: Starting in ENTERPRISE mode")
            logger.info(
                "ENTERPRISE: Features: Multi-tenancy, Context awareness, Usage tracking"
            )

        if self.principal_propagation_enabled:
            logger.info(
                "AUTH: Principal Propagation ENABLED - using certificate-based authentication"
            )
            logger.info(
                "AUTH: IAM Identity -> SAP Username mapping with ephemeral X.509 certificates"
            )
        else:
            logger.info(
                "AUTH: Using Keychain-based authentication (set ENABLE_PRINCIPAL_PROPAGATION=true for cert auth)"
            )

    async def _initialize_principal_propagation(self) -> bool:
        """Initialize principal propagation service with CA certificate"""
        if not self.principal_propagation_enabled:
            return False

        try:
            from auth.principal_propagation import PrincipalPropagationService

            self._principal_propagation_service = PrincipalPropagationService()

            # Try to load CA from AWS Secrets Manager first
            try:
                success = await self._principal_propagation_service.initialize()
                if success and self._principal_propagation_service.is_ready():
                    self._ca_loaded = True
                    logger.info(
                        "AUTH: Principal Propagation initialized from AWS Secrets Manager"
                    )
                    return True
            except Exception as e:
                logger.warning(f"AUTH: Could not load CA from Secrets Manager: {e}")

            # Fallback: Try to load from local files
            ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca-certificate.pem")
            ca_key_path = os.getenv("CA_KEY_PATH", "certs/ca-private-key.pem")

            if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
                with open(ca_cert_path, "r", encoding="utf-8") as f:
                    ca_cert = f.read()
                with open(ca_key_path, "r", encoding="utf-8") as f:
                    ca_key = f.read()

                success = self._principal_propagation_service.set_ca_credentials_local(
                    ca_cert, ca_key
                )
                if success:
                    self._ca_loaded = True
                    logger.info(
                        f"AUTH: Principal Propagation initialized from local files: {ca_cert_path}"
                    )

                    # Load user exceptions if configured
                    exceptions_file = os.getenv(
                        "USER_EXCEPTIONS_FILE", "config/user-exceptions.yaml"
                    )
                    if os.path.exists(exceptions_file):
                        import yaml

                        with open(exceptions_file, "r", encoding="utf-8") as f:
                            exceptions_data = yaml.safe_load(f)
                            self._principal_propagation_service.set_local_configuration(
                                user_exceptions=exceptions_data.get("exceptions", {})
                            )

                    return True

            logger.error(
                "AUTH: Failed to initialize Principal Propagation - CA certificate not found"
            )
            return False

        except Exception as e:
            logger.error(f"AUTH: Failed to initialize Principal Propagation: {e}")
            return False

    async def _get_sap_client_and_context(
        self, user_id: str = None, system_id: str = None, login_identifier: str = None
    ) -> Tuple[Any, Dict[str, Any]]:
        """
        Get SAP client using the appropriate authentication method.

        Args:
            user_id: IAM identity (email) for principal propagation - REQUIRED for principal propagation
            system_id: SAP system identifier (e.g., S4H-100) - from request headers
            login_identifier: Pass-through value for certificate CN (what user typed to login)

        Returns:
            Tuple of (sap_client, context_info)

        Note:
            - For principal propagation: user_id must be the IAM Identity Center email
            - login_identifier is used as certificate CN for SAP CERTRULE mapping
        """
        # System ID is required and should come from headers
        if not system_id:
            raise ValueError("x-sap-system-id header is required")

        if self.principal_propagation_enabled and self._ca_loaded:
            if not user_id:
                raise ValueError(
                    "User identity (IAM email) is required for principal propagation"
                )
            return await self._get_sap_client_principal_propagation(
                user_id, system_id, login_identifier
            )
        else:
            return await self._get_sap_client_keychain(
                user_id or "service-account", system_id
            )

    async def _get_sap_client_principal_propagation(
        self, iam_identity: str, system_id: str, login_identifier: str = None
    ) -> Tuple[Any, Dict[str, Any]]:
        """Get SAP client using principal propagation (certificate auth)"""
        from sap.sap_client import SAPADTClient
        from sap_types.sap_types import SAPConnection

        # Use login_identifier for pass-through CN, fallback to iam_identity
        # This is what the user typed to login (email, username, employee ID, etc.)
        if not login_identifier:
            login_identifier = iam_identity

        # Get SAP credentials from principal propagation service
        # This loads SAP endpoint (host, port, client) from Parameter Store
        # and generates ephemeral certificate with login_identifier as CN
        credentials = (
            await self._principal_propagation_service.get_sap_credentials_for_request(
                iam_identity=iam_identity,
                login_identifier=login_identifier,  # Pass-through for certificate CN
                sap_system_id=system_id,
            )
        )

        sap_host = credentials["sap_host"]
        sap_port = credentials["sap_port"]
        sap_client_num = str(
            credentials["sap_client"]
        )  # Ensure string for SAPConnection
        sap_username = credentials["sap_username"]
        cert_pem = credentials["cert_pem"]
        key_pem = credentials["key_pem"]

        logger.info(
            f"AUTH: Principal Propagation - {iam_identity} -> {sap_username}@{sap_host}:{sap_port}"
        )

        # Create SAP connection with certificate
        sap_connection = SAPConnection(
            host=sap_host,
            client=sap_client_num,
            username=sap_username,
            password="",  # Not needed for cert auth
            language="EN",
            secure=True,
        )

        # Create SAP client
        sap_client_instance = SAPADTClient(sap_connection)

        # Store certificate data for use in requests
        sap_client_instance.client_certificate_pem = cert_pem
        sap_client_instance.client_private_key_pem = key_pem
        sap_client_instance.use_certificate_auth = True
        sap_client_instance.sap_port = sap_port

        # Connect to SAP
        connected = await sap_client_instance.connect()
        if not connected:
            raise ValueError(
                f"Failed to connect to SAP system {sap_host}:{sap_port} with certificate auth"
            )

        context_info = {
            "iam_identity": iam_identity,
            "sap_username": sap_username,
            "sap_host": sap_host,
            "sap_port": sap_port,
            "sap_client": sap_client_num,
            "auth_mode": "principal_propagation",
            "authenticated_at": datetime.now().isoformat(),
        }

        return sap_client_instance, context_info

    async def _get_sap_client_keychain(
        self, user_id: str, system_id: str
    ) -> Tuple[Any, Dict[str, Any]]:
        """Get SAP client using keychain credentials"""
        from sap.sap_client import SAPADTClient
        from sap_types.sap_types import SAPConnection

        # Try different identifier patterns
        identifiers = [system_id, f"sap-{system_id}", system_id.replace("sap-", "")]

        credentials = None
        used_identifier = None
        for identifier in identifiers:
            credentials = keychain_manager.get_sap_credentials_by_identifier(identifier)
            if credentials:
                used_identifier = identifier
                break

        if not credentials:
            raise ValueError(
                f"No SAP credentials found for system '{system_id}'. Tried: {identifiers}"
            )

        logger.info(
            f"AUTH: Keychain - {user_id} using credentials for {used_identifier}"
        )

        # Create SAP connection (port should be included in host, e.g., sap.company.com:44300)
        sap_connection = SAPConnection(
            host=credentials["sap_host"],
            client=credentials["sap_client"],
            username=credentials["sap_username"],
            password=credentials["sap_password"],
            language=credentials.get("sap_language", "EN"),
            secure=credentials.get("sap_secure", "true").lower() == "true",
        )

        # Create and connect SAP client
        sap_client_instance = SAPADTClient(sap_connection)
        connected = await sap_client_instance.connect()

        if not connected:
            raise ValueError(
                f"Failed to connect to SAP system {credentials['sap_host']}"
            )

        context_info = {
            "iam_identity": user_id,
            "sap_username": credentials["sap_username"],
            "sap_host": credentials["sap_host"],
            "sap_client": credentials["sap_client"],
            "keychain_identifier": used_identifier,
            "auth_mode": "keychain",
            "authenticated_at": datetime.now().isoformat(),
        }

        return sap_client_instance, context_info

    def _setup_mcp(self) -> None:
        """Set up FastMCP application without default SAP connection"""
        from fastmcp import FastMCP

        # Try to get FastMCP OAuth provider first (NEW approach)
        oauth_provider = get_fastmcp_oauth_provider()

        if oauth_provider:
            logger.info("OAuth: Using FastMCP's built-in OAuth (OAuthProxy)")
            # Initialize FastMCP with OAuth
            self.mcp = FastMCP(
                name="ABAP-Accelerator-Enterprise",
                auth=oauth_provider,  # FastMCP handles OAuth flow!
            )
        else:
            logger.info("OAuth: FastMCP OAuth not configured, using stateless HTTP")
            # Initialize FastMCP without OAuth (backward compatible)
            self.mcp = FastMCP("ABAP-Accelerator-Enterprise")

            # Try legacy OAuth manager (OLD approach - for backward compatibility)
            oauth_mgr = get_oauth_manager()
            if oauth_mgr.enabled:
                logger.info("OAuth: Initializing legacy OAuth flow...")
                import asyncio

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(oauth_mgr.initialize())
                    if oauth_mgr.is_enabled():
                        logger.info("OAuth: Legacy OAuth flow initialized successfully")
                    else:
                        logger.warning(
                            "OAuth: Legacy OAuth flow initialization failed, continuing without OAuth"
                        )
                finally:
                    loop.close()

        # Add health check endpoint
        self._add_health_endpoint()

        # Register basic tools first (without middleware)
        self._register_basic_tools()

        # Always register SAP tools (they work in both enterprise and standard mode)
        self._register_sap_tools()

        if self.enterprise_enabled:
            # Register enterprise management tools (hidden from Q Developer)
            self._register_enterprise_tools()
            logger.info("ENTERPRISE: Enterprise management tools registered")

        logger.info("FastMCP server configured successfully - SAP tools available")

    def _add_health_endpoint(self):
        """Add health check endpoint to FastMCP server"""
        try:
            # Add a simple health check tool that can be accessed via HTTP
            @self.mcp.tool()
            def health_check() -> dict:
                """Health check endpoint for container orchestration"""
                from datetime import datetime

                return {
                    "status": "healthy",
                    "timestamp": datetime.utcnow().isoformat(),
                    "version": "1.0.0",
                    "service": "ABAP-Accelerator-Enterprise",
                    "enterprise_mode": self.enterprise_enabled,
                    "principal_propagation": self.principal_propagation_enabled,
                    "ca_loaded": getattr(self, "_ca_loaded", False),
                }

            logger.info("HEALTH: Health check tool registered")

            # Try to add HTTP endpoint if possible
            # This is a workaround since FastMCP doesn't expose the FastAPI app directly
            # We'll need to use a different approach

        except Exception as e:
            logger.error(f"HEALTH: Error adding health endpoint: {e}")

    def _register_basic_tools(self):
        """Register basic test tools (hidden from Q Developer)"""
        if not self.mcp:
            return

        # These are internal test tools - not exposed to Q Developer
        logger.info(
            "BASIC: Internal test tools registered (hidden from Q Developer interface)"
        )

    def _register_sap_tools(self):
        """Register core SAP tools for ABAP developers with principal propagation support"""
        if not self.mcp:
            return

        # Import and register tools from the dedicated module
        from enterprise_main_tools import register_sap_tools

        register_sap_tools(self.mcp, self)

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown"""
        import signal

        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating shutdown...")
            self.shutdown_event.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def run_sync(self, transport: str = "streamable-http") -> None:
        """Run the MCP server"""
        # Initialize principal propagation if enabled
        if self.principal_propagation_enabled:
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._initialize_principal_propagation())
            finally:
                loop.close()

        # Set up MCP
        self._setup_mcp()
        self._setup_signal_handlers()

        logger.info(
            f"Starting Enterprise ABAP-Accelerator MCP server on {self.settings.server.host}:{self.settings.server.port}"
        )
        logger.info(
            f"Health check available via MCP protocol at: http://{self.settings.server.host}:{self.settings.server.port}/mcp"
        )
        logger.info(
            f"Transport: {transport} (Streamable HTTP for Q Developer compatibility)"
        )

        # Check if FastMCP OAuth is configured
        from server.fastmcp_oauth_integration import is_fastmcp_oauth_available

        if is_fastmcp_oauth_available():
            logger.info(
                f"OAuth: FastMCP OAuth ENABLED - automatic browser authentication available"
            )
            logger.info(
                f"OAuth: Callback URL: {os.getenv('SERVER_BASE_URL')}/oauth/callback"
            )
        else:
            logger.info(
                f"OAuth: OAuth flow DISABLED - using header-based authentication"
            )

        try:
            # Use FastMCP's Streamable HTTP transport for Q Developer
            self.mcp.run(
                transport=transport,
                host=self.settings.server.host,
                port=self.settings.server.port,
                stateless_http=True,
            )
        except KeyboardInterrupt:
            logger.info("Server interrupted by user")
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            raise
        finally:
            logger.info("Server stopped")

    def run(self, transport: str = "sse") -> None:
        """Run the MCP server (synchronous wrapper)"""
        try:
            self.run_sync(transport)
        except KeyboardInterrupt:
            logger.info("Server interrupted by user")
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            sys.exit(1)

    async def _cleanup(self) -> None:
        """Cleanup resources"""
        try:
            # Cleanup enterprise resources
            if self.enterprise_enabled:
                logger.info("ENTERPRISE: Cleaning up enterprise resources...")
                enterprise_context_manager.cleanup_expired_contexts()

                # Export final usage stats
                stats = enterprise_usage_tracker.get_overall_stats()
                logger.info(f"ENTERPRISE: Final usage stats: {stats}")

            logger.info("Cleanup completed")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def _register_enterprise_tools(self):
        """Register enterprise-specific management tools (hidden from developers)"""
        if not self.mcp:
            return

        # Only register internal monitoring tools - these won't be exposed to Q Developer
        # They can be accessed via direct API calls for admin purposes

        logger.info(
            "ENTERPRISE: Enterprise management tools registered (hidden from Q Developer interface)"
        )


def _initialize_interactive_credentials() -> bool:
    """
    Initialize credentials using interactive prompt if configured.
    This is for local Docker deployment where users can't use OS keychain
    and don't want to pass credentials via environment variables.

    Returns:
        True if credentials were initialized (or not needed), False on error
    """
    credential_provider = os.getenv("CREDENTIAL_PROVIDER", "env").lower()
    principal_propagation = (
        os.getenv("ENABLE_PRINCIPAL_PROPAGATION", "false").lower() == "true"
    )

    # Skip interactive prompt if using principal propagation (AWS/ECS deployment)
    if principal_propagation:
        logger.info(
            "AUTH: Principal propagation enabled - skipping interactive credential prompt"
        )
        return True

    # Handle different credential providers
    if credential_provider == "interactive":
        logger.info(
            "AUTH: Interactive credential provider - prompting for SAP credentials"
        )
        identifier = keychain_manager.prompt_credentials_interactive()
        if identifier:
            logger.info(f"AUTH: Credentials stored with identifier: {identifier}")
            # Set default system ID for tools to use
            os.environ["DEFAULT_SAP_SYSTEM_ID"] = identifier
            return True
        else:
            logger.error("AUTH: Failed to get credentials interactively")
            return False

    elif credential_provider == "interactive-multi":
        config_path = os.getenv(
            "SAP_SYSTEMS_CONFIG_PATH", "/app/config/sap-systems.yaml"
        )
        logger.info(
            f"AUTH: Multi-system interactive credential provider - config: {config_path}"
        )

        identifiers = keychain_manager.prompt_credentials_multi_system(config_path)
        if identifiers:
            logger.info(
                f"AUTH: Credentials stored for {len(identifiers)} system(s): {identifiers}"
            )
            # Set first system as default
            os.environ["DEFAULT_SAP_SYSTEM_ID"] = identifiers[0]
            return True
        else:
            logger.error("AUTH: No credentials configured for any system")
            return False

    elif credential_provider in ("env", "keychain", "aws_secrets"):
        # These providers don't need interactive prompt
        logger.info(f"AUTH: Using credential provider: {credential_provider}")

        # For 'env' provider: load SAP_* env vars into the in-memory keychain
        # so the enterprise tool path (_get_sap_client_keychain) can find them.
        if credential_provider == "env":
            from utils.secret_reader import SecretReader

            sap_host = os.getenv("SAP_HOST", "")
            sap_client = os.getenv("SAP_CLIENT", "")
            sap_username = os.getenv("SAP_USERNAME", "")
            sap_password = (
                SecretReader.get_secret_or_env("sap_password", "SAP_PASSWORD") or ""
            )
            sap_language = os.getenv("SAP_LANGUAGE", "EN")
            sap_instance = os.getenv("SAP_INSTANCE_NUMBER", "00")

            if sap_host and sap_username:
                # Build a system identifier from host + client
                system_id = os.getenv("DEFAULT_SAP_SYSTEM_ID", f"env-{sap_client}")
                credential_data = {
                    "sap_host": sap_host,
                    "sap_client": sap_client,
                    "sap_username": sap_username,
                    "sap_password": sap_password,
                    "sap_language": sap_language,
                    "sap_instance_number": sap_instance,
                    "sap_secure": os.getenv("SAP_SECURE", "true"),
                }
                import json

                keychain_manager._memory_store[system_id] = json.dumps(credential_data)
                os.environ.setdefault("DEFAULT_SAP_SYSTEM_ID", system_id)
                logger.info(
                    f"AUTH: Loaded env credentials into keychain as '{system_id}' for {sap_username}@{sap_host}"
                )
            else:
                logger.warning(
                    "AUTH: CREDENTIAL_PROVIDER=env but SAP_HOST or SAP_USERNAME not set"
                )

        return True

    else:
        logger.warning(
            f"AUTH: Unknown credential provider: {credential_provider}, defaulting to 'env'"
        )
        return True


def main():
    """Main entry point for enterprise MCP server"""
    try:
        # Setup logging
        setup_logging()
        logger.info("🚀 Starting Enterprise ABAP-Accelerator MCP Server")

        # Log SSL/TLS configuration
        ssl_verify = os.getenv("SSL_VERIFY", "true").lower()
        custom_ca = os.getenv("CUSTOM_CA_CERT_PATH") or os.getenv("SSL_CERT_FILE")
        if ssl_verify in ("false", "0", "no"):
            logger.warning("⚠️  SSL verification DISABLED - this is insecure!")
        if custom_ca:
            logger.info(f"SSL: Custom CA certificate configured: {custom_ca}")

        # Check enterprise mode
        enterprise_mode = os.getenv("ENABLE_ENTERPRISE_MODE", "false").lower() == "true"

        if enterprise_mode:
            logger.info("ENTERPRISE: Enterprise Mode: ENABLED")
            logger.info(
                "ENTERPRISE: Multi-tenant HTTP server - context extracted from request headers"
            )
            logger.info(
                "ENTERPRISE: Expected headers: x-user-id, x-sap-system-id, x-team-id, x-session-id"
            )
        else:
            logger.info(
                "ENTERPRISE: Enterprise Mode: DISABLED (set ENABLE_ENTERPRISE_MODE=true to enable)"
            )

        # Initialize interactive credentials if configured (for local Docker deployment)
        # This MUST happen before server starts, and only when NOT using principal propagation
        if not _initialize_interactive_credentials():
            logger.error("❌ Failed to initialize credentials - exiting")
            sys.exit(1)

        # Log configured systems
        configured_systems = keychain_manager.get_configured_systems()
        if configured_systems:
            logger.info(f"AUTH: {len(configured_systems)} SAP system(s) configured:")
            for sys_info in configured_systems:
                logger.info(
                    f"  - {sys_info['identifier']}: {sys_info['sap_username']}@{sys_info['sap_host']}"
                )

        # Create minimal settings for enterprise mode (no SAP validation required)
        class MinimalSettings:
            def __init__(self):
                self.server = type(
                    "Server",
                    (),
                    {
                        # nosec B104 - Binding to 0.0.0.0 is intentional for containerized deployments (ECS/Docker/Kubernetes)
                        "host": os.getenv("SERVER_HOST", "0.0.0.0"),
                        "port": int(os.getenv("SERVER_PORT", "8000")),
                    },
                )()

        settings = MinimalSettings()

        # Create enhanced server
        server = EnterpriseABAPAcceleratorServer(settings)

        # Run server with same transport as original
        logger.info(
            "SERVER: Starting HTTP server with Streamable HTTP transport for Q Developer..."
        )
        logger.info(
            f"SERVER: Server will be available at: http://{settings.server.host}:{settings.server.port}"
        )
        logger.info(
            "SERVER: Multi-tenant: Each HTTP request can have different user/system context via headers"
        )
        server.run("streamable-http")

    except KeyboardInterrupt:
        logger.info("👋 Server stopped by user")
    except Exception as e:
        logger.error(f"❌ Server error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
