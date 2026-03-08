# Project Structure

All application code lives under `src/aws_abap_accelerator/`.

```
src/aws_abap_accelerator/
├── main.py                  # Standard mode entry point (single-user, direct SAP connection)
├── enterprise_main.py       # Enterprise mode entry point (multi-tenant, principal propagation)
├── enterprise_main_tools.py # MCP tool registration for enterprise mode
├── health_check.py          # Docker health check endpoint
│
├── config/
│   └── settings.py          # Pydantic settings models, env var loading, config validation
│
├── server/                  # MCP server setup and HTTP layer
│   ├── fastmcp_server.py    # Standard FastMCP server (ABAPAcceleratorServer class)
│   ├── tool_handlers.py     # MCP tool handler implementations
│   ├── middleware.py         # HTTP middleware
│   ├── health.py            # Health endpoint
│   ├── oauth_manager.py     # Legacy OAuth manager
│   ├── oauth_callback.py    # OAuth callback handler
│   ├── oauth_helpers.py     # OAuth utility functions
│   ├── oidc_discovery.py    # OIDC discovery
│   └── fastmcp_oauth_integration.py  # FastMCP OAuth provider integration
│
├── sap/                     # SAP ADT API client layer
│   ├── sap_client.py        # Core SAP ADT HTTP client (SAPADTClient)
│   ├── core/                # Low-level SAP operations
│   │   ├── connection.py    # Connection management
│   │   ├── source_manager.py    # Source code read/write
│   │   ├── activation_manager.py # Object activation
│   │   └── object_manager.py    # Object CRUD
│   ├── class_handler.py     # ABAP class operations
│   ├── cds_handler.py       # CDS view operations
│   ├── behavior_definition_handler.py  # BDEF operations
│   ├── service_binding_handler.py      # SRVB operations
│   └── service_definition_handler.py   # SRVD operations
│
├── sap_types/
│   └── sap_types.py         # Pydantic models for all SAP object types, requests, and results
│
├── auth/                    # Authentication subsystem
│   ├── types.py             # Auth enums and dataclasses
│   ├── keychain_manager.py  # In-memory credential store
│   ├── session_manager.py   # Session management
│   ├── sap_auth_helper.py   # SAP authentication helpers
│   ├── sap_client_factory.py # SAP client creation with auth
│   ├── principal_propagation.py          # X.509 cert-based auth service
│   ├── principal_propagation_middleware.py # Middleware for cert auth
│   ├── iam_identity_validator.py         # IAM identity validation
│   ├── rbac_manager.py      # Role-based access control
│   ├── multi_system_manager.py # Multi-SAP-system management
│   ├── mcp_tools.py         # Auth-related MCP tools
│   ├── integration.py       # Auth integration helpers
│   └── providers/           # Auth provider implementations
│       ├── base.py          # Base auth provider
│       ├── basic_auth.py
│       ├── certificate_auth.py
│       ├── certificate_auth_provider.py
│       ├── reentrance_ticket_auth.py
│       └── saml_sso.py
│
├── enterprise/              # Enterprise mode features
│   ├── context_manager.py   # Multi-tenant context management
│   ├── middleware.py         # Enterprise middleware
│   ├── sap_client_factory.py # Enterprise SAP client factory
│   └── usage_tracker.py     # Usage tracking/analytics
│
└── utils/                   # Shared utilities
    ├── logger.py            # Logging setup, RAPLogger for SAP-specific logging
    ├── security.py          # Input sanitization, host validation
    ├── secret_reader.py     # Docker secrets / env var reader
    ├── host_credential_manager.py # OS keychain integration
    ├── response_optimizer.py # Response formatting
    └── xml_utils.py         # XML parsing helpers (uses defusedxml)
```

## Key Patterns
- Entry points (`main.py`, `enterprise_main.py`) create a server instance and call `server.run()`
- MCP tools are registered as decorated functions on the `FastMCP` instance
- SAP interactions go through `SAPADTClient` which wraps HTTP calls to the SAP ADT REST API
- All data models use Pydantic (`BaseModel` for API types, `BaseSettings` for config)
- Auth types use dataclasses; SAP types use Pydantic models
- Settings are loaded from env vars with `pydantic-settings` (prefix-based: `SAP_`, `SERVER_`, `SSL_`, etc.)
- XML responses from SAP are parsed with `defusedxml` for security
- All user-facing strings in logs are sanitized via `utils/security.py`
