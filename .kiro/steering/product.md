# Product Overview

The ABAP Accelerator is an enterprise-grade Model Context Protocol (MCP) server that enables AI-powered SAP ABAP development through Amazon Q Developer and Kiro.

It exposes ~15 SAP development tools over MCP:
- SAP connection management and status checking
- ABAP object CRUD (classes, CDS views, behavior definitions, service bindings, etc.)
- Syntax checking and code activation (single and batch)
- ATC (ABAP Test Cockpit) quality checks with quickfix support
- Unit test execution with coverage
- Transport request management
- Custom code migration analysis
- Object search

The server supports two deployment modes:
- Standard mode (`main.py`): single-user, direct SAP connection via env vars
- Enterprise mode (`enterprise_main.py`): multi-tenant, supports principal propagation (X.509 cert auth) and keychain-based auth, designed for ECS Fargate deployment

Enterprise mode adds multi-tenancy via HTTP headers (`x-user-id`, `x-sap-system-id`, `x-team-id`), usage tracking, and OAuth integration (Cognito, Okta, Entra ID).

Target environments: DEV, SBX, QAS, TST systems only. Not intended for production SAP systems.
