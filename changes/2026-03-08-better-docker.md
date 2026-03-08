# `better-docker` — Docker modernization, fastmcp v3, STDIO transport

## Docker Build Modernization

- Rewrote `Dockerfile.simple` as a multi-stage build using `uv` (pinned `0.6.6`). Builder stage installs locked deps; runtime stage copies only the `.venv`. No pip/setuptools in the final image.
- Hardened runtime: non-root `appuser` with `/sbin/nologin`, `chmod 770` on writable dirs, exec-form `HEALTHCHECK`, OCI labels.
- New `src/docker-entrypoint.sh`: injects custom CA certs into the system trust store (if `CUSTOM_CA_CERT_PATH` is set), then drops to `appuser` via `gosu`.
- New `.dockerignore` with deny-all allowlist (`pyproject.toml`, `uv.lock`, `src/**` only).

## Package Management

- Added `pyproject.toml` as single source of truth for dependencies.
- Added `uv.lock` for reproducible installs.
- Bumped `fastmcp` from `>=2.14.0` to `~=3.1.0` in `requirements.txt`.

## STDIO Transport Support

- `enterprise_main.py` now reads `MCP_TRANSPORT` env var (`streamable-http` default, `stdio` for client-managed lifecycle).
- Transport-aware logging: HTTP-specific messages suppressed in STDIO mode.
- `stateless_http` set via both env var and runtime parameter for fastmcp v3 compatibility.
- Default transport changed from `sse` to `streamable-http` across both entry points.

## Environment Credential Loading

- When `CREDENTIAL_PROVIDER=env`, SAP env vars are now loaded into the in-memory keychain so the enterprise tool path (`_get_sap_client_keychain`) can find them.
- System identifier defaults to `env-{SAP_CLIENT}`, overridable with `DEFAULT_SAP_SYSTEM_ID`.
- Password read via `SecretReader` (Docker secrets first, then env var fallback).
- Added `KeychainManager.store_credentials_by_identifier()` public method.

## Async Tool Handlers (upstream merge)

- All MCP tool handlers in `fastmcp_server.py` converted from sync + `asyncio.create_task()` to proper `async def` + `await` (correct pattern for fastmcp v3).

## SAP Client Cookie Handling

- Switched to `aiohttp.DummyCookieJar` — cookies now managed manually via `Cookie` header.
- Basic auth requests now include session cookies alongside the `Authorization` header, fixing CSRF 403 errors on write operations.
- Added logging around set-cookie capture and missing cookie warnings.

## Build Tooling

- New `Makefile` with targets: `build`, `run`, `docker-export`, `clean`, `lint`, `lint-fix`, `lint-changed`, `lint-fix-changed`.
- Added `*.tar.gz` to `.gitignore`.

## Code Formatting

- `enterprise_main.py` reformatted: single→double quotes, line wrapping, trailing commas. Cosmetic only.

## Kiro Steering Files

- Added `.kiro/steering/product.md`, `structure.md`, `tech.md` for persistent project context.

## README

- Expanded with Quick Start guide (HTTP and STDIO modes), Docker loading instructions, Makefile usage, and reformatted tables.
