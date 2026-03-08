# Tech Stack & Build

## Language & Runtime
- Python 3.12+ (required)
- Async-first architecture using `asyncio`

## Package Management
- `uv` for dependency management and virtual environments
- `pyproject.toml` is the source of truth for dependencies
- `uv.lock` for reproducible installs
- `requirements.txt` exists as a fallback

## Key Dependencies
- `fastmcp ~3.1.0` — MCP protocol framework (streamable-http and stdio transports)
- `fastapi` / `uvicorn` / `starlette` — HTTP server layer
- `pydantic` / `pydantic-settings` — data models and settings validation
- `aiohttp` / `httpx` / `requests` — HTTP clients for SAP ADT API calls
- `boto3` — AWS SDK (Secrets Manager, Parameter Store, IAM)
- `cryptography` — X.509 certificate generation for principal propagation
- `PyJWT` — OAuth/JWT token handling
- `defusedxml` / `xmltodict` — secure XML parsing (SAP ADT responses are XML)
- `python-dotenv` — `.env` file loading
- `PyYAML` — config file parsing
- `structlog` / `loguru` — structured logging

## Dev Dependencies
- `pytest` / `pytest-asyncio` — testing
- `ruff` — linting and formatting
- `mypy` — type checking

## Linting (Ruff)
Config in `pyproject.toml`:
- Target: Python 3.12
- Line length: 120
- Rules: E, F, I, W, UP, B, SIM, RUF (E501 ignored — handled by formatter)
- isort with `aws_abap_accelerator` as first-party

## Common Commands
```bash
# Install dependencies
uv sync

# Run linter
make lint
# or: uv run --group dev ruff check src/

# Auto-fix lint issues
make lint-fix
# or: uv run --group dev ruff check --fix src/

# Run tests
uv run --group dev pytest

# Build Docker image (linux/amd64)
make build

# Export Docker image as tarball
make docker-export

# Run interactive shell in container
make run

# Clean up
make clean
```

## Docker
- Multi-stage build using `Dockerfile.simple`
- Base image: `public.ecr.aws/docker/library/python:3.12-slim`
- Uses `uv` in builder stage for fast, locked installs
- Runtime drops to non-root `appuser` via `gosu`
- Entrypoint handles custom CA cert injection before starting the app
- Health check via `health_check.py`
