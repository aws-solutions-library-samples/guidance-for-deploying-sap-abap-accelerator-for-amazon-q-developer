# ABAP Accelerator MCP Server

Enterprise-grade Model Context Protocol (MCP) server for SAP ABAP development, enabling AI-powered coding assistance through Amazon Q Developer and Kiro.

## Table of Contents

- [ABAP Accelerator MCP Server](#abap-accelerator-mcp-server)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Deployment Options](#deployment-options)
  - [Environment Guidance](#environment-guidance)
- [Option 1: Local Deployment (Without Docker)](#option-1-local-deployment-without-docker)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
  - [Environment Variables](#environment-variables)
  - [Q Developer / Kiro Configuration](#q-developer--kiro-configuration)
- [Option 2: Local Deployment (With Docker)](#option-2-local-deployment-with-docker)
  - [Prerequisites](#prerequisites-1)
  - [Building the Docker Image](#building-the-docker-image)
  - [Loading a Pre-Built Image](#loading-a-pre-built-image)
  - [Deployment Scenarios](#deployment-scenarios)
    - [Quick Start: Single SAP System with Environment Variables](#quick-start-single-sap-system-with-environment-variables)
      - [Option A: Standalone HTTP Server](#option-a-standalone-http-server)
      - [Option B: STDIO Mode (MCP Client Manages the Container)](#option-b-stdio-mode-mcp-client-manages-the-container)
        - [Step 2: Run Container with Config Mounted](#step-2-run-container-with-config-mounted)
        - [Step 3: Enter Credentials at Startup](#step-3-enter-credentials-at-startup)
        - [sap-systems.yaml Location Summary](#sap-systemsyaml-location-summary)
    - [Option 3: Central Deployment (ECS Fargate)](#option-3-central-deployment-ecs-fargate)
  - [Environment Variables Reference](#environment-variables-reference)
    - [Core Server Configuration](#core-server-configuration)
    - [Credential Provider Options](#credential-provider-options)
    - [SAP Connection (for `env` credential provider)](#sap-connection-for-env-credential-provider)
    - [Enterprise Mode (ECS/Production)](#enterprise-mode-ecsproduction)
    - [SSL/TLS Configuration](#ssltls-configuration)
    - [OAuth Configuration (Optional)](#oauth-configuration-optional)
  - [Q Developer Configuration](#q-developer-configuration)
    - [Local Docker Deployment](#local-docker-deployment)
      - [Single System](#single-system)
      - [Multiple Systems](#multiple-systems)
    - [ECS Fargate Deployment](#ecs-fargate-deployment)
    - [With OAuth Authentication](#with-oauth-authentication)
  - [Kiro Configuration](#kiro-configuration)
    - [Local Deployment](#local-deployment)
    - [Multiple Systems](#multiple-systems-1)
    - [ECS/Remote Deployment](#ecsremote-deployment)
  - [ECS Fargate Deployment](#ecs-fargate-deployment-1)
    - [Credential Storage: Secrets Manager vs Parameter Store](#credential-storage-secrets-manager-vs-parameter-store)
      - [AWS Secrets Manager (Sensitive Data)](#aws-secrets-manager-sensitive-data)
        - [1. CA Certificate (for Principal Propagation)](#1-ca-certificate-for-principal-propagation)
        - [2. OAuth Client Secret (for Principal Propagation with OAuth)](#2-oauth-client-secret-for-principal-propagation-with-oauth)
      - [AWS Parameter Store (Non-Sensitive Configuration)](#aws-parameter-store-non-sensitive-configuration)
        - [1. SAP Endpoints Configuration](#1-sap-endpoints-configuration)
        - [2. User Exception Mappings (for Principal Propagation)](#2-user-exception-mappings-for-principal-propagation)
      - [Storage Summary Table](#storage-summary-table)
    - [Prerequisites](#prerequisites-2)
    - [Step 1: Push Docker Image to ECR](#step-1-push-docker-image-to-ecr)
    - [Step 2: Create Secrets and Parameters](#step-2-create-secrets-and-parameters)
    - [Step 3: Create ECS Task Definition](#step-3-create-ecs-task-definition)
    - [Step 4: Create IAM Roles](#step-4-create-iam-roles)
      - [Task Role Policy (for application to access AWS resources)](#task-role-policy-for-application-to-access-aws-resources)
      - [Execution Role Policy (for ECS to pull images and write logs)](#execution-role-policy-for-ecs-to-pull-images-and-write-logs)
    - [Step 5: Deploy Service](#step-5-deploy-service)
  - [OAuth Authentication Setup (for Principal Propagation)](#oauth-authentication-setup-for-principal-propagation)
    - [Supported Identity Providers](#supported-identity-providers)
    - [How It Works](#how-it-works)
    - [AWS Cognito Configuration](#aws-cognito-configuration)
    - [Okta Configuration](#okta-configuration)
    - [Microsoft Entra ID Configuration](#microsoft-entra-id-configuration)
  - [SAP System Selection](#sap-system-selection)
    - [Example Usage](#example-usage)
  - [SAP Port Configuration](#sap-port-configuration)
    - [Local Deployment (sap-systems.yaml)](#local-deployment-sap-systemsyaml)
    - [ECS Deployment (Parameter Store)](#ecs-deployment-parameter-store)
  - [Available Tools](#available-tools)
  - [Troubleshooting](#troubleshooting)
    - [SSL Certificate Errors](#ssl-certificate-errors)
    - [Connection Timeout](#connection-timeout)
    - [OAuth Not Working](#oauth-not-working)
    - [No User Identity Found](#no-user-identity-found)
  - [Security Recommendations](#security-recommendations)
    - [Authentication \& Authorization](#authentication--authorization)
      - [Local Development](#local-development)
      - [ECS Based Deployment](#ecs-based-deployment)
    - [Secrets Management](#secrets-management)
    - [Network Security](#network-security)
    - [Input Validation](#input-validation)
    - [Audit Logging](#audit-logging)
    - [Container Security](#container-security)
    - [Denial of Service Protection](#denial-of-service-protection)
    - [SAP System Security](#sap-system-security)
    - [Monitoring \& Incident Response](#monitoring--incident-response)
    - [Compliance Considerations](#compliance-considerations)
    - [CA Private Key Protection](#ca-private-key-protection)
    - [SAP Trust Store \& Certificate Rule Governance](#sap-trust-store--certificate-rule-governance)
    - [Code Change Control](#code-change-control)
    - [Identity Provider Hardening](#identity-provider-hardening)
    - [Intellectual Property \& Data Loss Prevention](#intellectual-property--data-loss-prevention)
    - [Supply Chain Integrity](#supply-chain-integrity)
    - [DNS Rebinding Prevention](#dns-rebinding-prevention)
    - [Denial of Service Resilience](#denial-of-service-resilience)
    - [LLM Tool Safety \& Human Oversight](#llm-tool-safety--human-oversight)
    - [Assumptions](#assumptions)
    - [Security Checklist for ECS Based Deployment](#security-checklist-for-ecs-based-deployment)
      - [Pre-Deployment](#pre-deployment)
      - [Deployment](#deployment)
      - [Post-Deployment](#post-deployment)
  - [Configuration Comparison: Local vs ECS](#configuration-comparison-local-vs-ecs)
  - [Code of Conduct](#code-of-conduct)
  - [Support](#support)
  - [Terms of Use](#terms-of-use)
  - [Notices](#notices)
  - [License](#license)

## Overview

The ABAP Accelerator provides 15 SAP development tools accessible via MCP protocol:
- Connection management and status checking
- ABAP object creation, retrieval, and modification
- Syntax checking and code activation
- ATC quality checks and unit testing
- Transport request management
- Migration analysis

## Deployment Options

| Option                                                                        | Use Case              | Authentication                | Best For                           |
| ----------------------------------------------------------------------------- | --------------------- | ----------------------------- | ---------------------------------- |
| [1. Local (Without Docker)](#option-1-local-deployment-without-docker)        | Development/testing   | Interactive credentials       | Quick testing, development         |
| [2. Local (With Docker)](#option-2-local-deployment-with-docker)              | Development/testing   | Interactive credentials       | Isolated environment, multi-system |
| [3. ECS Fargate](#option-3-ecs-fargate-deployment-with-principal-propagation) | Production/multi-user | Principal Propagation + OAuth | Enterprise, multi-user             |

---

## Environment Guidance

The ABAP Accelerator is designed for specific SAP system types. Please follow this guidance when deploying:

| ✅ Intended              | ❌ Not Recommended |
| ----------------------- | ----------------- |
| Development (DEV)       | Production (PRD)  |
| Sandbox (SBX)           | Pre-production    |
| Quality Assurance (QAS) |                   |
| Test (TST)              |                   |
| Training                |                   |
| Demo                    |                   |

**Important:** This tool provides direct access to ABAP development objects and should only be used in non-production environments. Production systems should follow established change management and transport processes.

---

# Option 1: Local Deployment (Without Docker)

Run the MCP server directly with Python on your local machine.

## Prerequisites

- Python 3.10+
- Network access to SAP system

## Setup

```bash
# Clone repository
git clone https://github.com/aws-solutions-library-samples/guidance-for-deploying-sap-abap-accelerator-for-amazon-q-developer.git
cd abap-accelerator

# Install dependencies
pip install -r requirements.txt

# Run the server
python main.py
```

## Environment Variables

Create a `.env` file or set environment variables:

```bash
# SAP Connection
SAP_HOST=your-sap-host.example.com
SAP_INSTANCE_NUMBER=00
SAP_CLIENT=100
SAP_USERNAME=your_username
SAP_PASSWORD=your_password
SAP_LANGUAGE=EN
SAP_SECURE=true
# Server
SERVER_HOST=localhost
SERVER_PORT=8000
# SSL (optional)
SSL_VERIFY=true
# CUSTOM_CA_CERT_PATH=/path/to/ca-cert.pem
# Logging
LOG_LEVEL=INFO
```

## Q Developer / Kiro Configuration

```json
{
  "mcpServers": {
    "abap-accelerator": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

---

# Option 2: Local Deployment (With Docker)

Run the MCP server in a Docker container for isolated, reproducible deployments.

## Prerequisites

- Docker installed
- Network access to SAP system

## Building the Docker Image

```bash
# Build for AMD64 (Windows/Linux x86)
docker build --platform linux/amd64 -f Dockerfile.simple -t abap-accelerator-enterprise:latest .

# Build for ARM64 (Mac M1/M2/M3)
docker buildx build --platform linux/arm64 -f Dockerfile.simple -t abap-accelerator-enterprise:latest .
```

A `Makefile` is included for convenience:

```bash
make build          # Build the image (linux/amd64)
make run            # Run an interactive shell in the container
make docker-export  # Build and export to abap-accelerator-enterprise-latest.tar.gz
make clean          # Remove exported tarball and image
```

## Loading a Pre-Built Image

If you received a pre-built `abap-accelerator-enterprise-latest.tar.gz` file, load it into your local Docker daemon:

```bash
# Mac / Linux / PowerShell
docker load < abap-accelerator-enterprise-latest.tar.gz

# Windows (Command Prompt)
docker load -i abap-accelerator-enterprise-latest.tar.gz
```

Verify the image was loaded:

```bash
docker images abap-accelerator-enterprise:latest
```

## Deployment Scenarios

### Quick Start: Single SAP System with Environment Variables

For connecting to a single SAP system using environment variables and a Docker secret for the password.

Create a `secrets` folder with a file named `sap_password` (no extension) containing only the SAP password.

If your network uses a corporate proxy or internal CA, mount the CA certificate. Export the full certificate chain (root CA + intermediate CA) into a single PEM file.

There are two ways to run the container: as a standalone HTTP server, or as a STDIO process managed by your MCP client.

#### Option A: Standalone HTTP Server

Run the container in a terminal, then point your MCP client at the URL.

**Windows (Command Prompt):**
```cmd
docker run -i --rm -p 8000:8000 --platform linux/amd64 ^
  --mount type=bind,source=C:\path\to\secrets,target=/run/secrets,readonly ^
  --mount type=bind,source=C:\path\to\proxy-ca.crt,target=/app/certs/proxy-ca.crt,readonly ^
  -e CREDENTIAL_PROVIDER=env ^
  -e DEFAULT_SAP_SYSTEM_ID=DEV_100 ^
  -e SAP_HOST=sap-dev.company.com:44300 ^
  -e SAP_CLIENT=100 ^
  -e SAP_INSTANCE_NUMBER=00 ^
  -e SAP_USERNAME=YOUR_USER ^
  -e SAP_LANGUAGE=EN ^
  -e SAP_SECURE=true ^
  -e CUSTOM_CA_CERT_PATH=/app/certs/proxy-ca.crt ^
  abap-accelerator-enterprise:latest
```

**Mac / Linux:**
```bash
docker run -i --rm -p 8000:8000 \
  --mount type=bind,source=$(pwd)/secrets,target=/run/secrets,readonly \
  --mount type=bind,source=$(pwd)/proxy-ca.crt,target=/app/certs/proxy-ca.crt,readonly \
  -e CREDENTIAL_PROVIDER=env \
  -e DEFAULT_SAP_SYSTEM_ID=DEV_100 \
  -e SAP_HOST=sap-dev.company.com:44300 \
  -e SAP_CLIENT=100 \
  -e SAP_INSTANCE_NUMBER=00 \
  -e SAP_USERNAME=YOUR_USER \
  -e SAP_LANGUAGE=EN \
  -e SAP_SECURE=true \
  -e CUSTOM_CA_CERT_PATH=/app/certs/proxy-ca.crt \
  abap-accelerator-enterprise:latest
```

MCP client configuration:

```json
{
  "mcpServers": {
    "abap-accelerator": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

#### Option B: STDIO Mode (MCP Client Manages the Container)

Let Q Developer or Kiro launch and manage the container directly. No separate terminal needed.

Set `MCP_TRANSPORT=stdio` and remove the port mapping (`-p`). The MCP client communicates with the server over stdin/stdout.

MCP client configuration (Windows paths shown — adjust for your OS):

```json
{
  "mcpServers": {
    "abap-accelerator": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--platform", "linux/amd64",
        "--mount", "type=bind,source=C:\\path\\to\\secrets,target=/run/secrets,readonly",
        "--mount", "type=bind,source=C:\\path\\to\\proxy-ca.crt,target=/app/certs/proxy-ca.crt,readonly",
        "-e", "MCP_TRANSPORT=stdio",
        "-e", "CREDENTIAL_PROVIDER=env",
        "-e", "DEFAULT_SAP_SYSTEM_ID=DEV_100",
        "-e", "SAP_HOST=sap-dev.company.com:44300",
        "-e", "SAP_CLIENT=100",
        "-e", "SAP_INSTANCE_NUMBER=00",
        "-e", "SAP_USERNAME=YOUR_USER",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "-e", "CUSTOM_CA_CERT_PATH=/app/certs/proxy-ca.crt",
        "abap-accelerator-enterprise:latest"
      ],
      "timeout": 100000
    }
  }
}
```

> **Notes:**
> - If you don't need a custom CA certificate, remove both the `--mount` for `proxy-ca.crt` and the `CUSTOM_CA_CERT_PATH` variable.
> - The password is read from `/run/secrets/sap_password` inside the container. Alternatively, pass it as `-e SAP_PASSWORD=...` (or `"-e", "SAP_PASSWORD=..."` in STDIO mode) instead of using the secrets mount.
> - `DEFAULT_SAP_SYSTEM_ID` is the identifier used when no system is specified in tool calls. Use a meaningful name like `DEV_100` (system + client).
```

### Scenario A: Single SAP System

For connecting to a single SAP system with interactive credential input.

**Windows:**
```cmd
docker run -it -p 8000:8000 ^
  -e CREDENTIAL_PROVIDER=interactive ^
  -e ENABLE_PRINCIPAL_PR
For local multi-system deployments, you define SAP systems in a `sap-systems.yaml` file. This file contains only non-sensitive connection information - credentials are prompted interactively at container startup.

##### Step 1: Create sap-systems.yaml

Create the file anywhere on your local machine (e.g., `C:\projects\sap-config\sap-systems.yaml` on Windows or `~/sap-config/sap-systems.yaml` on Mac/Linux):

```yaml
# sap-systems.yaml - SAP System Configuration
# Only non-sensitive information stored here
# Credentials are prompted at container startup

systems:
  # Development System
  S4H-DEV:
    host: s4h-dev.company.com:44300    # Include port in host
    client: "100"                       # SAP client number (string)
    description: "S/4HANA Development"  # Optional description
  
  # QA System
  S4H-QAS:
    host: s4h-qas.company.com:44301
    client: "200"
    description: "S/4HANA QA System"
  
  # Production System (read-only recommended)
  S4H-PROD:
    host: s4h-prod.company.com:44302
    client: "300"
    description: "S/4HANA Production"
```

##### Step 2: Run Container with Config Mounted

Mount the config file to `/app/config/sap-systems.yaml` inside the container:

**Windows (Command Prompt):**
```cmd
docker run -it -p 8000:8000 ^
  -v C:\projects\sap-config\sap-systems.yaml:/app/config/sap-systems.yaml:ro ^
  -e CREDENTIAL_PROVIDER=interactive-multi ^
  -e ENABLE_PRINCIPAL_PROPAGATION=false ^
  abap-accelerator-enterprise:latest
```

**Windows (PowerShell):**
```powershell
docker run -it -p 8000:8000 `
  -v ${PWD}\sap-systems.yaml:/app/config/sap-systems.yaml:ro `
  -e CREDENTIAL_PROVIDER=interactive-multi `
  -e ENABLE_PRINCIPAL_PROPAGATION=false `
  abap-accelerator-enterprise:latest
```

**Mac/Linux:**
```bash
docker run -it -p 8000:8000 \
  -v $(pwd)/sap-systems.yaml:/app/config/sap-systems.yaml:ro \
  -e CREDENTIAL_PROVIDER=interactive-multi \
  -e ENABLE_PRINCIPAL_PROPAGATION=false \
  abap-accelerator-enterprise:latest
```

##### Step 3: Enter Credentials at Startup

The container will prompt for credentials for each system:
```
============================================================
  SAP CREDENTIALS INPUT (Stored in memory only)
============================================================

System: S4H-DEV (S/4HANA Development)
  Host: s4h-dev.company.com:44300
  Client: 100
  Username: DEVELOPER01
  Password: ********
  ✓ Credentials stored for S4H-DEV

System: S4H-QAS (S/4HANA QA System)
  Host: s4h-qas.company.com:44301
  Client: 200
  Username: DEVELOPER01
  Password: ********
  ✓ Credentials stored for S4H-QAS

============================================================
  All credentials stored. Starting MCP server...
============================================================
```

##### sap-systems.yaml Location Summary

| Location          | Mount Path                                                       | Example                              |
| ----------------- | ---------------------------------------------------------------- | ------------------------------------ |
| Current directory | `-v $(pwd)/sap-systems.yaml:/app/config/sap-systems.yaml:ro`     | `./sap-systems.yaml`                 |
| Specific path     | `-v /path/to/sap-systems.yaml:/app/config/sap-systems.yaml:ro`   | `/home/user/config/sap-systems.yaml` |
| Windows path      | `-v C:\path\to\sap-systems.yaml:/app/config/sap-systems.yaml:ro` | `C:\Users\dev\sap-systems.yaml`      |

**Important:** Always mount as read-only (`:ro`) for security.

### Option 3: Central Deployment (ECS Fargate)

For production multi-user deployments with Principal Propagation:

```bash
# ECS Task Definition environment variables
ENABLE_ENTERPRISE_MODE=true
ENABLE_PRINCIPAL_PROPAGATION=true
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
AWS_REGION=us-east-1
DEFAULT_SAP_SYSTEM_ID=S4H-100
```

See [ECS Deployment Guide](#ecs-fargate-deployment) for complete setup.

---

## Environment Variables Reference

### Core Server Configuration

| Variable                | Required | Default           | Description                                  |
| ----------------------- | -------- | ----------------- | -------------------------------------------- |
| `SERVER_HOST`           | Yes      | `0.0.0.0`         | Server bind address                          |
| `SERVER_PORT`           | Yes      | `8000`            | Server port                                  |
| `MCP_TRANSPORT`         | No       | `streamable-http` | Transport mode: `streamable-http` or `stdio` |
| `DEFAULT_SAP_SYSTEM_ID` | No       | `env-<client>`    | Default SAP system identifier for tool calls |
| `LOG_LEVEL`             | No       | `INFO`            | Logging level (DEBUG, INFO, WARNING, ERROR)  |
| `CORS_ENABLED`          | No       | `false`           | Enable CORS                                  |
| `CORS_ALLOWED_ORIGINS`  | No       | `*`               | CORS allowed origins                         |

### Credential Provider Options

| Variable              | Value               | Description                                  |
| --------------------- | ------------------- | -------------------------------------------- |
| `CREDENTIAL_PROVIDER` | `interactive`       | Prompt for single SAP system at startup      |
| `CREDENTIAL_PROVIDER` | `interactive-multi` | Prompt for multiple systems from config file |
| `CREDENTIAL_PROVIDER` | `env`               | Use SAP_* environment variables              |
| `CREDENTIAL_PROVIDER` | `aws_secrets`       | Use AWS Secrets Manager (production)         |

### SAP Connection (for `env` credential provider)

| Variable              | Required | Description                    |
| --------------------- | -------- | ------------------------------ |
| `SAP_HOST`            | Yes      | SAP system hostname            |
| `SAP_INSTANCE_NUMBER` | Yes      | SAP instance number (e.g., 00) |
| `SAP_CLIENT`          | Yes      | SAP client number (e.g., 100)  |
| `SAP_USERNAME`        | Yes      | SAP username                   |
| `SAP_PASSWORD`        | Yes      | SAP password                   |
| `SAP_LANGUAGE`        | No       | SAP language (default: EN)     |
| `SAP_SECURE`          | No       | Use HTTPS (default: true)      |

### Enterprise Mode (ECS/Production)

| Variable                       | Required    | Default | Description                             |
| ------------------------------ | ----------- | ------- | --------------------------------------- |
| `ENABLE_ENTERPRISE_MODE`       | Yes         | `false` | Enable multi-tenancy and usage tracking |
| `ENABLE_PRINCIPAL_PROPAGATION` | Yes         | `false` | Enable X.509 certificate authentication |
| `DEFAULT_SAP_SYSTEM_ID`        | Recommended | -       | Default SAP system when not specified   |
| `DEFAULT_USER_ID`              | Recommended | -       | Default user identity                   |

### SSL/TLS Configuration

| Variable              | Default | Description                                               |
| --------------------- | ------- | --------------------------------------------------------- |
| `SSL_VERIFY`          | `true`  | Set to `false` to disable SSL verification (testing only) |
| `CUSTOM_CA_CERT_PATH` | -       | Path to custom CA certificate for corporate CAs           |

### OAuth Configuration (Optional)

| Variable               | Required | Description                                    |
| ---------------------- | -------- | ---------------------------------------------- |
| `ENABLE_OAUTH_FLOW`    | No       | Enable OAuth authentication flow               |
| `OAUTH_ISSUER`         | If OAuth | OIDC issuer URL                                |
| `OAUTH_AUTH_ENDPOINT`  | If OAuth | Authorization endpoint                         |
| `OAUTH_TOKEN_ENDPOINT` | If OAuth | Token endpoint                                 |
| `OAUTH_CLIENT_ID`      | If OAuth | OAuth client ID                                |
| `OAUTH_CLIENT_SECRET`  | No       | OAuth client secret (for confidential clients) |
| `OAUTH_REDIRECT_URI`   | No       | OAuth callback URL                             |
| `SERVER_BASE_URL`      | If OAuth | MCP server public URL                          |

---

## Q Developer Configuration

### Local Docker Deployment

Add to your Q Developer MCP configuration (`~/.aws/amazonq/mcp.json` or workspace `.amazonq/mcp.json`):

#### Single System
```json
{
  "mcpServers": {
    "abap-accelerator": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

#### Multiple Systems
```json
{
  "mcpServers": {
    "abap-dev": {
      "url": "http://localhost:8000/mcp",
      "headers": {
        "x-sap-system-id": "S4H-DEV"
      }
    },
    "abap-qas": {
      "url": "http://localhost:8000/mcp",
      "headers": {
        "x-sap-system-id": "S4H-QAS"
      }
    }
  }
}
```

### ECS Fargate Deployment

```json
{
  "mcpServers": {
    "abap-accelerator": {
      "url": "https://your-alb-endpoint.com/mcp",
      "headers": {
        "x-sap-system-id": "S4H-100"
      }
    }
  }
}
```

### With OAuth Authentication

```json
{
  "mcpServers": {
    "abap-accelerator": {
      "url": "https://your-mcp-server.com/mcp",
      "headers": {
        "x-sap-system-id": "S4H-100"
      }
    }
  }
}
```
No authentication headers needed - OAuth flow opens browser automatically.

---

## Kiro Configuration

Add to your Kiro MCP configuration (`.kiro/settings/mcp.json`):

### Local Deployment
```json
{
  "mcpServers": {
    "abap-accelerator": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

### Multiple Systems
```json
{
  "mcpServers": {
    "abap-dev": {
      "url": "http://localhost:8000/mcp",
      "headers": {
        "x-sap-system-id": "S4H-DEV"
      }
    },
    "abap-qas": {
      "url": "http://localhost:8000/mcp",
      "headers": {
        "x-sap-system-id": "S4H-QAS"
      }
    }
  }
}
```

### ECS/Remote Deployment
```json
{
  "mcpServers": {
    "abap-accelerator": {
      "url": "https://your-alb-endpoint.com/mcp",
      "headers": {
        "x-sap-system-id": "S4H-100"
      }
    }
  }
}
```

---

## ECS Fargate Deployment

### Credential Storage: Secrets Manager vs Parameter Store

When deploying on ECS Fargate, sensitive and non-sensitive configuration data are stored separately:

| Storage                 | What to Store                                       | Why                                                |
| ----------------------- | --------------------------------------------------- | -------------------------------------------------- |
| **AWS Secrets Manager** | CA certificates, private keys, OAuth client secrets | Encrypted, access-controlled, audit logged         |
| **AWS Parameter Store** | SAP endpoints, user mappings, non-sensitive config  | Cost-effective, easy to update, version controlled |

#### AWS Secrets Manager (Sensitive Data)

Store these secrets in AWS Secrets Manager:

##### 1. CA Certificate (for Principal Propagation)

**Secret Name:** `abap-accelerator/ca-certificate`

```bash
# Create the secret
aws secretsmanager create-secret \
  --name abap-accelerator/ca-certificate \
  --description "CA certificate for ABAP Accelerator principal propagation" \
  --secret-string '{
    "ca_certificate": "<YOUR-CA-CERTIFICATE-PEM-CONTENT>",
    "ca_private_key": "<YOUR-CA-PRIVATE-KEY-PEM-CONTENT>"
  }' \
  --region us-east-1
```

**JSON Structure:**
```json
{
  "ca_certificate": "<YOUR-CA-CERTIFICATE-PEM-CONTENT>",
  "ca_private_key": "<YOUR-CA-PRIVATE-KEY-PEM-CONTENT>"
}
```

##### 2. OAuth Client Secret (for Principal Propagation with OAuth)

**Secret Name:** `abap-accelerator/oauth-client-secret`

```bash
aws secretsmanager create-secret \
  --name abap-accelerator/oauth-client-secret \
  --description "OAuth client secret for ABAP Accelerator principal propagation" \
  --secret-string '{"client_secret": "your-oauth-client-secret"}' \
  --region us-east-1
```

#### AWS Parameter Store (Non-Sensitive Configuration)

Store these configurations in AWS Systems Manager Parameter Store:

##### 1. SAP Endpoints Configuration

**Parameter Name:** `/abap-accelerator/sap-endpoints`

```bash
aws ssm put-parameter \
  --name /abap-accelerator/sap-endpoints \
  --description "SAP system endpoints for ABAP Accelerator" \
  --type String \
  --value 'endpoints:
  S4H-100:
    host: sap-dev.company.com
    port: 443
    client: "100"
    description: "Development System"
  S4H-200:
    host: sap-qa.company.com
    port: 443
    client: "200"
    description: "QA System"
  S4H-300:
    host: sap-prod.company.com
    port: 443
    client: "300"
    description: "Production System"' \
  --region us-east-1
```

**YAML Structure:**
```yaml
endpoints:
  S4H-100:
    host: sap-dev.company.com
    port: 443                    # SAP HTTPS port
    client: "100"                # SAP client number
    description: "Development"   # Optional
  S4H-200:
    host: sap-qa.company.com
    port: 443
    client: "200"
    description: "QA System"
```

##### 2. User Exception Mappings (for Principal Propagation)

**Parameter Name:** `/abap-accelerator/user-exceptions`

When IAM/OAuth username differs from SAP username, define mappings:

```bash
aws ssm put-parameter \
  --name /abap-accelerator/user-exceptions \
  --description "User mapping exceptions for principal propagation" \
  --type String \
  --value 'exceptions:
  alice@company.com:
    S4H-100: ALICE_DEV
    S4H-200: ALICE_QA
  bob.smith@company.com:
    S4H-100: BSMITH01
  john.doe@company.com:
    S4H-100: JDOE
    S4H-200: JDOE
    S4H-300: JDOE' \
  --region us-east-1
```

**YAML Structure:**
```yaml
exceptions:
  # OAuth/IAM email -> SAP username per system
  alice@company.com:
    S4H-100: ALICE_DEV      # SAP username in dev
    S4H-200: ALICE_QA       # SAP username in QA
  bob.smith@company.com:
    S4H-100: BSMITH01       # Different SAP username
```

**Note:** Users not in exceptions use algorithmic mapping (email prefix = SAP username).

#### Storage Summary Table

| Data                         | Storage         | Parameter/Secret Name                  | Required                            |
| ---------------------------- | --------------- | -------------------------------------- | ----------------------------------- |
| CA Certificate + Private Key | Secrets Manager | `abap-accelerator/ca-certificate`      | Yes (for Principal Propagation)     |
| OAuth Client Secret          | Secrets Manager | `abap-accelerator/oauth-client-secret` | Yes (if IdP requires client secret) |
| SAP Endpoints                | Parameter Store | `/abap-accelerator/sap-endpoints`      | Yes                                 |
| User Exception Mappings      | Parameter Store | `/abap-accelerator/user-exceptions`    | Optional                            |

### Prerequisites

- AWS Account with ECS Fargate access
- Docker image pushed to ECR
- AWS Secrets Manager secrets created (see above)
- AWS Parameter Store parameters created (see above)

### Step 1: Push Docker Image to ECR

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build for ARM64 (recommended for AWS Graviton - better price/performance)
docker buildx build --platform linux/arm64 -f Dockerfile.simple -t abap-accelerator-enterprise:latest .

# Tag and push
docker tag abap-accelerator-enterprise:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/abap-accelerator:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/abap-accelerator:latest
```

### Step 2: Create Secrets and Parameters

Follow the [Credential Storage](#credential-storage-secrets-manager-vs-parameter-store) section above to create:
- Secrets Manager: CA certificate, OAuth secret (if needed)
- Parameter Store: SAP endpoints, user exceptions (if needed)

### Step 3: Create ECS Task Definition

```json
{
  "family": "abap-accelerator-mcp",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "runtimePlatform": {
    "cpuArchitecture": "ARM64",
    "operatingSystemFamily": "LINUX"
  },
  "containerDefinitions": [
    {
      "name": "mcp-server",
      "image": "<account-id>.dkr.ecr.us-east-1.amazonaws.com/abap-accelerator:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "SERVER_HOST", "value": "0.0.0.0"},
        {"name": "SERVER_PORT", "value": "8000"},
        {"name": "ENABLE_ENTERPRISE_MODE", "value": "true"},
        {"name": "ENABLE_PRINCIPAL_PROPAGATION", "value": "true"},
        {"name": "DEFAULT_SAP_SYSTEM_ID", "value": "S4H-100"},
        {"name": "AWS_REGION", "value": "us-east-1"},
        {"name": "LOG_LEVEL", "value": "INFO"}
      ],
      "secrets": [
        {
          "name": "CA_CERTIFICATE",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:<account-id>:secret:abap-accelerator/ca-certificate"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/abap-accelerator-mcp",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ],
  "taskRoleArn": "arn:aws:iam::<account-id>:role/ecsTaskRole",
  "executionRoleArn": "arn:aws:iam::<account-id>:role/ecsTaskExecutionRole"
}
```

### Step 4: Create IAM Roles

#### Task Role Policy (for application to access AWS resources)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecretsManagerAccess",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:<account-id>:secret:abap-accelerator/*"
      ]
    },
    {
      "Sid": "ParameterStoreAccess",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": [
        "arn:aws:ssm:us-east-1:<account-id>:parameter/abap-accelerator/*"
      ]
    }
  ]
}
```

#### Execution Role Policy (for ECS to pull images and write logs)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ECRAccess",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:<account-id>:log-group:/ecs/abap-accelerator-mcp:*"
    },
    {
      "Sid": "SecretsManagerForTaskDefinition",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:<account-id>:secret:abap-accelerator/*"
      ]
    }
  ]
}
```

### Step 5: Deploy Service

```bash
# Register task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json

# Create service
aws ecs create-service \
  --cluster your-cluster \
  --service-name abap-accelerator-mcp \
  --task-definition abap-accelerator-mcp \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}"
```

---

## OAuth Authentication Setup (for Principal Propagation)

OAuth authentication is used with Principal Propagation to identify users and map them to SAP usernames. The OAuth flow authenticates users via your Identity Provider, and the server uses the authenticated identity to generate X.509 certificates for SAP access.

### Supported Identity Providers

- AWS Cognito
- Okta
- Microsoft Entra ID (Azure AD)
- Any OIDC-compliant provider

### How It Works

1. User connects to MCP server via Q Developer/Kiro
2. Server redirects to Identity Provider for authentication
3. User logs in with corporate credentials
4. Server extracts user identity from OAuth token
5. Server generates ephemeral X.509 certificate with SAP username
6. Server connects to SAP using certificate authentication
7. SAP enforces user's authorizations

### AWS Cognito Configuration

```bash
# Environment variables
ENABLE_OAUTH_FLOW=true
OAUTH_ISSUER=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXXXXXX
OAUTH_AUTH_ENDPOINT=https://your-domain.auth.us-east-1.amazoncognito.com/oauth2/authorize
OAUTH_TOKEN_ENDPOINT=https://your-domain.auth.us-east-1.amazoncognito.com/oauth2/token
OAUTH_CLIENT_ID=your-client-id
SERVER_BASE_URL=https://your-mcp-server.com
```

### Okta Configuration

```bash
ENABLE_OAUTH_FLOW=true
OAUTH_ISSUER=https://your-domain.okta.com
OAUTH_AUTH_ENDPOINT=https://your-domain.okta.com/oauth2/v1/authorize
OAUTH_TOKEN_ENDPOINT=https://your-domain.okta.com/oauth2/v1/token
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
SERVER_BASE_URL=https://your-mcp-server.com
```

### Microsoft Entra ID Configuration

```bash
ENABLE_OAUTH_FLOW=true
OAUTH_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
OAUTH_AUTH_ENDPOINT=https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize
OAUTH_TOKEN_ENDPOINT=https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
SERVER_BASE_URL=https://your-mcp-server.com
```

---

## SAP System Selection

The server supports three ways to specify the SAP system (in priority order):

1. **Tool Parameter** - Specify `sap_system_id` in each tool call
2. **HTTP Header** - Send `x-sap-system-id` header
3. **Environment Variable** - Set `DEFAULT_SAP_SYSTEM_ID`

### Example Usage

```
# Using default system (from env var)
Check SAP connection status

# Specifying system explicitly
Check SAP connection status for system S4H-200
Get objects from package ZTEST in system S4H-100
```

---

## SAP Port Configuration

SAP systems use different ports based on the instance number:

| Instance Number | HTTPS Port | HTTP Port |
| --------------- | ---------- | --------- |
| 00              | 44300      | 8000      |
| 01              | 44301      | 8001      |
| 02              | 44302      | 8002      |
| 10              | 44310      | 8010      |

**Formula:**
- HTTPS: `44300 + instance_number`
- HTTP: `8000 + instance_number`

### Local Deployment (sap-systems.yaml)

Include the port in the host field:

```yaml
systems:
  S4H-DEV:
    host: sap-dev.company.com:44300    # Instance 00
    client: "100"
  S4H-QAS:
    host: sap-qas.company.com:44301    # Instance 01
    client: "200"
```

### ECS Deployment (Parameter Store)

Specify port separately:

```yaml
endpoints:
  S4H-DEV:
    host: sap-dev.company.com
    port: 44300                         # Instance 00
    client: "100"
  S4H-QAS:
    host: sap-qas.company.com
    port: 44301                         # Instance 01
    client: "200"
```

---

## Available Tools

| Tool                                      | Description                    |
| ----------------------------------------- | ------------------------------ |
| `aws_abap_cb_connection_status`           | Check SAP connection status    |
| `aws_abap_cb_get_objects`                 | List ABAP objects in a package |
| `aws_abap_cb_get_source`                  | Get source code of an object   |
| `aws_abap_cb_search_object`               | Search for ABAP objects        |
| `aws_abap_cb_create_object`               | Create new ABAP object         |
| `aws_abap_cb_update_source`               | Update source code             |
| `aws_abap_cb_check_syntax`                | Check syntax of source code    |
| `aws_abap_cb_activate_object`             | Activate ABAP object           |
| `aws_abap_cb_run_atc_check`               | Run ATC quality checks         |
| `aws_abap_cb_run_unit_tests`              | Execute unit tests             |
| `aws_abap_cb_get_test_classes`            | Get test classes for an object |
| `aws_abap_cb_get_migration_analysis`      | Get migration analysis         |
| `aws_abap_cb_create_or_update_test_class` | Create/update test class       |
| `aws_abap_cb_activate_objects_batch`      | Batch activate objects         |
| `aws_abap_cb_get_transport_requests`      | Get transport requests         |

---

## Troubleshooting

### SSL Certificate Errors

**Error:** `SSL: CERTIFICATE_VERIFY_FAILED`

**Solutions:**
1. Add custom CA certificate:
   ```bash
   -v ./company-ca.pem:/app/certs/custom-ca.pem:ro
   -e CUSTOM_CA_CERT_PATH=/app/certs/custom-ca.pem
   ```
2. For testing only: `SSL_VERIFY=false`

### Connection Timeout

**Error:** Connection to SAP system times out

**Solutions:**
1. Verify SAP system is accessible from your network
2. Check firewall rules allow port 44300 (or your SAP port)
3. Verify SAP ADT services are enabled

### OAuth Not Working

1. Check OAuth status: `curl https://your-server/oauth/status`
2. Verify environment variables are set correctly
3. Check IdP callback URL matches `OAUTH_REDIRECT_URI`

### No User Identity Found

**Error:** "No user identity found in request headers"

**Solutions:**
1. Verify authentication proxy is configured
2. Check JWT token is being injected in headers
3. Enable debug logging: `LOG_LEVEL=DEBUG`

---

## Security Recommendations

The following guidance covers security best practices, operational recommendations, and deployment checklists for the ABAP Accelerator. These are recommendations and not standardized requirements; adapt them to your organization's security posture and policies.

To report security vulnerabilities, please submit to the [AWS Vulnerability Disclosure Program](https://hackerone.com/amazonwebservices) via HackerOne or visit the [AWS Vulnerability Reporting Page](https://aws.amazon.com/security/vulnerability-reporting/).

### Authentication & Authorization

#### Local Development
- Use interactive credential input for testing
- Never commit credentials to version control
- Credentials are stored in memory only and cleared on container stop

#### ECS Based Deployment
- Use OAuth 2.0 / OIDC with external Identity Providers (Okta, Entra ID, AWS IAM Identity Center)
- Implement Principal Propagation with X.509 certificates for SAP authentication
- Use short-lived ephemeral certificates (5-minute validity)
- Store CA certificates in AWS Secrets Manager with encryption at rest

### Secrets Management

- **AWS Secrets Manager:** Store sensitive data (CA certificates, OAuth secrets)
- **AWS Parameter Store:** Store non-sensitive configuration (SAP endpoints)
- **IAM Policies:** Apply least privilege access to secrets and parameters
- **Rotation:** Enable automatic rotation for long-lived secrets

### Network Security

- **TLS:** Use TLS 1.3 (minimum TLS 1.2) for all connections
- **VPC Isolation:** Deploy in private subnets with VPC peering or Direct Connect to SAP
- **Security Groups:** Restrict inbound traffic to Application Load Balancer only
- **Certificate Validation:** Enable SSL verification (disable only for testing)

### Input Validation

All user inputs are validated and sanitized to prevent injection attacks:
- Object names: Alphanumeric and underscore characters only
- File paths: Directory traversal protection
- XML content: Special character encoding
- Log data: Sensitive data redaction

### Audit Logging

- Enable comprehensive audit logging to AWS CloudWatch Logs
- Log all authentication attempts and SAP operations
- Automatically redact passwords, tokens, and secrets from logs
- Set appropriate log retention periods (90+ days recommended)

### Container Security

- A reference Dockerfile is provided with the source code. It can be used as-is or customized to suit your packaging and deployment requirements.
- If customizing the Dockerfile, ensure security best practices are maintained (non-root user, minimal packages, no embedded secrets).
- Run containers as non-root user
- Apply minimal package installation (runtime dependencies only)
- Scan the built container image for vulnerabilities before deployment (e.g., using Amazon Inspector, Trivy, or Grype)
- Use read-only root filesystem where possible

### Denial of Service Protection

- Implement AWS WAF with rate limiting on Application Load Balancer
- Configure connection pooling and request timeouts
- Set appropriate ECS task CPU and memory limits

### SAP System Security

- Configure SAP STRUST with trusted CA certificate
- Implement SAP CERTRULE for certificate-to-user mapping
- Enforce SAP authorization objects (S_DEVELOP, S_TRANSPRT, etc.)
- The MCP server respects SAP's native authorization system

### Monitoring & Incident Response

- Configure CloudWatch alarms for security events:
  - High error rates
  - Failed authentication attempts
  - Certificate generation failures
  - Secrets Manager access denials
- Establish incident response procedures for:
  - Credential compromise
  - Identity Provider compromise
  - SAP system compromise

### Compliance Considerations

- **Audit Trail:** All operations logged with user identity
- **Encryption at Rest:** AWS Secrets Manager with KMS encryption
- **Encryption in Transit:** TLS 1.3 for all connections
- **Access Control:** IAM policies and SAP authorization objects
- **Least Privilege:** Minimal permissions for all components

### CA Private Key Protection

- Restrict Secrets Manager access so only the ECS task role can retrieve the CA secret; no human IAM principals should have direct access.
- Enable CloudTrail alerting on any `GetSecretValue` calls originating outside the ECS task role.
- Use a dedicated KMS key for the CA secret with a strict key policy.
- Enable automatic secret rotation, coordinating CA regeneration with SAP STRUST updates.
- Implement dual-control (split knowledge) requiring two administrators for CA access or rotation via a break-glass procedure.
- Evaluate AWS CloudHSM for CA key storage. When the private key is generated and stored inside an HSM, it never leaves the hardware module, eliminating exfiltration risk.

### SAP Trust Store & Certificate Rule Governance

- Restrict S_TRUST and CERTRULE authorization to a dedicated security administrator role; remove this access from developer and basis roles.
- Require a transport request for all STRUST and CERTRULE changes, with QA approval before release.
- Enable SM21/STAD audit logging for trust store modifications and configure SAP Solution Manager alerts on changes.
- Implement Separation of Duties (SoD) rules via SAP GRC to prevent a single administrator from both modifying and approving trust configuration.
- Document the expected CERTRULE baseline and implement drift detection for unauthorized changes.

### Code Change Control

- Enforce the SAP transport workflow for all code changes: development, QA review, approval, and production transport.
- Mandate peer code review before any transport release (4-eyes principle).
- Enable SAP ATC (ABAP Test Cockpit) security checks as a mandatory gate for transport release.
- Separate developer and release manager roles using S_TRANSPRT authorization restrictions; developers must not approve their own transports.
- Monitor code change patterns (volume, timing, affected objects) via CloudWatch dashboards to detect anomalous activity.

### Identity Provider Hardening

- Select an enterprise Identity Provider with SOC2 Type II and ISO 27001 certifications (e.g., Okta, Entra ID).
- Require MFA for all IdP administrator accounts.
- Export IdP audit logs to CloudWatch and enable anomaly detection.
- Configure token lifetime to the minimum acceptable window (5-15 minutes) to limit the impact of token compromise.
- Combine IdP tokens with additional signals such as device posture and network location for defense in depth.
- Document an IdP compromise incident response playbook covering token revocation and failover to a secondary IdP.

### Intellectual Property & Data Loss Prevention

- Create CloudWatch metrics for code read operations per user and set alarm thresholds for unusual volume (e.g., more than 50 objects per hour).
- Conduct quarterly access reviews to verify that only authorized personnel retain code read access.
- Establish an offboarding procedure that immediately revokes SAP and MCP access upon resignation notice.
- Detect anomalous access patterns such as after-hours bulk reads through behavioral analytics.
- Ensure employment contracts include IP protection clauses.

### Supply Chain Integrity

- Review the provided source code and reference Dockerfile before building. If customizing the Dockerfile, ensure any additional base images or packages come from trusted, verified sources.
- Use only trusted, verified base images (e.g., official Python images from Docker Hub or AWS public ECR).
- Scan the locally built container image for vulnerabilities before pushing to any registry or deploying (e.g., using Amazon Inspector, Trivy, or Grype).
- If pushing to a private ECR repository, enable Amazon Inspector enhanced scanning on that repository.
- Enable AWS GuardDuty ECS Runtime Monitoring for runtime threat detection.
- Generate a Software Bill of Materials (SBOM) for each container image build.
- Pin all dependency versions in `requirements.txt` and mirror approved packages in a private PyPI registry.
- Build container images in an isolated environment with restricted internet access.

### DNS Rebinding Prevention

- Always deploy the MCP server behind an Application Load Balancer in a VPC; never expose containers directly.
- Configure security groups to allow inbound traffic only from the ALB to ECS tasks.
- For local development, bind to `127.0.0.1` (set `SERVER_HOST=127.0.0.1` in the local `.env` file); never bind to `0.0.0.0`.
- Configure ALB rules to reject requests with unexpected Host headers.

### Denial of Service Resilience

- Create a WAF WebACL with a rate-based rule (e.g., 100 requests per 5 minutes per IP) and attach it to the Application Load Balancer.
- Verify AWS Shield Standard is active (enabled automatically for all AWS accounts).
- Configure ECS auto scaling policies based on CPU utilization to absorb traffic spikes.
- Set up CloudWatch alarms for high request rate, elevated error rate, and increased latency.
- Consider adding CloudFront in front of the ALB for edge-level DDoS absorption.

### LLM Tool Safety & Human Oversight

- Require user approval (human-in-the-loop) for all MCP tool write operations via the AI assistant's approval workflow.
- Start with read-only MCP tool permissions and progressively enable write operations as trust is established.
- Return only structured JSON data from tool responses; avoid free-form text that could carry injection payloads.
- Limit MCP tool response sizes to reduce the surface area for prompt injection.
- Classify tools by risk level and apply controls accordingly:
  - High risk (delete, mass update, transport release): disable or require additional approval.
  - Medium risk (create, modify, activate): require standard approval.
  - Low risk (read, list, get metadata): allow with standard approval.
- Log all tool calls with full context (user identity, parameters, results) for audit and review.
- Ensure all write operations can be reversed via SAP transport rollback.
- Consider WAF rules to filter known prompt injection patterns (e.g., "ignore previous instructions", "you are now", "system prompt:") in request and response bodies.

### Assumptions

The following assumptions underpin the security posture of this system. If any assumption does not hold in your environment, additional mitigations should be applied.

1. **CA key access is restricted to automation.** Only the ECS task role retrieves the CA private key from Secrets Manager. No human IAM principal has direct access. If this assumption is violated, consider CloudHSM.
2. **SAP trust configuration is change-controlled.** STRUST and CERTRULE modifications go through a transport workflow with approval. If administrators can make ad-hoc changes, implement SAP GRC SoD rules.
3. **SAP transport workflow is enforced.** All ABAP code changes require transport, QA review, and approval before reaching production. The MCP server cannot bypass SAP's native change management.
4. **The Identity Provider is secure.** The system relies on the IdP (Okta, Entra ID, IAM Identity Center) to issue valid tokens. If the IdP is compromised, all downstream authentication is affected. Short token lifetimes and an incident response playbook reduce this risk.
5. **Code read access is monitored.** Bulk code download is detectable through CloudWatch metrics and alarms. Without monitoring, insider exfiltration may go unnoticed.
6. **Container images are built from reviewed source and scanned before deployment.** The customer builds images from the provided source code using the reference Dockerfile (or a customized version). Trusted base images are used, dependencies are pinned, and the built image is scanned for vulnerabilities before deployment. Without these controls, supply chain compromise is possible.
7. **The MCP server is never exposed directly to the internet.** All production traffic flows through an ALB with security groups. Direct exposure (especially binding to `0.0.0.0`) creates DNS rebinding and other network-level risks.
8. **WAF rate limiting is in place.** The ALB has a WAF WebACL with rate-based rules. Without rate limiting, the server is vulnerable to resource exhaustion.
9. **Human oversight is maintained for LLM tool calls.** Users review and approve tool operations, especially write actions. Without human-in-the-loop controls, the LLM may execute unintended or damaging operations.
10. **Tool responses are treated as untrusted input.** Data returned by MCP tools may contain adversarial content. Structured output formats and response size limits reduce the risk of prompt injection through tool responses.

### Security Checklist for ECS Based Deployment

#### Pre-Deployment
- [ ] Generate CA certificate and store in AWS Secrets Manager
- [ ] Configure SAP STRUST with CA certificate
- [ ] Configure SAP CERTRULE for user mapping
- [ ] Register OAuth client with Identity Provider
- [ ] Create IAM roles with least privilege policies
- [ ] Configure VPC, subnets, and security groups
- [ ] Create CloudWatch log group
- [ ] Review the source code and reference Dockerfile before building
- [ ] Build the container image using the reference Dockerfile (or a customized version)
- [ ] Scan the built image for vulnerabilities (Amazon Inspector, Trivy, or Grype)
- [ ] Pin all dependency versions in requirements.txt

#### Deployment
- [ ] ECS task runs as non-root user
- [ ] Secrets referenced from Secrets Manager (not environment variables)
- [ ] TLS 1.3 enabled on Application Load Balancer
- [ ] AWS WAF attached with rate limiting rules
- [ ] CloudWatch Logs retention configured (90+ days)
- [ ] Parameter Store change detection enabled
- [ ] ALB configured with Host header validation
- [ ] Security groups restrict inbound to ALB only
- [ ] GuardDuty ECS Runtime Monitoring enabled

#### Post-Deployment
- [ ] Test OAuth authentication flow end-to-end
- [ ] Verify certificate generation and SAP authentication
- [ ] Confirm audit logs are being written to CloudWatch
- [ ] Test rate limiting with load testing
- [ ] Verify secrets rotation functionality
- [ ] Document incident response procedures
- [ ] Configure CloudWatch alarms for code read volume per user
- [ ] Verify AI assistant tool approval workflow is enabled
- [ ] Conduct quarterly access review for SAP and MCP permissions

---

## Configuration Comparison: Local vs ECS

| Aspect                    | Local (Docker)                               | ECS Fargate                                                  |
| ------------------------- | -------------------------------------------- | ------------------------------------------------------------ |
| **SAP Systems Config**    | `sap-systems.yaml` file mounted to container | AWS Parameter Store (`/abap-accelerator/sap-endpoints`)      |
| **SAP Authentication**    | Interactive credentials (basic auth)         | Principal Propagation (X.509 certificates)                   |
| **User Identity**         | Manual input at startup                      | OAuth/OIDC (Cognito, Okta, Entra ID)                         |
| **CA Certificate**        | Not needed                                   | AWS Secrets Manager (`abap-accelerator/ca-certificate`)      |
| **OAuth Client Secret**   | Not needed                                   | AWS Secrets Manager (`abap-accelerator/oauth-client-secret`) |
| **Multi-tenancy**         | Via `x-sap-system-id` header                 | Via `x-sap-system-id` header + user isolation                |
| **Credential Provider**   | `interactive` or `interactive-multi`         | `aws_secrets`                                                |
| **Principal Propagation** | `false`                                      | `true`                                                       |

---

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct). For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact opensource-codeofconduct@amazon.com with any additional questions or comments.

---

## Support

For issues and questions:

- [GitHub Issues](https://github.com/aws/abap-accelerator/issues) for ABAP Accelerator
- [Amazon Q Developer documentation](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/what-is.html)

This tool is intended for SAP development, sandbox, and training environments. Using this with SAP production environments is not recommended.

---

## Terms of Use

ABAP Accelerator for Amazon Q Developer is AWS Content under the [Amazon Customer Agreement](https://aws.amazon.com/agreement/) or other written agreement governing your usage of AWS Services. If you do not have an Agreement governing use of Amazon Services, ABAP Accelerator for Amazon Q Developer is made available to you under the terms of the [AWS Intellectual Property License](https://aws.amazon.com/legal/aws-ip-license-terms/).

ABAP Accelerator for Amazon Q Developer is intended for use in a development environment for testing and validation purposes, and is not intended to be used in a production environment or with production workloads or data. ABAP Accelerator for Amazon Q Developer utilizes generative AI to create outputs, and AWS does not make any representations or warranties about the accuracy of the outputs of ABAP Accelerator for Amazon Q Developer. You are solely responsible for the use of any outputs that you utilize from ABAP Accelerator for Amazon Q Developer and appropriately reviewing, validating, or testing any outputs from ABAP Accelerator for Amazon Q Developer.

---

## Notices

Customers are responsible for making their own independent assessment of the information in this Guidance. This Guidance: (a) is for informational purposes only, (b) represents AWS current product offerings and practices, which are subject to change without notice, and (c) does not create any commitments or assurances from AWS and its affiliates, suppliers or licensors. AWS products or services are provided "as is" without warranties, representations, or conditions of any kind, whether express or implied. AWS responsibilities and liabilities to its customers are controlled by AWS agreements, and this Guidance is not part of, nor does it modify, any agreement between AWS and its customers.

---

## License

MIT No Attribution

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
