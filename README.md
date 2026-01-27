# ABAP Accelerator for Amazon Q Developer

ABAP Accelerator is an MCP server that helps organizations create, test, document, and transform SAP ABAP code faster and with higher code accuracy. [Learn more](https://aws.amazon.com/blogs/awsforsap/introducing-abap-accelerator-for-ai-assisted-development/) or get started below.

**Key Capabilities**
- **Code Generation** – Generate ABAP code with plain English prompts
- **Documentation** – Analyze and document existing ABAP code
- **Unit Testing** – Automate test development cycle
- **BTP Development** – Generate CAP/RAP artifacts
- **HANA Transformation** – Convert ABAP objects from ECC to S/4HANA

## Architecture

```
  ┌─────────────────────┐            ┌────────────────┐            ┌────────────────┐
  │  Amazon Q Developer │    MCP     │     Docker     │    RFC     │   SAP System   │
  │  (Eclipse/VS Code)  │◄──────────►│   Container    │◄──────────►│                │
  └─────────────────────┘            └────────────────┘            └────────────────┘
                                            ▲
                                            │ read-only mount
                                    secrets/sap_password
```

<p align="center">Amazon Q Developer communicates with the Docker container via MCP protocol.<br>The container connects to your SAP system using RFC and reads credentials from a mounted secrets file.</p>

## Environment Guidance

| ✅ Intended | ❌ Not Recommended |
|-------------|---------------------|
| Development (DEV) | Production (PRD) |
| Sandbox (SBX) | Quality Assurance (QAS) |
| Training | Test (TST) |
| Demo | Pre-production |

---

## Quick Start

1. [Install Docker](#step-1-install-docker)
2. [Download ABAP Accelerator MCP Server](#step-2-download-abap-accelerator-mcp-server)
3. [Load the Container Image](#step-3-load-the-container-image)
4. [Create Secrets File](#step-4-create-secrets-file)
5. [Test the Container](#step-5-test-the-container)
6. [Configure MCP for Amazon Q Developer](#step-6-configure-mcp-for-amazon-q-developer)

### Step 1: Install Docker

Download and install from [docs.docker.com/desktop](https://docs.docker.com/desktop/)

<details open>
<summary><b>Windows</b></summary>

Download [installer](https://docs.docker.com/desktop/setup/install/windows-install/) and install. Verify using UI or command line:
```cmd
docker --version
```
</details>

<details>
<summary><b>macOS</b></summary>

```bash
# Using Homebrew
brew install --cask docker

# Start Docker Desktop from Applications
open -a Docker
```

Verify installation:
```bash
docker --version
```
</details>

<details>
<summary><b>Linux</b></summary>

Instructions for different flavors: [docs.docker.com/desktop/setup/install/linux](https://docs.docker.com/desktop/setup/install/linux/)

Verify installation:
```bash
docker --version
```
</details>

### Step 2: Download ABAP Accelerator MCP Server

Download the container image from the [GitHub assets](https://github.com/aws-solutions-library-samples/guidance-for-deploying-sap-abap-accelerator-for-amazon-q-developer/tree/main/assets) page.

### Step 3: Load the Container Image

```bash
# Navigate to your download folder
# Windows:
cd C:\path\to\abap-accelerator-q-docker-image-local
# Mac/Linux:
cd /path/to/abap-accelerator-q-docker-image-local

# Load image
docker load -i abap-accelerator-q-3.2.1-node22.tar
```

Verify the image loaded:
```bash
docker images | grep abap-accelerator-q
# Windows CMD: docker images | findstr abap-accelerator-q
```

Expected output:
```
abap-accelerator-q   3.2.1-node22   abc123def456   ...   XXX MB
```

### Step 4: Create Secrets File

> ⚠️ **Security:** Never store passwords in config files, environment variables, or commit to git.

<details open>
<summary><b>Windows</b></summary>

```cmd
mkdir C:\path\to\secrets
echo your-sap-password> C:\path\to\secrets\sap_password
```

Note: Windows does not require explicit file permissions, but ensure the folder is not shared.
</details>

<details>
<summary><b>macOS / Linux</b></summary>

```bash
mkdir -p /path/to/secrets
echo "your-sap-password" > /path/to/secrets/sap_password
chmod 600 /path/to/secrets/sap_password
chmod 755 /path/to/secrets
```
</details>

Note your full path to the secrets folder - you'll need this for MCP configuration:
- Windows: `C:\Users\YourUsername\path\to\abap-accelerator-q-docker-image-local\secrets` (use forward slashes `/` in config)
- Mac/Linux: `/Users/YourUsername/path/to/abap-accelerator-q-docker-image-local/secrets`

### Step 5: Test the Container

Replace the placeholder values with your SAP system details:

<details open>
<summary><b>Windows</b></summary>

```cmd
# Note: Use forward slashes (/) in path, not backslashes (\)
docker run --rm -i --platform linux/amd64 ^
  --mount type=bind,source=C:/full/path/to/secrets,target=/run/secrets,readonly ^
  -e SAP_HOST=your-sap-host.company.com ^
  -e SAP_CLIENT=100 ^
  -e SAP_USERNAME=your_username ^
  -e SAP_LANGUAGE=EN ^
  -e SAP_SECURE=true ^
  abap-accelerator-q-3.2.1-node22 ^
  node dist/index.js
```
</details>

<details>
<summary><b>macOS / Linux</b></summary>

```bash
docker run --rm -i --platform linux/amd64 \
  --mount type=bind,source=/full/path/to/secrets,target=/run/secrets,readonly \
  -e SAP_HOST=your-sap-host.company.com \
  -e SAP_CLIENT=100 \
  -e SAP_USERNAME=your_username \
  -e SAP_LANGUAGE=EN \
  -e SAP_SECURE=true \
  abap-accelerator-q-3.2.1-node22 \
  node dist/index.js
```
</details>

**Important:**
- Replace `/full/path/to/secrets` with your actual absolute path to the secrets folder
- The password is read from the mounted `/run/secrets/sap_password` file inside the container
- Password never appears in command line or configuration files

**Success indicator:** Container starts without errors and waits for input.

Press `Ctrl+C` to stop the test container.

### Step 6: Configure MCP for Amazon Q Developer

<details open>
<summary><b>Windows</b></summary>

**Config file location:** `C:\Users\YourUsername\.aws\amazonq\mcp.json`

Create the directory if it doesn't exist:
```cmd
mkdir C:\Users\%USERNAME%\.aws\amazonq
```

Create `mcp.json` with this content:
```json
{
  "mcpServers": {
    "abap-accelerator-q": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--mount", "type=bind,source=C:/Users/YourUsername/.secrets/sap,target=/run/secrets,readonly",
        "-e", "SAP_HOST=your-sap-host.company.com",
        "-e", "SAP_CLIENT=100",
        "-e", "SAP_USERNAME=your_username",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "abap-accelerator-q-3.2.1-node22",
        "node", "dist/index.js"
      ],
      "timeout": 60000,
      "disabled": false
    }
  }
}
```

> ⚠️ **Windows paths:** Always use forward slashes (`/`) in the JSON config, not backslashes.
</details>

<details>
<summary><b>macOS / Linux</b></summary>

**Config file location:** `~/.aws/amazonq/mcp.json`

Create the directory if it doesn't exist:
```bash
mkdir -p ~/.aws/amazonq
```

Create `mcp.json` with this content:
```json
{
  "mcpServers": {
    "abap-accelerator-q": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--mount", "type=bind,source=/Users/YourUsername/.secrets/sap,target=/run/secrets,readonly",
        "-e", "SAP_HOST=your-sap-host.company.com",
        "-e", "SAP_CLIENT=100",
        "-e", "SAP_USERNAME=your_username",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "abap-accelerator-q-3.2.1-node22",
        "node", "dist/index.js"
      ],
      "timeout": 60000,
      "disabled": false
    }
  }
}
```
</details>

**Restart Amazon Q Developer** to load the new configuration.

---

## Connecting Multiple SAP Systems

To connect to multiple SAP systems (e.g., ECC and S/4HANA), create separate secrets and config entries.

Docker will automatically spin up separate containers for each configured system, allowing simultaneous connections to all your SAP environments.

### Secrets Structure

```
~/.secrets/
├── ecc/
│   └── sap_password
└── s4hana/
    └── sap_password
```

<details open>
<summary><b>Windows</b></summary>

```cmd
mkdir C:\Users\%USERNAME%\.secrets\ecc
mkdir C:\Users\%USERNAME%\.secrets\s4hana
echo ecc-password> C:\Users\%USERNAME%\.secrets\ecc\sap_password
echo s4hana-password> C:\Users\%USERNAME%\.secrets\s4hana\sap_password
```
</details>

<details>
<summary><b>macOS / Linux</b></summary>

```bash
mkdir -p ~/.secrets/ecc ~/.secrets/s4hana
echo "ecc-password" > ~/.secrets/ecc/sap_password
echo "s4hana-password" > ~/.secrets/s4hana/sap_password
chmod 600 ~/.secrets/ecc/sap_password ~/.secrets/s4hana/sap_password
```
</details>

### Multi-System MCP Configuration

```json
{
  "mcpServers": {
    "abap-ecc": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--mount", "type=bind,source=/path/to/.secrets/ecc,target=/run/secrets,readonly",
        "-e", "SAP_HOST=ecc-host.company.com",
        "-e", "SAP_CLIENT=100",
        "-e", "SAP_USERNAME=ecc_user",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "abap-accelerator-q-3.2.1-node22",
        "node", "dist/index.js"
      ],
      "timeout": 60000,
      "disabled": false
    },
    "abap-s4hana": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--mount", "type=bind,source=/path/to/.secrets/s4hana,target=/run/secrets,readonly",
        "-e", "SAP_HOST=s4hana-host.company.com",
        "-e", "SAP_CLIENT=200",
        "-e", "SAP_USERNAME=s4_user",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "abap-accelerator-q-3.2.1-node22",
        "node", "dist/index.js"
      ],
      "timeout": 60000,
      "disabled": false
    }
  }
}
```

### How Multiple Systems Work

In Amazon Q Developer, you'll see separate tool sets:

- Tools prefixed with `abap-ecc-system_` for ECC operations
- Tools prefixed with `abap-s4hana-system_` for S/4HANA operations

### Example Usage

```
User: "Get source code for class ZCL_TEST from ECC system"
Q Developer: Uses abap-ecc-system tools automatically

User: "Create a new class in S/4HANA system"
Q Developer: Uses abap-s4hana-system tools automatically

User: "Now check the same class in S/4HANA"
Q Developer: Switches to S/4HANA system tools
```

---

## Available MCP Tools

Once configured, Amazon Q Developer can use these ABAP tools:

### Object Management
| Tool | Description |
|------|-------------|
| `aws_abap_cb_get_objects` | List ABAP objects in a package or namespace |
| `aws_abap_cb_create_object` | Create new ABAP objects (classes, programs, etc.) |
| `aws_abap_cb_get_source` | Retrieve source code of an ABAP object |
| `aws_abap_cb_update_source` | Update source code of an existing object |
| `aws_abap_cb_search_object` | Search for ABAP objects by name or pattern |

### Development & Testing
| Tool | Description |
|------|-------------|
| `aws_abap_cb_check_syntax` | Validate ABAP syntax |
| `aws_abap_cb_activate_object` | Activate ABAP objects |
| `aws_abap_cb_run_unit_tests` | Execute ABAP unit tests |
| `aws_abap_cb_run_atc_check` | Run ABAP Test Cockpit checks |

### Advanced Operations
| Tool | Description |
|------|-------------|
| `aws_abap_cb_generate_documentation` | Generate technical documentation |
| `aws_abap_cb_get_migration_analysis` | Analyze code for S/4HANA migration |
| `aws_abap_cb_create_or_update_test_class` | Create or update ABAP unit test classes |

---

## Troubleshooting

### Container Issues

| Problem | Solution |
|---------|----------|
| `image not found` | Run `docker load -i abap-accelerator-q-3.2.1-node22.tar` again |
| `permission denied` on secrets | Check file permissions: `chmod 600 ~/.secrets/sap/sap_password` |
| Container exits immediately | Verify SAP_HOST is reachable: `ping your-sap-host.company.com` |
| `platform mismatch` error | Ensure `--platform linux/amd64` flag is included |

### MCP Connection Issues

| Problem | Solution |
|---------|----------|
| MCP server not appearing | Restart Amazon Q Developer after config changes |
| `timeout` errors | Increase timeout value (minimum 60000ms recommended) |
| `invalid JSON` error | Validate mcp.json at [jsonlint.com](https://jsonlint.com) |
| Path not found | Use absolute paths; Windows: use forward slashes `/` |

### SAP Connection Issues

| Problem | Solution |
|---------|----------|
| `authentication failed` | Verify password in secrets file has no trailing whitespace |
| `connection refused` | Check SAP_HOST, SAP_CLIENT values; verify network/VPN access |
| `user locked` | Contact SAP Basis team to unlock the user |

### Platform Compatibility (Apple Silicon)

1. Always include `--platform linux/amd64` flag
2. Docker Desktop: Enable Rosetta 2 emulation in Settings → General
3. Finch: Platform flag is required

### Debugging Commands

```bash
# Check runtime version
docker --version

# Check if image is loaded
docker images | grep abap-accelerator-q

# Test if secrets are mounted correctly
docker run --rm \
  --mount type=bind,source=/full/path/to/secrets,target=/run/secrets,readonly \
  abap-accelerator-q-3.2.1-node22 \
  ls -la /run/secrets/

# Check password file content inside container
docker run --rm \
  --mount type=bind,source=/full/path/to/secrets,target=/run/secrets,readonly \
  abap-accelerator-q-3.2.1-node22 \
  cat /run/secrets/sap_password

# Test network connectivity from container
docker run --rm \
  abap-accelerator-q-3.2.1-node22 \
  ping -c 3 your-sap-system.company.com

# Check system resources
docker system df
```

### MCP Configuration Common Mistakes

1. **Wrong path separators** - Use `/` not `\` even on Windows
2. **Relative paths** - Always use absolute paths for bind mounts
3. **Missing timeout** - Add `"timeout": 60000` for SAP connections
4. **Wrong image name** - Ensure exact match: `abap-accelerator-q-3.2.1-node22`
5. **Password in config** - Never put password in MCP config, use secrets folder only

### Container Management

```bash
# List running containers
docker ps

# View logs
docker logs <container-id>

# Stop container
docker stop <container-id>

# List images
docker images

# System cleanup
docker system prune
```

---

## Configuration Reference

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `SAP_HOST` | Yes | SAP system hostname | `dev-sap.company.com` |
| `SAP_CLIENT` | Yes | SAP client number | `100` |
| `SAP_USERNAME` | Yes | SAP username | `DEVUSER` |
| `SAP_LANGUAGE` | No | Logon language (default: EN) | `EN`, `DE` |
| `SAP_SECURE` | No | Use secure connection (default: true) | `true`, `false` |

### Docker Flags Reference

| Flag | Purpose |
|------|---------|
| `--rm` | Automatically remove container when it exits |
| `-i` | Keep STDIN open for MCP communication |
| `--platform linux/amd64` | Ensure correct architecture (required on Apple Silicon) |
| `--mount type=bind,source=...,target=/run/secrets,readonly` | Mount secrets securely |

---

## Alternative Container Runtimes

<details>
<summary><b>Using Podman</b> - <a href="https://podman.io/">podman.io</a></summary>

### Installation

**macOS:**
```bash
brew install podman
podman machine init
podman machine start
```

**Linux (RHEL/Fedora):**
```bash
sudo dnf install podman
```

**Windows:**
Download from [podman.io](https://podman.io/getting-started/installation)

### Usage

Replace `docker` with `podman` in all commands:

```bash
podman load -i abap-accelerator-q-3.2.1-node22.tar
podman images | grep abap-accelerator-q
```

Update `mcp.json` to use `podman`:
```json
{
  "mcpServers": {
    "abap-accelerator-q": {
      "command": "podman",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        ...
      ]
    }
  }
}
```
</details>

<details>
<summary><b>Using Finch</b> - <a href="https://github.com/runfinch/finch">github.com/runfinch/finch</a></summary>

### Installation

**macOS:**
```bash
brew install --cask finch
finch vm init
finch vm start
```

**Linux:**
See [Finch installation guide](https://github.com/runfinch/finch)

### Usage

Replace `docker` with `finch` in all commands:

```bash
finch load -i abap-accelerator-q-3.2.1-node22.tar
finch images | grep abap-accelerator-q
```

Update `mcp.json` to use `finch`:
```json
{
  "mcpServers": {
    "abap-accelerator-q": {
      "command": "finch",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        ...
      ]
    }
  }
}
```
</details>

---

## Security Best Practices

- ✅ Store passwords in mounted secret files (`/run/secrets/sap_password`)
- ✅ Use `readonly` flag when mounting secrets
- ✅ Set file permissions to `600` (owner read/write only)
- ✅ Use absolute paths for all mounts
- ❌ Never store passwords in `mcp.json`
- ❌ Never pass passwords as environment variables
- ❌ Never commit secrets to version control
- ❌ Never use with production SAP systems

---

## Support

For issues and questions:
- [GitHub Issues for ABAP Accelerator](https://github.com/aws-solutions-library-samples/guidance-for-deploying-sap-abap-accelerator-for-amazon-q-developer/issues)
- [Amazon Q Developer documentation](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/what-is.html)

---

*This tool is intended for SAP development, sandbox, and training environments. Using this with SAP production environments is not recommended.*

## Terms of Use

ABAP Accelerator for Amazon Q Developer is AWS Content under the Amazon Customer Agreement (available at: https://aws.amazon.com/agreement/) or other written agreement governing your usage of AWS Services. If you do not have an Agreement governing use of Amazon Services ABAP Accelerator for Amazon Q Developer is made available to you under the terms of the AWS Intellectual Property License (available at: https://aws.amazon.com/legal/aws-ip-license-terms/).

ABAP Accelerator for Amazon Q Developer is intended for use in a development environment for testing and validation purposes, and is not intended to be used in a production environment or with production workloads or data. ABAP Accelerator for Amazon Q Developer utilizes generative AI to create outputs, and AWS does not make any representations or warranties about the accuracy of the outputs of ABAP Accelerator for Amazon Q Developer. You are solely responsible for the use of any outputs that you utilize from ABAP Accelerator for Amazon Q Developer and appropriately reviewing, validating, or testing any outputs from ABAP Accelerator for Amazon Q Developer.

## Notices  

*Customers are responsible for making their own independent assessment of the information in this Guidance. This Guidance: (a) is for informational purposes only, (b) represents AWS current product offerings and practices, which are subject to change without notice, and (c) does not create any commitments or assurances from AWS and its affiliates, suppliers or licensors. AWS products or services are provided “as is” without warranties, representations, or conditions of any kind, whether express or implied. AWS responsibilities and liabilities to its customers are controlled by AWS agreements, and this Guidance is not part of, nor does it modify, any agreement between AWS and its customers.*

