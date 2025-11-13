# ABAP Accelerator for Amazon Q Developer - Universal Container Setup

This guide covers setting up ABAP Accelerator for Amazon Q Developer with any container runtime: Docker Desktop, Finch, or Podman on any operating system.

## Notices and Terms of Use

ABAP Accelerator for Amazon Q Developer is AWS Content under the Amazon Customer Agreement (available at: https://aws.amazon.com/agreement/) or other written agreement governing your usage of AWS Services. If you do not have an Agreement governing use of Amazon Services ABAP Accelerator for Amazon Q Developer is made available to you under the terms of the AWS Intellectual Property License (available at: https://aws.amazon.com/legal/aws-ip-license-terms/).

ABAP Accelerator for Amazon Q Developer is intended for use in a development environment for testing and validation purposes, and is not intended to be used in a production environment or with production workloads or data. ABAP Accelerator for Amazon Q Developer utilizes generative AI to create outputs, and AWS does not make any representations or warranties about the accuracy of the outputs of ABAP Accelerator for Amazon Q Developer. You are solely responsible for the use of any outputs that you utilize from ABAP Accelerator for Amazon Q Developer and appropriately reviewing, validating, or testing any outputs from ABAP Accelerator for Amazon Q Developer.

## ⚠️ **IMPORTANT: DEVELOPMENT USE ONLY**

**This MCP server should ONLY be used with SAP Development environments as users are authorized to modify the code only in Dev environment such as:**
- ✅ Development systems (DEV)
- ✅ Sandbox environments
- ✅ Training systems
- ✅ Demo systems

**❌ DO NOT use with:**
- ❌ Production SAP systems (PRD)
- ❌ Quality/Test systems (QAS/TST)
- ❌ Pre-production systems

## Container Runtime Options

Choose your preferred container runtime:

### Docker Desktop (Windows/Mac/Linux)
- **Windows**: [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
- **Mac**: [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)
- **Linux**: [Docker Desktop for Linux](https://docs.docker.com/desktop/install/linux-install/)

### Finch (Mac/Linux)
- **Best for**: Lightweight alternative to Docker Desktop
- **Mac**: `brew install finch`
- **Linux**: [Finch releases](https://github.com/runfinch/finch)

### Podman (Windows/Mac/Linux)
- **Best for**: Rootless containers, enterprise environments
- **Windows**: [Podman Desktop](https://podman-desktop.io/)
- **Mac**: `brew install podman`
- **Linux**: [Distribution packages](https://podman.io/getting-started/installation)

## Setup Steps

### Download MCP image

[Click here to download the Docker MCP image](https://ws-assets-prod-iad-r-iad-ed304a55c2ca1aee.s3.us-east-1.amazonaws.com/d01697ea-1e3c-4b38-934b-859884fdb406/ABAP-Accelerator-for-Q-Developer.zip)

### 1. Install Container Runtime

#### Docker Desktop
```bash
# Windows: Download installer from docker.com
# Mac: Download installer or use Homebrew
brew install --cask docker  # Mac only
# Linux: Follow Docker Desktop for Linux instructions

# Verify installation (all platforms)
docker --version
```

#### Finch
```bash
# Mac
brew install finch
finch vm init

# Linux
# Download from GitHub releases and follow installation guide
```

#### Podman
```bash
# Windows: Install Podman Desktop from podman-desktop.io

# Mac
brew install podman
podman machine init
podman machine start

# Linux (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install podman

# Linux (RHEL/CentOS/Fedora)
sudo dnf install podman
```

### 2. Load Container Image
```bash
# Navigate to your distribution folder
# Windows:
cd C:\path\to\abap-accelerator-q-docker-image-local
# Mac/Linux:
cd /path/to/abap-accelerator-q-docker-image-local

# Universal command - works with any runtime: (Make sure you have the latest version)
[docker|finch|podman] load -i abap-accelerator-q-3.2.0-node22.tar 

# Examples:
docker load -i abap-accelerator-q-3.2.0-node22.tar
finch load -i abap-accelerator-q-3.2.0-node22.tar --platform linux/amd64
podman load -i abap-accelerator-q-3.2.0-node22.tar

# Verify image loaded
docker images | grep abap-accelerator-q
finch images | grep abap-accelerator-q
podman images | grep abap-accelerator-q
```

### 3. Configure SAP Password (Method with Advanced Security Features)

**🔒 IMPORTANT: Use Docker secrets for advanced security features for password storage - never store passwords in .env files or MCP configuration!**

#### Create secrets folder and password file:

**Windows (PowerShell):**
```powershell
# Create secrets folder if it doesn't exist
New-Item -ItemType Directory -Force -Path secrets

# Store your SAP password securely
"your-sap-password" | Out-File -FilePath secrets\sap_password -NoNewline -Encoding ASCII
```

**Windows (CMD):**
```cmd
# Create secrets folder if it doesn't exist
mkdir secrets

# Store your SAP password securely
echo your-sap-password > secrets\sap_password
```

**Mac/Linux:**
```bash
# Create secrets folder if it doesn't exist
mkdir -p secrets

# Store your SAP password with advanced security features
echo "your-sap-password" > secrets/sap_password

# Set file permissions (Mac/Linux only)
# 600 = read/write for owner only, no access for others
chmod 600 secrets/sap_password
# 755 = read/execute for all, write for owner only
chmod 755 secrets/
```

**Note your full path to the secrets folder** - you'll need this for MCP configuration:
- **Windows**: `C:\Users\YourUsername\path\to\abap-accelerator-q-docker-image-local\secrets`
- **Mac/Linux**: `/Users/YourUsername/path/to/abap-accelerator-q-docker-image-local/secrets`

### 4. Test Container (Universal Command)

**🔒 Method with advanced security features using bind mount for secrets:**

```bash
# Windows (use forward slashes in path):
docker run --rm -i --platform linux/amd64 \
  --mount type=bind,source=C:/Users/YourUsername/path/to/secrets,target=/run/secrets,readonly \
  -e SAP_HOST=your-sap-host.company.com \
  -e SAP_CLIENT=100 \
  -e SAP_USERNAME=your-username \
  -e SAP_LANGUAGE=EN \
  -e SAP_SECURE=true \
  abap-accelerator-q:3.2.0-node22 \
  node dist/index.js

# Mac/Linux:
docker run --rm -i --platform linux/amd64 \
  --mount type=bind,source=/full/path/to/secrets,target=/run/secrets,readonly \
  -e SAP_HOST=your-sap-host.company.com \
  -e SAP_CLIENT=100 \
  -e SAP_USERNAME=your-username \
  -e SAP_LANGUAGE=EN \
  -e SAP_SECURE=true \
  abap-accelerator-q:3.2.0-node22 \
  node dist/index.js

# Works with any runtime - just replace 'docker' with 'finch' or 'podman':
finch run --rm -i --platform linux/amd64 \
  --mount type=bind,source=/full/path/to/secrets,target=/run/secrets,readonly \
  -e SAP_HOST=your-sap-host.company.com \
  -e SAP_CLIENT=100 \
  -e SAP_USERNAME=your-username \
  -e SAP_LANGUAGE=EN \
  -e SAP_SECURE=true \
  abap-accelerator-q:3.2.0-node22 \
  node dist/index.js
```

**Important:**
- Replace `/full/path/to/secrets` with your actual absolute path to the secrets folder
- The password is read from the mounted `/run/secrets/sap_password` file inside the container
- Password never appears in command line or configuration files

## MCP Client Configuration

### Amazon Q Developer

**🔒 Configuration with Advanced Security Features Using Docker Secrets**

#### Configuration File Location:
- **Windows**: `%USERPROFILE%\.aws\amazonq\mcp.json`
  - Full path: `C:\Users\YourUsername\.aws\amazonq\mcp.json`
- **Mac**: `~/.aws/amazonq/mcp.json`
- **Linux**: `~/.aws/amazonq/mcp.json`

#### Configuration (Windows):
```json
{
  "mcpServers": {
    "abap-accelerator-q": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--mount", "type=bind,source=C:/Users/YourUsername/path/to/secrets,target=/run/secrets,readonly",
        "-e", "SAP_HOST=your-sap-host.company.com",
        "-e", "SAP_CLIENT=100",
        "-e", "SAP_USERNAME=your-username",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "abap-accelerator-q:3.2.0-node22",
        "node", "dist/index.js"
      ],
      "timeout": 60000,
      "disabled": false
    }
  }
}
```

#### Configuration (Mac/Linux):
```json
{
  "mcpServers": {
    "abap-accelerator-q": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--mount", "type=bind,source=/Users/YourUsername/path/to/secrets,target=/run/secrets,readonly",
        "-e", "SAP_HOST=your-sap-host.company.com",
        "-e", "SAP_CLIENT=100",
        "-e", "SAP_USERNAME=your-username",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "abap-accelerator-q:3.2.0-node22",
        "node", "dist/index.js"
      ],
      "timeout": 60000,
      "disabled": false
    }
  }
}
```

#### For Finch or Podman:
Replace `"command": "docker"` with `"command": "finch"` or `"command": "podman"`

**Important Configuration Notes:**
1. **Replace the source path** with your actual absolute path to the secrets folder
2. **Windows paths**: Use forward slashes: `C:/Users/YourUsername/path/to/secrets`
3. **Mac/Linux paths**: Use absolute paths: `/Users/YourUsername/path/to/secrets`
4. **Password with advanced security features**: Password is stored in `secrets/sap_password` file, never in this config
5. **Timeout**: Set to 60000ms (60 seconds) for SAP system connections
6. **After editing**: Restart Amazon Q Developer or reload the MCP configuration

## Multiple SAP Systems Configuration

### Connecting to Multiple SAP Systems (ECC and S/4HANA)

If you need to connect to multiple SAP systems (e.g., ECC and S/4HANA environments), you can configure multiple MCP server instances. Each instance will connect to a different SAP system.

**Note:** You can extend this pattern to connect to multiple SAP systems by following the same steps for the other systems. Docker will automatically spin up separate containers for each configured system, allowing simultaneous connections to all your SAP environments.

#### Setup for Multiple Systems

**1. Create separate secrets folders:**
```bash
# Windows
mkdir secrets\ecc
mkdir secrets\s4hana
echo your-ecc-password > secrets\ecc\sap_password
echo your-s4hana-password > secrets\s4hana\sap_password

# Mac/Linux
mkdir -p secrets/ecc
mkdir -p secrets/s4hana
echo "your-ecc-password" > secrets/ecc/sap_password
echo "your-s4hana-password" > secrets/s4hana/sap_password

# Set permissions (Mac/Linux only)
chmod 600 secrets/ecc/sap_password
chmod 600 secrets/s4hana/sap_password
chmod 755 secrets/ecc/
chmod 755 secrets/s4hana/
```

**2. Multi-System MCP Configuration:**

#### Windows Configuration:
```json
{
  "mcpServers": {
    "abap-ecc-system": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--mount", "type=bind,source=C:/Users/YourUsername/path/to/secrets/ecc,target=/run/secrets,readonly",
        "-e", "SAP_HOST=ecc-system.company.com",
        "-e", "SAP_CLIENT=100",
        "-e", "SAP_USERNAME=ecc-username",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "abap-accelerator-q:3.2.0-node22",
        "node", "dist/index.js"
      ],
      "timeout": 60000,
      "disabled": false
    },
    "abap-s4hana-system": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--mount", "type=bind,source=C:/Users/YourUsername/path/to/secrets/s4hana,target=/run/secrets,readonly",
        "-e", "SAP_HOST=s4hana-system.company.com",
        "-e", "SAP_CLIENT=200",
        "-e", "SAP_USERNAME=s4hana-username",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "abap-accelerator-q:3.2.0-node22",
        "node", "dist/index.js"
      ],
      "timeout": 60000,
      "disabled": false
    }
  }
}
```

#### Mac/Linux Configuration:
```json
{
  "mcpServers": {
    "abap-ecc-system": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--mount", "type=bind,source=/Users/YourUsername/path/to/secrets/ecc,target=/run/secrets,readonly",
        "-e", "SAP_HOST=ecc-system.company.com",
        "-e", "SAP_CLIENT=100",
        "-e", "SAP_USERNAME=ecc-username",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "abap-accelerator-q:3.2.0-node22",
        "node", "dist/index.js"
      ],
      "timeout": 60000,
      "disabled": false
    },
    "abap-s4hana-system": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--platform", "linux/amd64",
        "--mount", "type=bind,source=/Users/YourUsername/path/to/secrets/s4hana,target=/run/secrets,readonly",
        "-e", "SAP_HOST=s4hana-system.company.com",
        "-e", "SAP_CLIENT=200",
        "-e", "SAP_USERNAME=s4hana-username",
        "-e", "SAP_LANGUAGE=EN",
        "-e", "SAP_SECURE=true",
        "abap-accelerator-q:3.2.0-node22",
        "node", "dist/index.js"
      ],
      "timeout": 60000,
      "disabled": false
    }
  }
}
```

#### How Multiple Systems Work:

**In Amazon Q Developer, you'll see separate tool sets:**
- Tools prefixed with `abap-ecc-system_` for ECC operations
- Tools prefixed with `abap-s4hana-system_` for S/4HANA operations

**Usage Examples:**
```
User: "Get source code for class ZCL_TEST from ECC system"
Q Developer: Uses abap-ecc-system tools automatically

User: "Create a new class in S/4HANA system"
Q Developer: Uses abap-s4hana-system tools automatically

User: "Now check the same class in S/4HANA"
Q Developer: Switches to S/4HANA system tools
```

**Benefits of Multiple System Setup:**
- ✅ **Isolated credentials** - separate passwords per system
- ✅ **Clear separation** - no confusion between systems
- ✅ **Parallel access** - work with both systems simultaneously
- ✅ **Easy switching** - Q Developer handles system selection based on context
- ✅ **No code changes** - uses same container image for all systems
- ✅ **Scalable** - add more SAP systems by following the same pattern
- ✅ **Automatic containers** - Docker spins up separate containers for each system

**Final folder structure for multiple systems:**
```
secrets/
├── ecc/
│   └── sap_password    # ECC system password
└── s4hana/
    └── sap_password    # S/4HANA system password
```

## Troubleshooting

### Common Issues

**MCP Client shows "Connection failed" or timeout:**
1. **Check container image is loaded:**
   ```bash
   docker images | grep abap-accelerator-q
   ```

2. **Test the exact MCP command manually:**
   ```bash
   # Windows (use your actual path):
   docker run --rm -i --platform linux/amd64 \
     --mount type=bind,source=C:/Users/YourUsername/path/to/secrets,target=/run/secrets,readonly \
     -e SAP_HOST=your-host -e SAP_CLIENT=100 -e SAP_USERNAME=your-username \
     -e SAP_LANGUAGE=EN -e SAP_SECURE=true \
     abap-accelerator-q:3.2.0-node22 node dist/index.js
   
   # Mac/Linux (use your actual path):
   docker run --rm -i --platform linux/amd64 \
     --mount type=bind,source=/full/path/to/secrets,target=/run/secrets,readonly \
     -e SAP_HOST=your-host -e SAP_CLIENT=100 -e SAP_USERNAME=your-username \
     -e SAP_LANGUAGE=EN -e SAP_SECURE=true \
     abap-accelerator-q:3.2.0-node22 node dist/index.js
   ```

**"No such file or directory" error:**
1. **Verify the secrets folder path is correct:**
   ```bash
   # Windows - Check if path exists
   dir "C:\Users\YourUsername\path\to\secrets"
   
   # Mac/Linux - Check if path exists
   ls -la /Users/YourUsername/path/to/secrets
   ```

2. **Use absolute paths** - relative paths don't work with bind mounts
3. **Windows**: Use forward slashes in MCP config: `C:/path/to/secrets`

**SAP Connection fails:**
1. **Check password file content:**
   ```bash
   # Windows
   type secrets\sap_password
   
   # Mac/Linux
   cat secrets/sap_password
   ```

2. **Verify SAP system is reachable:** 
   ```bash
   ping your-sap-system.company.com
   ```

3. **Check secrets are mounted correctly:**
   ```bash
   # Test if secrets are accessible in container
   docker run --rm \
     --mount type=bind,source=/full/path/to/secrets,target=/run/secrets,readonly \
     abap-accelerator-q:3.2.0-node22 \
     ls -la /run/secrets/
   
   # Check password file content inside container
   docker run --rm \
     --mount type=bind,source=/full/path/to/secrets,target=/run/secrets,readonly \
     abap-accelerator-q:3.2.0-node22 \
     cat /run/secrets/sap_password
   ```

**Permission errors (Mac/Linux):**
```bash
# Fix file permissions
chmod 600 secrets/sap_password
chmod 755 secrets/  # Directory needs to be readable
```

**Windows path issues:**
- Use forward slashes in MCP config: `C:/Users/Username/path` not `C:\Users\Username\path`
- Ensure no spaces in the path or use quotes properly
- Use the full absolute path, not relative paths

**Platform compatibility issues (Apple Silicon):**
1. **Generally include** `--platform linux/amd64` flag for compatibility
2. **Docker Desktop**: Enable Rosetta 2 emulation in Settings → General
3. **Finch**: Platform flag is required

### Debugging Commands

```bash
# Check runtime version
docker --version
finch --version
podman --version

# Test if secrets are mounted correctly
docker run --rm \
  --mount type=bind,source=/full/path/to/secrets,target=/run/secrets,readonly \
  abap-accelerator-q:3.2.0-node22 \
  ls -la /run/secrets/

# Test network connectivity from container
docker run --rm \
  abap-accelerator-q:3.2.0-node22 \
  ping -c 3 your-sap-system.company.com

# Check system resources
docker system df
finch system df
podman system df
```

### MCP Configuration Troubleshooting

**Common MCP config mistakes:**
1. **Wrong path separators** - Use `/` not `\` even on Windows
2. **Relative paths** - Generally use absolute paths for bind mounts
3. **Missing timeout** - Add `"timeout": 60000` (60 seconds) for SAP system connections
4. **Wrong image name** - Help achieve correct configuration by matching: `abap-accelerator-q:3.2.0-node22`
5. **Password in config** - Never put password in MCP config, use secrets folder only

## Universal Commands

### Container Management
```bash
# List running containers
[docker|finch|podman] ps

# View logs
[docker|finch|podman] logs <container-id>

# Stop container
[docker|finch|podman] stop <container-id>

# List images
[docker|finch|podman] images

# System cleanup
[docker|finch|podman] system prune
```

## Security Features

This configuration provides advanced security features through:

- **🔒 Docker Secrets** - Password stored in separate file, not in MCP configuration
- **📁 Bind Mount with Advanced Security Features** - Read-only access to secrets folder
- **🚫 No Credentials in Config** - SAP password never appears in MCP configuration files
- **🔐 File Permissions** - File permissions (600 for password file, 755 for directory on Mac/Linux) help protect against unintended access to the password file
- **🛡️ Container Isolation** - Secrets are only accessible within the container

## Available MCP Tools

The server provides these tools for ABAP development:

### Object Management
- `aws_abap_cb_get_objects` - List ABAP objects
- `aws_abap_cb_create_object` - Create new objects
- `aws_abap_cb_get_source` - Get source code
- `aws_abap_cb_update_source` - Update source code

### Development Tools
- `aws_abap_cb_check_syntax` - Syntax validation
- `aws_abap_cb_activate_object` - Activate objects
- `aws_abap_cb_run_unit_tests` - Execute unit tests
- `aws_abap_cb_run_atc_check` - Run ATC checks (you can also provide your variant name in the prompt)

### Advanced Features
- `aws_abap_cb_search_object` - Search for objects
- `aws_abap_cb_generate_documentation` - Generate docs in the SAP System (requires custom ODATA Service)
- `aws_abap_cb_get_migration_analysis` - Get Custom Code Migration analysis
- `aws_abap_cb_create_or_update_test_class` - Create or update unit test class

## Runtime-Specific Management

### Docker Desktop
```bash
# Start Docker Desktop (GUI application)
# Containers start automatically with --rm flag

# Monitor via GUI or CLI
docker ps
docker stats

# Stop Docker Desktop to save resources
# Docker Desktop → Quit Docker Desktop
```

### Finch
```bash
# Check VM status
finch vm status

# Start VM if stopped
finch vm start

# Stop VM to save resources
finch vm stop

# Monitor containers
finch ps
finch stats
```

### Podman
```bash
# Check machine status (Mac/Windows)
podman machine list

# Start machine if stopped
podman machine start

# Stop machine to save resources
podman machine stop

# Monitor containers
podman ps
podman stats
```

## Security Best Practices

### Password Management
- ✅ **DO**: Store password in `secrets/sap_password` file
- ✅ **DO**: Use bind mount with `readonly` flag
- ✅ **DO**: Set file permissions to 600 for password file and 755 for directory (Mac/Linux)
- ❌ **DON'T**: Put password in MCP configuration
- ❌ **DON'T**: Put password in .env file
- ❌ **DON'T**: Commit secrets folder to version control

### Container Security with Advanced Security Features
- Use `--rm` flag for automatic cleanup
- Mount secrets as read-only
- Container runs as non-root user
- No network exposure beyond SAP connection

### File Permissions (Mac/Linux)
```bash
# Set file permissions for advanced security features
# 600 = read/write for owner only, no access for others
chmod 600 secrets/sap_password

# Help achieve directory accessibility
# 755 = read/execute for all, write for owner only
chmod 755 secrets/
```

**Your secrets folder and configuration remain the same across updates.**
