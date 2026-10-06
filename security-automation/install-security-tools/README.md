# Security / IaC Tooling Installer

## Overview

This script automates the installation of common Infrastructure-as-Code (IaC), DevSecOps, and security scanning tools on Ubuntu and Debian-based systems.

The installer is **idempotent**, meaning it only installs tools that are missing and can safely be run multiple times without reinstalling existing software.

## Tools Installed

The script installs and verifies the following tools:

- Terraform
- Checkov
- tfsec
- TFLint
- Trivy
- Semgrep
- pip-audit
- Node.js
- npm
- Gitleaks

It also confirms that **npm audit** is available after npm installation.

---

## Features

- Installs only missing tools
- Supports Ubuntu and Debian distributions
- Performs OS validation before installation
- Runs pre-flight checks
- Handles temporary download failures with retry logic
- Supports version pinning for selected tools
- Automatically adds pipx-installed tools to PATH
- Initializes TFLint plugins after installation
- Provides a detailed installation summary with tool versions
- Safe to run multiple times

---

## Prerequisites

Before running the script, ensure the following:

### Supported Operating Systems

- Ubuntu 22.04+
- Ubuntu 24.04+
- Debian 11+
- Debian 12+

### Requirements

- Internet connectivity
- sudo privileges
- Access to external repositories:
  - GitHub
  - HashiCorp
  - Aqua Security

### Optional

You may specify custom versions for:

- tfsec
- TFLint
- Gitleaks

If no versions are specified, the script installs the latest available release.

---

## Installation

### Make the Script Executable

```bash
chmod +x install-security-tools.sh
```

### Run the Installer

```bash
./install-security-tools.sh
```

If prompted, enter your sudo password.

---

## Version Pinning

Specific tool versions can be installed by setting environment variables.

### Example: Install a Specific tfsec Version

```bash
TFSEC_VERSION=v1.28.14 ./install-security-tools.sh
```

### Example: Install a Specific TFLint Version

```bash
TFLINT_VERSION=v0.58.1 ./install-security-tools.sh
```

### Example: Install a Specific Gitleaks Version

```bash
GITLEAKS_VERSION=v8.24.2 ./install-security-tools.sh
```

### Multiple Version Overrides

```bash
TFSEC_VERSION=v1.28.14 \
TFLINT_VERSION=v0.58.1 \
GITLEAKS_VERSION=v8.24.2 \
./install-security-tools.sh
```

---

## Installed Tool Locations

Most binaries are installed to:

```text
/usr/local/bin
```

Python-based tools installed through pipx are made available through:

```text
~/.local/bin
```

The script automatically updates your PATH for the current session.

---

## Verifying Installation

After execution, the script displays a summary similar to:

```text
✓ terraform
✓ checkov
✓ tfsec
✓ tflint
✓ trivy
✓ semgrep
✓ pip-audit
✓ node
✓ npm
✓ gitleaks
✓ npm audit
```

You can also manually verify tools:

```bash
terraform version
checkov --version
tfsec --version
tflint --version
trivy --version
semgrep --version
pip-audit --version
node --version
npm --version
gitleaks version
```

---

## Typical Use Cases

This installer is useful for:

- Terraform development workstations
- DevSecOps environments
- Cloud engineering labs
- Security scanning CI/CD runners
- IaC code quality validation
- Secrets scanning
- Dependency vulnerability scanning
- Shift-left security initiatives

---

## Notes

- The script can be run repeatedly without impacting existing installations.
- Tool downloads use retry logic to improve reliability.
- TFLint plugins are initialized automatically after installation.
- If a tool installation fails, the final summary will identify the missing component.

---

## Example Usage

```bash
git clone <repository>
cd <repository>

chmod +x install-security-tools.sh

./install-security-tools.sh
```

After completion, your machine will be ready for Terraform validation, security scanning, secret detection, vulnerability analysis, and IaC compliance checks.