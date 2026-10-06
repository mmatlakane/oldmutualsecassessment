# Cloud Security Scanner

## Overview

Cloud Security Scanner is a Python-based security orchestration tool that executes multiple open-source security scanners against Infrastructure-as-Code (IaC), source code and repository content.

The solution aggregates findings into a single professionally formatted HTML report and machine-readable JSON output.

The following tools are executed:

| Scanner | Purpose |
|---|---|
| Checkov | Infrastructure-as-Code security and compliance scanning |
| tfsec | Terraform security analysis |
| TFLint | Terraform linting and best-practice checks |
| Semgrep | Static application security analysis |
| Trivy | IaC misconfiguration, vulnerabilities and secret detection |
| Gitleaks | Secret and credential detection |

The generated report follows Old Mutual branding requirements and provides a consolidated security view of the scanned repository.


## Features

### Infrastructure as Code Security

- Terraform Security Analysis
- Terraform Best Practice Validation
- Misconfiguration Detection
- Compliance Validation

### Source Code Security

- Static Application Security Testing (SAST)
- Secure Coding Validation
- Secret Detection
- Dependency Vulnerability Detection

### Reporting

- HTML Executive Report
- JSON Results Export
- Severity Breakdown
- Security Gate Outcome
- Detailed Findings
- Scanner Metadata

---

## Directory Structure

```text
security-automation/
├── security-scan.py
├── README.md
│
├── assets/
│   └── old-mutual-logo.png
│
├── install-security-tools/
│   └── install-security-tools.sh
│
└── results/
    ├── <repository>-security-scan-report.html
    └── <repository>-security-scan-results.json
```


## Prerequisites

### Python

```bash
Python 3.10+
```

### Security Tools

```bash
Checkov
tfsec
TFLint
Semgrep
Trivy
Gitleaks
```

## Running the Scanner

### Scan Current Repository

```bash
chmod +x security-scan.py
Next...
./security-scan.py oldmutualsecassessment --format all
```

## Generated Outputs

CLI Output
```text
Cloud Security Scanner
================================================================
Repository: oldmutualsecassessment
Target:     /home/que/Assessment-Mbali/oldmutualsecassessment
Results:    /home/que/Assessment-Mbali/security-automation/results
```

HTML Report:

```text
results/<repo-name>-security-report.html
```

JSON Report:

```text
results/<repo-name>-security-results.json
```


## Security Gate Logic

The scanner returns:

| Exit Code | Description |
|------------|-------------|
| 0 | Security Gate Passed |
| 1 | Findings Detected or Scanner Error |
| 2 | Configuration Error |


## GitHub Actions Integration

The scanner can be executed automatically through GitHub Actions.

Supported triggers:

- Push
- Pull Request
- Manual Execution

Reports are uploaded as workflow artifacts for review.


## Supported Security Tools

### Checkov

Detects:

- Terraform Misconfigurations
- Cloud Security Issues
- Compliance Violations

### tfsec

Detects:

- Terraform Security Issues
- AWS Configuration Risks

### TFLint

Detects:

- Terraform Syntax Issues
- Provider Best-Practice Violations

### Semgrep

Detects:

- SAST Findings
- Insecure Coding Patterns

### Trivy

Detects:

- Vulnerabilities
- Misconfigurations
- Secrets

### Gitleaks

Detects:

- API Keys
- Passwords
- Access Tokens
- Other Sensitive Information


## Recommendations

For CI/CD environments:

1. Run on every Pull Request.
2. Run before deployment.
3. Upload reports as artifacts.
4. Review Critical and High findings before approval.
5. Automate remediation where possible.


## Ownership

Cloud Engineering and Security Engineering Teams


## License

Internal Use Only
Old Mutual