#!/usr/bin/env bash

# ============================================================
# Security / IaC Tooling Installer
#
# Supported:
#   Ubuntu 22.04+
#   Ubuntu 24.04+
#   Debian 11+
#   Debian 12+
#
# Requirements:
#   sudo access
#   internet connectivity
#   apt repositories available
#
# Optional:
#   TFSEC_VERSION=vX.Y.Z
#   TFLINT_VERSION=vX.Y.Z
#   GITLEAKS_VERSION=vX.Y.Z
#
# Example:
#   TFSEC_VERSION=v1.28.14 ./install-tools.sh
#
# Safe to run repeatedly.
# Installs only missing software.
#
# Tools:
#   Terraform
#   Checkov
#   tfsec
#   TFLint
#   Trivy
#   Semgrep
#   pip-audit
#   Node.js / npm
#   Gitleaks
#
# ============================================================

set -Eeuo pipefail

# ============================================================
# Configuration
# ============================================================

INSTALL_DIR="/usr/local/bin"

TFSEC_VERSION="${TFSEC_VERSION:-latest}"
TFLINT_VERSION="${TFLINT_VERSION:-latest}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-latest}"

# ============================================================
# Colours
# ============================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================
# Logging
# ============================================================

log() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
    echo -e "${GREEN}[OK]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# ============================================================
# Utility Functions
# ============================================================

add_path() {

    local dir="$1"

    case ":${PATH}:" in
        *":${dir}:"*) ;;
        *) export PATH="${dir}:${PATH}" ;;
    esac
}

download_file() {

    curl \
        --retry 5 \
        --retry-delay 5 \
        --retry-all-errors \
        -fsSL \
        "$@"
}

require_command() {

    command -v "$1" >/dev/null 2>&1 || {
        error "Required command missing: $1"
        return 1
    }
}

require_jq() {

    require_command jq
}

validate_tool() {

    local tool="$1"
    local version_command="$2"

    command -v "${tool}" >/dev/null 2>&1 &&
    eval "${version_command}" >/dev/null 2>&1
}

get_latest_release() {

    local repo="$1"

    download_file \
        "https://api.github.com/repos/${repo}/releases/latest" \
        | jq -r '.tag_name'
}

# ============================================================
# Operating System Validation
# ============================================================

validate_os() {

    [[ -f /etc/os-release ]] || {
        error "Cannot determine operating system."
        exit 1
    }

    source /etc/os-release

    if [[ "${ID}" != "ubuntu" && "${ID_LIKE:-}" != *"debian"* ]]; then
        error "This script supports Ubuntu/Debian only."
        exit 1
    fi
}

# ============================================================
# Preflight Checks
# ============================================================

preflight_checks() {

    log "Running pre-flight checks..."

    require_command sudo
    require_command apt-get

    sudo -v

    if ! wget --spider https://github.com >/dev/null 2>&1; then
        warn "GitHub may not be reachable."
    fi

    if ! wget --spider https://apt.releases.hashicorp.com >/dev/null 2>&1; then
        warn "HashiCorp repository may not be reachable."
    fi

    success "Pre-flight checks complete."
}

# ============================================================
# Base Packages
# ============================================================

install_base_packages() {

    log "Checking base packages..."

    local packages=(
        curl
        wget
        unzip
        tar
        git
        jq
        gnupg
        ca-certificates
        software-properties-common
        python3
        python3-pip
        python3-venv
        pipx
    )

    local missing=()

    for package in "${packages[@]}"; do
        if ! dpkg -s "${package}" >/dev/null 2>&1; then
            missing+=("${package}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then

        log "Installing missing packages..."

        sudo apt-get update
        sudo apt-get install -y "${missing[@]}"

    else
        success "Base packages already installed."
    fi

    pipx ensurepath >/dev/null 2>&1 || true

    add_path "${HOME}/.local/bin"
}

# ============================================================
# Terraform
# ============================================================

install_terraform() {

    if command -v terraform >/dev/null 2>&1; then
        success "Terraform already installed."
        return
    fi

    log "Installing Terraform..."

    sudo mkdir -p /usr/share/keyrings

    download_file https://apt.releases.hashicorp.com/gpg \
        | sudo gpg --dearmor --yes \
        -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

    source /etc/os-release

    local codename
    codename="${UBUNTU_CODENAME:-${VERSION_CODENAME}}"

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com ${codename} main" \
        | sudo tee /etc/apt/sources.list.d/hashicorp.list >/dev/null

    sudo apt-get update
    sudo apt-get install -y terraform

    success "Terraform installed."
}

# ============================================================
# Python Tools
# ============================================================

install_python_tool() {

    local command_name="$1"
    local package_name="$2"

    if command -v "${command_name}" >/dev/null 2>&1; then
        success "${command_name} already installed."
        return
    fi

    log "Installing ${package_name}..."

    pipx install "${package_name}"

    success "${command_name} installed."
}

install_python_tools() {

    install_python_tool checkov checkov
    install_python_tool semgrep semgrep
    install_python_tool pip-audit pip-audit
}

# ============================================================
# TFLint
# ============================================================

install_tflint() {

    if command -v tflint >/dev/null 2>&1; then
        success "TFLint already installed."
        return
    fi

    require_jq

    log "Installing TFLint..."

    local arch
    arch="$(uname -m)"

    case "${arch}" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) error "Unsupported architecture: ${arch}"; return 1 ;;
    esac

    local version="${TFLINT_VERSION}"

    if [[ "${version}" == "latest" ]]; then
        version="$(get_latest_release terraform-linters/tflint)"
    fi

    local url
    url="https://github.com/terraform-linters/tflint/releases/download/${version}/tflint_linux_${arch}.zip"

    local temp_dir
    temp_dir="$(mktemp -d)"

    download_file "${url}" -o "${temp_dir}/tflint.zip"

    unzip -q "${temp_dir}/tflint.zip" -d "${temp_dir}"

    sudo install -m 0755 \
        "${temp_dir}/tflint" \
        "${INSTALL_DIR}/tflint"

    rm -rf "${temp_dir}"

    tflint --init || warn "TFLint plugin initialization failed."

    success "TFLint installed."
}

# ============================================================
# tfsec
# ============================================================

install_tfsec() {

    if command -v tfsec >/dev/null 2>&1; then
        success "tfsec already installed."
        return
    fi

    require_jq

    log "Installing tfsec..."

    local arch
    arch="$(uname -m)"

    case "${arch}" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) error "Unsupported architecture: ${arch}"; return 1 ;;
    esac

    local version="${TFSEC_VERSION}"

    if [[ "${version}" == "latest" ]]; then
        version="$(get_latest_release aquasecurity/tfsec)"
    fi

    local url
    url="https://github.com/aquasecurity/tfsec/releases/download/${version}/tfsec-linux-${arch}"

    local file
    file="$(mktemp)"

    download_file "${url}" -o "${file}"

    sudo install -m 0755 "${file}" "${INSTALL_DIR}/tfsec"

    rm -f "${file}"

    success "tfsec installed."
}

# ============================================================
# Trivy
# ============================================================

install_trivy() {

    if command -v trivy >/dev/null 2>&1; then
        success "Trivy already installed."
        return
    fi

    log "Installing Trivy..."

    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor \
        | sudo tee /usr/share/keyrings/trivy.gpg >/dev/null

    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        | sudo tee /etc/apt/sources.list.d/trivy.list >/dev/null

    sudo apt-get update
    sudo apt-get install -y trivy

    success "Trivy installed."
}

# ============================================================
# NodeJS
# ============================================================

install_nodejs() {

    if command -v node >/dev/null 2>&1 &&
       command -v npm >/dev/null 2>&1; then

        success "Node.js already installed: $(node --version)"
        success "npm already installed: $(npm --version)"
        return
    fi

    log "Installing Node.js and npm..."

    sudo apt-get update
    sudo apt-get install -y nodejs npm

    if command -v node >/dev/null 2>&1; then
        success "Node.js installed: $(node --version)"
    else
        error "Node.js installation failed."
        return 1
    fi

    if command -v npm >/dev/null 2>&1; then
        success "npm installed: $(npm --version)"
    else
        error "npm installation failed."
        return 1
    fi
}

# ============================================================
# Gitleaks
# ============================================================

install_gitleaks() {

    if command -v gitleaks >/dev/null 2>&1; then
        success "Gitleaks already installed."
        return
    fi

    require_jq

    log "Installing Gitleaks..."

    local arch
    arch="$(uname -m)"

    case "${arch}" in
        x86_64) arch="x64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)
            error "Unsupported architecture: ${arch}"
            return 1
            ;;
    esac

    local version="${GITLEAKS_VERSION}"

    if [[ "${version}" == "latest" ]]; then
        version="$(get_latest_release gitleaks/gitleaks)"
    fi

    local version_number="${version#v}"

    local url
    url="https://github.com/gitleaks/gitleaks/releases/download/${version}/gitleaks_${version_number}_linux_${arch}.tar.gz"

    local temp_dir
    temp_dir="$(mktemp -d)"

    download_file "${url}" -o "${temp_dir}/gitleaks.tar.gz"

    tar -xzf "${temp_dir}/gitleaks.tar.gz" \
        -C "${temp_dir}"

    sudo install -m 0755 \
        "${temp_dir}/gitleaks" \
        "${INSTALL_DIR}/gitleaks"

    rm -rf "${temp_dir}"

    success "Gitleaks installed."
}

# ============================================================
# npm audit
# ============================================================

check_npm_audit() {

    if ! command -v npm >/dev/null 2>&1; then
        warn "npm is not installed."
        return
    fi

    if npm audit --help >/dev/null 2>&1; then
        success "npm audit is available."
    else
        warn "npm audit is unavailable."
    fi
}

# ============================================================
# Final Verification
# ============================================================

print_summary() {

    echo
    echo "============================================================"
    echo " Security Tool Installation Summary"
    echo "============================================================"
    echo

    local tools=(
        terraform
        checkov
        tfsec
        tflint
        trivy
        semgrep
        pip-audit
        node
        npm
        gitleaks
    )

    local failed=0
    local version

    for tool in "${tools[@]}"; do

        if command -v "${tool}" >/dev/null 2>&1; then

            case "${tool}" in

                terraform)
                    version="$(terraform version | head -n 1)"
                    ;;

                checkov)
                    version="$(checkov --version 2>&1 | head -n 1)"
                    ;;

                tfsec)
                    version="$(tfsec --version 2>&1 | head -n 1)"
                    ;;

                tflint)
                    version="$(tflint --version 2>&1 | head -n 1)"
                    ;;

                trivy)
                    version="$(trivy --version 2>&1 | head -n 1)"
                    ;;

                semgrep)
                    version="$(semgrep --version 2>&1 | head -n 1)"
                    ;;

                pip-audit)
                    version="$(pip-audit --version 2>&1 | head -n 1)"
                    ;;

                node)
                    version="$(node --version)"
                    ;;

                npm)
                    version="$(npm --version)"
                    ;;

                gitleaks)
                    version="$(gitleaks version 2>&1 | head -n 1)"
                    ;;

                *)
                    version="installed"
                    ;;
            esac

            echo -e "${GREEN}✓${NC} ${tool}: ${version}"

        else

            echo -e "${RED}✗${NC} ${tool}: NOT INSTALLED"
            failed=1

        fi

    done

    echo

    if command -v npm >/dev/null 2>&1 &&
       npm audit --help >/dev/null 2>&1; then

        echo -e "${GREEN}✓${NC} npm audit: available"

    else

        echo -e "${RED}✗${NC} npm audit: unavailable"
        failed=1

    fi

    echo
    echo "============================================================"

    if [[ "${failed}" -eq 0 ]]; then
        success "All requested tools are installed."
    else
        warn "One or more tools are missing."
        warn "Run the installer again to retry."
    fi

    echo "============================================================"
}

# ============================================================
# Main
# ============================================================

main() {

    echo
    echo "============================================================"
    echo " Security / IaC Tool Installer"
    echo "============================================================"
    echo

    log "Ubuntu/Debian version: ${PRETTY_NAME:-Unknown}"
    log "Architecture: $(uname -m)"
    echo

    validate_os

    preflight_checks

    install_base_packages

    echo
    install_terraform

    echo
    install_python_tools

    echo
    install_tflint

    echo
    install_tfsec

    echo
    install_trivy

    echo
    install_nodejs

    echo
    install_gitleaks

    echo
    check_npm_audit

    print_summary
}

main "$@"
