#!/bin/bash
#
# Hanirizer Installation Script
# Installs Hanirizer with all required archive format support
#

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        Hanirizer Installation Script v1.2.3                ║"
echo "║    Network Configuration Sanitizer with Full Archive Support    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
    else
        DISTRO="unknown"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    DISTRO="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
    DISTRO="windows"
else
    OS="unknown"
    DISTRO="unknown"
fi

echo "Detected OS: $OS ($DISTRO)"
echo

# Check if running as root for system package installation
if [[ $EUID -ne 0 ]] && [[ "$OS" == "linux" ]]; then
    echo "Note: System packages require sudo. You may be prompted for your password."
    echo
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install system packages
install_system_packages() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Installing System Dependencies (7z and unrar)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    echo "⚠️  IMPORTANT: 7z and RAR are the most common archive formats"
    echo "   for network device configurations. Installing these tools"
    echo "   ensures Hanirizer can handle all vendor-provided configs."
    echo

    if [[ "$DISTRO" == "debian" ]]; then
        echo "Installing for Debian/Ubuntu..."
        sudo apt-get update
        sudo apt-get install -y p7zip-full unrar

    elif [[ "$DISTRO" == "rhel" ]]; then
        echo "Installing for RHEL/Fedora/CentOS..."
        sudo dnf install -y p7zip p7zip-plugins unrar || sudo yum install -y p7zip p7zip-plugins unrar

    elif [[ "$DISTRO" == "arch" ]]; then
        echo "Installing for Arch Linux..."
        sudo pacman -S --noconfirm p7zip unrar

    elif [[ "$DISTRO" == "macos" ]]; then
        echo "Installing for macOS..."
        if ! command_exists brew; then
            echo "Error: Homebrew not found. Install from https://brew.sh/"
            echo "Then run: brew install p7zip unrar"
            return 1
        fi
        brew install p7zip unrar

    elif [[ "$DISTRO" == "windows" ]]; then
        echo "Installing for Windows..."
        if ! command_exists choco; then
            echo "Error: Chocolatey not found. Install from https://chocolatey.org/"
            echo "Then run: choco install 7zip unrar"
            return 1
        fi
        choco install -y 7zip unrar

    else
        echo "⚠️  Unknown distribution. Please install manually:"
        echo "   - p7zip or 7-Zip"
        echo "   - unrar"
        return 1
    fi

    echo "✓ System packages installed"
    echo
}

# Function to install Python packages
install_python_packages() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Installing Python Dependencies"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo

    # Check Python version
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version | awk '{print $2}')
        echo "Found Python $PYTHON_VERSION"
    else
        echo "Error: Python 3 not found. Please install Python 3.8 or later."
        exit 1
    fi

    # Install Hanirizer
    echo "Installing Hanirizer..."
    pip3 install --upgrade pip
    pip3 install .

    echo "✓ Python packages installed"
    echo
}

# Function to verify installation
verify_installation() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Verifying Installation"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo

    ERRORS=0

    # Check Python packages
    echo "[Python Packages]"
    if pip3 show hanirizer >/dev/null 2>&1; then
        VERSION=$(pip3 show hanirizer | grep Version | awk '{print $2}')
        echo "  ✓ hanirizer $VERSION"
    else
        echo "  ✗ hanirizer not found"
        ERRORS=$((ERRORS + 1))
    fi

    if pip3 show click >/dev/null 2>&1; then
        echo "  ✓ click"
    else
        echo "  ✗ click not found"
        ERRORS=$((ERRORS + 1))
    fi

    if pip3 show pyyaml >/dev/null 2>&1; then
        echo "  ✓ pyyaml"
    else
        echo "  ✗ pyyaml not found"
        ERRORS=$((ERRORS + 1))
    fi

    if pip3 show pyminizip >/dev/null 2>&1; then
        echo "  ✓ pyminizip (encrypted ZIP support)"
    else
        echo "  ⚠ pyminizip not found (optional - for creating encrypted ZIPs)"
    fi

    echo
    echo "[System Tools - Archive Support]"

    if command_exists 7z; then
        echo "  ✓ 7z installed (7z/7zip archive support)"
    else
        echo "  ✗ 7z not found - 7z archives will NOT work"
        ERRORS=$((ERRORS + 1))
    fi

    if command_exists unrar; then
        echo "  ✓ unrar installed (RAR archive support)"
    else
        echo "  ✗ unrar not found - RAR archives will NOT work"
        ERRORS=$((ERRORS + 1))
    fi

    echo
    echo "[Commands]"

    if command_exists netsan; then
        echo "  ✓ netsan command available"
        NETSAN_VERSION=$(netsan --version 2>&1 | head -1 || echo "unknown")
        echo "    Version: $NETSAN_VERSION"
    else
        echo "  ✗ netsan command not found"
        ERRORS=$((ERRORS + 1))
    fi

    echo
    echo "[Supported Archive Formats]"
    echo "  ✓ ZIP (built-in)"
    echo "  ✓ TAR/TAR.GZ/TAR.BZ2/TAR.XZ (built-in)"

    if command_exists 7z; then
        echo "  ✓ 7Z (via 7z tool)"
    else
        echo "  ✗ 7Z (7z tool required)"
    fi

    if command_exists unrar; then
        echo "  ✓ RAR (via unrar tool)"
    else
        echo "  ✗ RAR (unrar tool required)"
    fi

    echo

    if [ $ERRORS -eq 0 ]; then
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  ✓✓✓ Installation Successful - All Features Available  ✓✓✓ ║"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo
        echo "Hanirizer is ready to use!"
        echo
        echo "Try it:"
        echo "  netsan sanitize myconfig.conf"
        echo "  netsan sanitize-archive configs.zip"
        echo "  netsan sanitize-archive configs.7z"
        echo "  netsan sanitize-archive configs.rar"
        return 0
    else
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  ⚠⚠⚠  Installation Incomplete - Missing Dependencies  ⚠⚠⚠  ║"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo
        echo "Found $ERRORS issue(s). Some archive formats will not work."
        echo
        echo "To fix:"
        if [[ "$DISTRO" == "debian" ]]; then
            echo "  sudo apt-get install p7zip-full unrar"
        elif [[ "$DISTRO" == "rhel" ]]; then
            echo "  sudo dnf install p7zip p7zip-plugins unrar"
        elif [[ "$DISTRO" == "macos" ]]; then
            echo "  brew install p7zip unrar"
        elif [[ "$DISTRO" == "windows" ]]; then
            echo "  choco install 7zip unrar"
        fi
        return 1
    fi
}

# Main installation flow
main() {
    echo "This script will install:"
    echo "  1. System dependencies (7z, unrar) - REQUIRED for most configs"
    echo "  2. Python packages (hanirizer, click, pyyaml, pyminizip)"
    echo "  3. Verification checks"
    echo

    read -p "Continue with installation? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ -n $REPLY ]]; then
        echo "Installation cancelled."
        exit 0
    fi

    echo

    # Install system packages
    if install_system_packages; then
        echo "✓ System dependencies installed"
    else
        echo "⚠ System dependencies installation had issues"
        echo "  You can still use Hanirizer, but 7z/RAR support may not work"
    fi

    echo

    # Install Python packages
    install_python_packages

    # Verify installation
    verify_installation
    EXIT_CODE=$?

    echo
    echo "Installation script completed."

    exit $EXIT_CODE
}

# Run main function
main
