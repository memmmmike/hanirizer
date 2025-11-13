#!/bin/bash
#
# Hanirizer Dependency Check Script
# Verifies all dependencies are installed and working
#

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          Hanirizer Dependency Check v1.2.3                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo

ERRORS=0
WARNINGS=0

# Colors (if supported)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

# Check function
check_command() {
    local cmd=$1
    local name=$2
    local required=$3
    local install_hint=$4

    if command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $name installed"
        if [ "$cmd" == "7z" ]; then
            VERSION=$(7z 2>&1 | head -2 | tail -1 | awk '{print $3}')
            echo "  Version: $VERSION"
        elif [ "$cmd" == "unrar" ]; then
            VERSION=$(unrar 2>&1 | head -1 | awk '{print $2}')
            echo "  Version: $VERSION"
        fi
        return 0
    else
        if [ "$required" == "yes" ]; then
            echo -e "${RED}✗${NC} $name NOT installed ${RED}(CRITICAL)${NC}"
            echo "  Install: $install_hint"
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${YELLOW}⚠${NC} $name NOT installed (optional)"
            echo "  Install: $install_hint"
            WARNINGS=$((WARNINGS + 1))
        fi
        return 1
    fi
}

# Check Python package
check_python_package() {
    local package=$1
    local required=$2
    local hint=$3

    if pip3 show "$package" >/dev/null 2>&1; then
        VERSION=$(pip3 show "$package" | grep Version | awk '{print $2}')
        echo -e "${GREEN}✓${NC} $package $VERSION"
        return 0
    else
        if [ "$required" == "yes" ]; then
            echo -e "${RED}✗${NC} $package NOT installed ${RED}(CRITICAL)${NC}"
            echo "  Install: pip3 install $package"
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${YELLOW}⚠${NC} $package NOT installed (optional)"
            echo "  Install: pip3 install $package"
            echo "  Note: $hint"
            WARNINGS=$((WARNINGS + 1))
        fi
        return 1
    fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Python Environment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION"
else
    echo -e "${RED}✗${NC} Python 3 NOT found ${RED}(CRITICAL)${NC}"
    ERRORS=$((ERRORS + 1))
fi

echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. Python Packages"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_python_package "hanirizer" "yes"
check_python_package "click" "yes"
check_python_package "pyyaml" "yes"
check_python_package "pyminizip" "no" "Only needed for creating encrypted ZIPs"

echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. System Tools for Archive Support"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Detect OS for install hints
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [ -f /etc/debian_version ]; then
        INSTALL_HINT_7Z="sudo apt-get install p7zip-full"
        INSTALL_HINT_UNRAR="sudo apt-get install unrar"
    elif [ -f /etc/redhat-release ]; then
        INSTALL_HINT_7Z="sudo dnf install p7zip p7zip-plugins"
        INSTALL_HINT_UNRAR="sudo dnf install unrar"
    else
        INSTALL_HINT_7Z="Install p7zip for your distribution"
        INSTALL_HINT_UNRAR="Install unrar for your distribution"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    INSTALL_HINT_7Z="brew install p7zip"
    INSTALL_HINT_UNRAR="brew install unrar"
else
    INSTALL_HINT_7Z="Install 7-Zip for your OS"
    INSTALL_HINT_UNRAR="Install unrar for your OS"
fi

echo -e "${YELLOW}⚠ IMPORTANT:${NC} 7z and RAR are the most common formats for network configs!"

check_command "7z" "7z (7-Zip)" "yes" "$INSTALL_HINT_7Z"
check_command "unrar" "unrar (RAR)" "yes" "$INSTALL_HINT_UNRAR"

echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. Hanirizer Commands"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v netsan >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} netsan command available"
    VERSION=$(netsan --version 2>&1 | head -1 || echo "unknown")
    echo "  $VERSION"
else
    echo -e "${RED}✗${NC} netsan command NOT available ${RED}(CRITICAL)${NC}"
    echo "  This means Hanirizer is not installed correctly"
    ERRORS=$((ERRORS + 1))
fi

echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. Archive Format Support"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo -e "${GREEN}✓${NC} ZIP (built-in Python support)"
echo -e "${GREEN}✓${NC} TAR/TAR.GZ/TAR.BZ2/TAR.XZ (built-in Python support)"

if command -v 7z >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} 7Z (via 7z tool) ${GREEN}[AVAILABLE]${NC}"
else
    echo -e "${RED}✗${NC} 7Z ${RED}[NOT AVAILABLE]${NC}"
    echo "  ${YELLOW}WARNING: Most vendors use 7z format!${NC}"
fi

if command -v unrar >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} RAR (via unrar tool) ${GREEN}[AVAILABLE]${NC}"
else
    echo -e "${RED}✗${NC} RAR ${RED}[NOT AVAILABLE]${NC}"
    echo "  ${YELLOW}WARNING: Many network devices export to RAR!${NC}"
fi

echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. Functionality Test"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v netsan >/dev/null 2>&1; then
    if netsan --version >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Hanirizer is working correctly"
    else
        echo -e "${RED}✗${NC} Hanirizer command exists but has errors"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${RED}✗${NC} Cannot test - netsan not available"
fi

echo

# Final summary
echo "╔════════════════════════════════════════════════════════════╗"

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo "║        ✓✓✓ ALL DEPENDENCIES INSTALLED ✓✓✓                  ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo
    echo -e "${GREEN}Perfect!${NC} Hanirizer is ready to handle all archive formats:"
    echo "  • ZIP (encrypted or not)"
    echo "  • 7Z (encrypted or not)"
    echo "  • RAR (encrypted or not)"
    echo "  • TAR, TAR.GZ, TAR.BZ2, TAR.XZ"
    echo
    echo "You can now sanitize any network config archive!"
    EXIT_CODE=0

elif [ $ERRORS -eq 0 ] && [ $WARNINGS -gt 0 ]; then
    echo "║     ⚠ INSTALLATION COMPLETE WITH WARNINGS ⚠               ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo
    echo -e "${YELLOW}Found $WARNINGS warning(s)${NC} - optional features missing"
    echo "Hanirizer will work, but some features may be limited."
    EXIT_CODE=0

else
    echo "║        ✗✗✗ MISSING CRITICAL DEPENDENCIES ✗✗✗              ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo
    echo -e "${RED}Found $ERRORS critical issue(s)${NC}"
    echo
    echo -e "${YELLOW}IMPORTANT:${NC} Network configs are commonly distributed as:"
    echo "  1. 7z archives (most common)"
    echo "  2. RAR archives (very common)"
    echo "  3. ZIP archives (common)"
    echo
    echo "Without 7z and unrar tools, you won't be able to process"
    echo "most vendor-provided configuration backups!"
    echo
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Quick Fix:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            echo "sudo apt-get install p7zip-full unrar"
        elif [ -f /etc/redhat-release ]; then
            echo "sudo dnf install p7zip p7zip-plugins unrar"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "brew install p7zip unrar"
    fi

    echo
    echo "Or run the installation script:"
    echo "  bash install.sh"

    EXIT_CODE=1
fi

echo

exit $EXIT_CODE
