#!/usr/bin/env bash
# ==============================================================================
# KIIBOT Installation Script
# Automated setup for Kali Linux, Debian, Ubuntu, and WSL2 environments
# ==============================================================================

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
cat << "EOF"
 ██╗  ██╗ ██╗ ██╗ ██████╗  ██████╗ ████████╗
 ██║ ██╔╝ ██║ ██║ ██╔══██╗ ██╔═══██╗╚══██╔══╝
 █████╔╝  ██║ ██║ ██████╔╝ ██║   ██║   ██║   
 ██╔═██╗  ██║ ██║ ██╔══██╗ ██║   ██║   ██║   
 ██║  ██╗ ██║ ██║ ██████╔╝ ╚██████╔╝   ██║   
 ╚═╝  ╚═╝ ╚═╝ ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   
EOF
echo -e "${NC}"
echo -e "${CYAN}=== KIIBOT Workstation Installer ===${NC}\n"

# Parse flags
INSTALL_ALL_TOOLS=false
for arg in "$@"; do
    if [ "$arg" == "--all-tools" ] || [ "$arg" == "-a" ]; then
        INSTALL_ALL_TOOLS=true
    fi
done

# 1. Check OS and Environment
echo -e "[*] Detecting operating system..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME=$NAME
    echo -e "    Detected: ${GREEN}${OS_NAME}${NC}"
else
    echo -e "    ${YELLOW}Warning: Unknown Linux distribution.${NC}"
fi

# 2. Check Python 3.11+
echo -e "[*] Checking Python version..."
PYTHON_BIN=""
for cmd in python3.11 python3.12 python3.13 python3; do
    if command -v "$cmd" &>/dev/null; then
        PY_VER=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$("$cmd" -c 'import sys; print(sys.version_info.major)')
        PY_MINOR=$("$cmd" -c 'import sys; print(sys.version_info.minor)')
        if [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -ge 11 ]; then
            PYTHON_BIN="$cmd"
            echo -e "    Found compatible Python: ${GREEN}$PYTHON_BIN ($PY_VER)${NC}"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[!] Error: Python 3.11 or newer is required.${NC}"
    echo -e "    Please install it using: sudo apt update && sudo apt install -y python3.11 python3.11-venv python3-pip"
    exit 1
fi

# 3. Create ~/.kiibot directories
echo -e "[*] Setting up directory structure..."
KIIBOT_DIR="${KIIBOT_HOME:-$HOME/.kiibot}"
mkdir -p "$KIIBOT_DIR/config"
mkdir -p "$KIIBOT_DIR/logs"
mkdir -p "$KIIBOT_DIR/challenges"
mkdir -p "$KIIBOT_DIR/workspaces"
mkdir -p "$KIIBOT_DIR/cache"
echo -e "    Created directory: ${GREEN}$KIIBOT_DIR${NC}"

# 4. Create Virtual Environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$KIIBOT_DIR/venv"

echo -e "[*] Setting up virtual environment at ${VENV_DIR}..."
if [ ! -d "$VENV_DIR" ]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# 5. Install Dependencies
echo -e "[*] Installing KIIBOT and dependencies..."
pip install --upgrade pip setuptools wheel
pip install -e "$SCRIPT_DIR"

# 6. Copy default configuration if not exists
if [ ! -f "$KIIBOT_DIR/config/config.yaml" ]; then
    echo -e "[*] Creating default configuration..."
    if [ -f "$SCRIPT_DIR/configs/defaults.yaml" ]; then
        cp "$SCRIPT_DIR/configs/defaults.yaml" "$KIIBOT_DIR/config/config.yaml"
    fi
fi

# 7. Install CLI wrapper to ~/.local/bin or /usr/local/bin
mkdir -p "$HOME/.local/bin"
BIN_TARGET="$HOME/.local/bin/kiibot"

cat << EOF > "$BIN_TARGET"
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
exec "$VENV_DIR/bin/kiibot" "\$@"
EOF
chmod +x "$BIN_TARGET"

echo -e "    Installed launcher to: ${GREEN}$BIN_TARGET${NC}"

# Ensure ~/.local/bin is in PATH notice
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo -e "${YELLOW}[!] Notice: Please add ~/.local/bin to your PATH:${NC}"
    echo -e "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
    echo -e "    source ~/.bashrc"
fi

echo -e "\n${GREEN}[✓] Installation completed successfully!${NC}\n"

# 8. Run Doctor Diagnostics
echo -e "[*] Running initial system diagnostics..."
"$BIN_TARGET" doctor || true

if [ "$INSTALL_ALL_TOOLS" = true ]; then
    echo -e "\n[*] --all-tools flag passed. Installing all local CTF tools..."
    bash "$SCRIPT_DIR/scripts/install_all_tools.sh"
    echo -e "\n[*] Re-running system diagnostics..."
    "$BIN_TARGET" doctor || true
fi

echo -e "\n${CYAN}You can now run KIIBOT using:${NC} ${GREEN}kiibot${NC}\n"
