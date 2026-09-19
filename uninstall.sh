#!/usr/bin/env bash
# ==============================================================================
# KIIBOT Uninstallation Script
# Removes virtual environment, binary launcher, and optionally user data
# ==============================================================================

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${YELLOW}=== KIIBOT Uninstaller ===${NC}\n"

BIN_TARGET="$HOME/.local/bin/kiibot"
KIIBOT_DIR="${KIIBOT_HOME:-$HOME/.kiibot}"

# Remove launcher
if [ -f "$BIN_TARGET" ]; then
    echo -e "[*] Removing launcher: $BIN_TARGET"
    rm -f "$BIN_TARGET"
fi

# Remove virtual environment
if [ -d "$KIIBOT_DIR/venv" ]; then
    echo -e "[*] Removing virtual environment: $KIIBOT_DIR/venv"
    rm -rf "$KIIBOT_DIR/venv"
fi

echo -e "\n${YELLOW}Do you want to delete all user data, configuration, workspaces, and database? (y/N)${NC}"
read -r response
case "$response" in
    [yY][eE][sS]|[yY])
        echo -e "[*] Removing data directory: $KIIBOT_DIR"
        rm -rf "$KIIBOT_DIR"
        echo -e "${GREEN}[✓] Full uninstallation complete.${NC}"
        ;;
    *)
        echo -e "[*] Kept data in $KIIBOT_DIR"
        echo -e "${GREEN}[✓] Package uninstallation complete.${NC}"
        ;;
esac
