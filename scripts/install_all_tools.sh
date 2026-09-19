#!/usr/bin/env bash
# ==============================================================================
# KIIBOT — Complete External Tools Installer for CTF Competitions
# Targets: Kali Linux, Debian, Ubuntu, and WSL2
# ==============================================================================

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}   KIIBOT — CTF Competitions Ultimate Tool Suite Installer      ${NC}"
echo -e "${CYAN}================================================================${NC}"

# Check for root / sudo
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

echo -e "\n${YELLOW}[+] Step 1: Updating system packages...${NC}"
$SUDO apt update -y

echo -e "\n${YELLOW}[+] Step 2: Installing Essential Core CTF System Packages (APT)...${NC}"
$SUDO apt install -y \
  aircrack-ng \
  apktool \
  binutils \
  binwalk \
  build-essential \
  bulk-extractor \
  checksec \
  clang \
  crunch \
  curl \
  dnsrecon \
  dnsutils \
  dsniff \
  ettercap-text-only \
  exiv2 \
  feh \
  feroxbuster \
  ffmpeg \
  ffuf \
  file \
  foremost \
  gdb \
  ghidra \
  git \
  gobuster \
  hashcat \
  httpx-toolkit \
  hydra \
  jadx \
  john \
  jq \
  ltrace \
  masscan \
  nasm \
  ncat \
  netcat-openbsd \
  net-tools \
  ngrep \
  nikto \
  nmap \
  nuclei \
  openssl \
  patchelf \
  pdf-parser \
  pngcheck \
  procps \
  pwndbg \
  radare2 \
  rsync \
  sleuthkit \
  smbclient \
  socat \
  sqlmap \
  steghide \
  stegsnow \
  strace \
  sublist3r \
  tcpdump \
  tcpflow \
  tcpreplay \
  tesseract-ocr \
  traceroute \
  tshark \
  unrar \
  unzip \
  upx-ucl \
  wafw00f \
  wfuzz \
  wget \
  whatweb \
  whois \
  wireshark \
  wkhtmltopdf \
  xxd \
  yara \
  zbar-tools \
  zeek \
  zsteg || true

echo -e "\n${YELLOW}[+] Step 3: Installing CTF Python & Reversing Modules (PIP)...${NC}"
python3 -m pip install --upgrade --quiet pip setuptools wheel
python3 -m pip install --upgrade --quiet \
  angr \
  capstone \
  cryptography \
  factordb-pycli \
  hashid \
  jwt_tool \
  keystone-engine \
  openai \
  pdfparser \
  pillow \
  pycryptodome \
  pwn \
  pwntools \
  pyjwt \
  python-magic \
  python-telegram-bot \
  requests \
  ropgadget \
  ropper \
  scapy \
  timm \
  volatility3 \
  z3-solver || true

echo -e "\n${YELLOW}[+] Step 4: Installing StegSeek & Dedicated CTF Tools...${NC}"
if ! command -v stegseek &>/dev/null; then
    echo "[*] Downloading and installing stegseek..."
    STEGSEEK_URL="https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb"
    wget -q "$STEGSEEK_URL" -O /tmp/stegseek.deb && $SUDO dpkg -i /tmp/stegseek.deb || true
    rm -f /tmp/stegseek.deb
fi

# Ensure wordlists (rockyou) are uncompressed for hashcat/john/stegseek
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "[*] Uncompressing rockyou.txt wordlist..."
    $SUDO gzip -d -k /usr/share/wordlists/rockyou.txt.gz || true
fi

echo -e "\n${YELLOW}[+] Step 5: Installing Modern CTF Go Tools (if Go is present)...${NC}"
if command -v go &>/dev/null; then
    echo "[*] Installing projectdiscovery and ffuf Go binaries..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest || true
fi

echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}  [✓] All Local CTF Tools have been installed successfully!    ${NC}"
echo -e "${GREEN}  Run 'kiibot doctor' or '/doctor' in Telegram to verify.     ${NC}"
echo -e "${GREEN}================================================================${NC}"
