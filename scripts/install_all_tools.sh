#!/usr/bin/env bash
# ==============================================================================
# KIIBOT PRO — Install All 85+ CTF & SOC Tools
# Target OS: Ubuntu 22.04 / 24.04 LTS (VPS)
# Usage: sudo bash scripts/install_all_tools.sh
# ==============================================================================

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

_ok()   { echo -e "${GREEN}  [✓]${NC} $1"; }
_warn() { echo -e "${YELLOW}  [!]${NC} $1"; }
_fail() { echo -e "${RED}  [✗]${NC} $1 — skip"; }
_info() { echo -e "${BLUE}  [*]${NC} $1"; }
_head() { echo -e "\n${CYAN}══════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}══════════════════════════════════${NC}"; }

# Wajib root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Script ini harus dijalankan sebagai root. Gunakan: sudo bash $0${NC}"
    exit 1
fi

echo -e "${CYAN}"
cat << "BANNER"
  ██╗  ██╗ ██╗ ██╗ ██████╗  ██████╗ ████████╗
  ██║ ██╔╝ ██║ ██║ ██╔══██╗ ██╔═══██╗╚══██╔══╝
  █████╔╝  ██║ ██║ ██████╔╝ ██║   ██║   ██║
  ██╔═██╗  ██║ ██║ ██╔══██╗ ██║   ██║   ██║
  ██║  ██╗ ██║ ██║ ██████╔╝ ╚██████╔╝   ██║
  ╚═╝  ╚═╝ ╚═╝ ╚═╝ ╚═════╝  ╚═════╝    ╚═╝
BANNER
echo -e "${NC}"
echo -e "${CYAN}  === KIIBOT PRO — INSTALL 85+ CTF & SOC TOOLS ===${NC}"
echo -e "${CYAN}  Target: Ubuntu 22.04 / 24.04 LTS VPS${NC}\n"

# ──────────────────────────────────────────────
# STEP 1: Update & base dependencies
# ──────────────────────────────────────────────
_head "STEP 1: Update System & Base Dependencies"
export DEBIAN_FRONTEND=noninteractive
export PIP_BREAK_SYSTEM_PACKAGES=1
apt-get update -qq
apt-get install -yq --no-install-recommends \
    curl wget git python3 python3-pip python3-venv python3-dev \
    build-essential cmake libssl-dev libffi-dev \
    software-properties-common apt-transport-https gnupg \
    ca-certificates lsb-release unzip tar jq \
    net-tools iproute2 lsof procps sysstat \
    file xxd hexdump strings binutils gdb ltrace strace \
    2>&1 | tail -5
_ok "Base dependencies installed"

# ──────────────────────────────────────────────
# STEP 2: Forensics & File Analysis Tools
# ──────────────────────────────────────────────
_head "STEP 2: Forensics & File Analysis Tools"

_info "Installing: file, exiftool, binwalk, foremost, bulk_extractor..."
apt-get install -yq --no-install-recommends \
    exiftool binwalk foremost bulk-extractor \
    pngcheck libimage-exiftool-perl \
    2>&1 | tail -3 && _ok "Forensics base installed" || _fail "Some forensics tools"

_info "Installing: pdf-parser (didier stevens)..."
pip3 install -q pdf-parser 2>/dev/null || \
    wget -q "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py" \
         -O /usr/local/bin/pdf-parser 2>/dev/null && \
    chmod +x /usr/local/bin/pdf-parser && _ok "pdf-parser" || _fail "pdf-parser"

_info "Installing: oletools (macro analysis)..."
pip3 install -q oletools 2>/dev/null && _ok "oletools" || _fail "oletools"

_info "Installing: yara + yara-python..."
apt-get install -yq --no-install-recommends yara 2>/dev/null && _ok "yara" || \
    (pip3 install -q yara-python 2>/dev/null && _ok "yara-python" || _fail "yara")

_info "Installing: Volatility3 (memory forensics)..."
if ! command -v vol3 &>/dev/null; then
    pip3 install -q volatility3 2>/dev/null && _ok "volatility3" || _fail "volatility3"
else
    _ok "volatility3 already installed"
fi

# ──────────────────────────────────────────────
# STEP 3: Steganography Tools
# ──────────────────────────────────────────────
_head "STEP 3: Steganography Tools"

_info "Installing: steghide, stegsnow, zbar-tools, tesseract..."
apt-get install -yq --no-install-recommends \
    steghide stegsnow zbar-tools \
    tesseract-ocr tesseract-ocr-ind \
    libzbar0 imagemagick \
    2>&1 | tail -3 && _ok "Stego base tools installed" || _fail "Some stego tools"

_info "Installing: stegseek..."
if ! command -v stegseek &>/dev/null; then
    STEGSEEK_URL="https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb"
    wget -q "$STEGSEEK_URL" -O /tmp/stegseek.deb 2>/dev/null && \
    apt-get install -yq /tmp/stegseek.deb 2>/dev/null && _ok "stegseek" || _fail "stegseek"
else
    _ok "stegseek already installed"
fi

_info "Installing: zsteg (Ruby gem)..."
if command -v gem &>/dev/null; then
    gem install zsteg -q 2>/dev/null && _ok "zsteg" || _fail "zsteg"
else
    apt-get install -yq ruby 2>/dev/null && \
    gem install zsteg -q 2>/dev/null && _ok "zsteg + ruby" || _fail "zsteg"
fi

_info "Installing: outguess..."
apt-get install -yq --no-install-recommends outguess 2>/dev/null && _ok "outguess" || _fail "outguess"

# ──────────────────────────────────────────────
# STEP 4: Cryptography & Password Tools
# ──────────────────────────────────────────────
_head "STEP 4: Cryptography & Password Cracking Tools"

_info "Installing: hashid, hashcat, john the ripper..."
apt-get install -yq --no-install-recommends hashcat john fcrackzip 2>/dev/null && _ok "hashcat + john + fcrackzip" || _fail "Some crypto tools"
pip3 install -q hashid 2>/dev/null && _ok "hashid" || _fail "hashid"

_info "Installing: RsaCtfTool..."
if ! command -v RsaCtfTool.py &>/dev/null; then
    git clone -q https://github.com/RsaCtfTool/RsaCtfTool.git /opt/RsaCtfTool 2>/dev/null || true
    pip3 install -q -r /opt/RsaCtfTool/requirements.txt 2>/dev/null || true
    ln -sf /opt/RsaCtfTool/RsaCtfTool.py /usr/local/bin/RsaCtfTool.py 2>/dev/null || true
    chmod +x /usr/local/bin/RsaCtfTool.py 2>/dev/null && _ok "RsaCtfTool" || _fail "RsaCtfTool"
else
    _ok "RsaCtfTool already installed"
fi

_info "Installing: jwt_tool..."
if ! command -v jwt_tool &>/dev/null; then
    pip3 install -q jwt_tool 2>/dev/null || \
    (git clone -q https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null && \
     ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool && \
     chmod +x /usr/local/bin/jwt_tool && \
     pip3 install -q termcolor cprint 2>/dev/null)
    _ok "jwt_tool" || _fail "jwt_tool"
else
    _ok "jwt_tool already installed"
fi

_info "Installing: gpg, openssl, crunch..."
apt-get install -yq --no-install-recommends gnupg openssl crunch 2>/dev/null && _ok "gpg + openssl + crunch" || _fail "crypto tools"

# ──────────────────────────────────────────────
# STEP 5: Network & PCAP Tools
# ──────────────────────────────────────────────
_head "STEP 5: Network & PCAP Analysis Tools"

_info "Installing: tshark, tcpdump, nmap, masscan..."
apt-get install -yq --no-install-recommends \
    tshark tcpdump nmap masscan \
    2>&1 | tail -3 && _ok "Network tools installed" || _fail "Some network tools"

_info "Installing: netdiscover, arp-scan..."
apt-get install -yq --no-install-recommends netdiscover arp-scan 2>/dev/null && _ok "netdiscover + arp-scan" || _fail "netdiscover"

# ──────────────────────────────────────────────
# STEP 6: Web Exploitation Tools
# ──────────────────────────────────────────────
_head "STEP 6: Web Exploitation & Recon Tools"

_info "Installing: curl, wget, nikto, whatweb, dirb, hydra..."
apt-get install -yq --no-install-recommends \
    curl wget nikto whatweb dirb hydra \
    2>&1 | tail -3 && _ok "Web base tools installed" || _fail "Some web tools"

_info "Installing: wafw00f..."
pip3 install -q wafw00f 2>/dev/null && _ok "wafw00f" || _fail "wafw00f"

_info "Installing: sqlmap..."
apt-get install -yq --no-install-recommends sqlmap 2>/dev/null || \
    pip3 install -q sqlmap 2>/dev/null && _ok "sqlmap" || _fail "sqlmap"

_info "Installing: gobuster..."
if ! command -v gobuster &>/dev/null; then
    # Try apt first
    apt-get install -yq --no-install-recommends gobuster 2>/dev/null || \
    (command -v go &>/dev/null && go install github.com/OJ/gobuster/v3@latest 2>/dev/null && \
     ln -sf ~/go/bin/gobuster /usr/local/bin/gobuster) || true
    command -v gobuster &>/dev/null && _ok "gobuster" || _fail "gobuster"
else
    _ok "gobuster already installed"
fi

_info "Installing: ffuf..."
if ! command -v ffuf &>/dev/null; then
    apt-get install -yq --no-install-recommends ffuf 2>/dev/null || \
    (FFUF_VER="2.1.0"; \
     wget -q "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz" -O /tmp/ffuf.tar.gz && \
     tar xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf && \
     chmod +x /usr/local/bin/ffuf)
    command -v ffuf &>/dev/null && _ok "ffuf" || _fail "ffuf"
else
    _ok "ffuf already installed"
fi

_info "Installing: nuclei..."
if ! command -v nuclei &>/dev/null; then
    NUCLEI_VER="3.2.4"
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" \
         -O /tmp/nuclei.zip 2>/dev/null && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ 2>/dev/null && \
    chmod +x /usr/local/bin/nuclei 2>/dev/null
    command -v nuclei &>/dev/null && _ok "nuclei" || _fail "nuclei"
    # Download templates
    nuclei -update-templates -silent 2>/dev/null && _ok "nuclei templates updated" || true
else
    _ok "nuclei already installed"
    nuclei -update-templates -silent 2>/dev/null || true
fi

_info "Installing: wpscan..."
if ! command -v wpscan &>/dev/null; then
    gem install wpscan -q 2>/dev/null && _ok "wpscan" || _fail "wpscan"
else
    _ok "wpscan already installed"
fi

_info "Installing: medusa..."
apt-get install -yq --no-install-recommends medusa 2>/dev/null && _ok "medusa" || _fail "medusa"

# ──────────────────────────────────────────────
# STEP 7: Reverse Engineering & Pwn Tools
# ──────────────────────────────────────────────
_head "STEP 7: Reverse Engineering & Exploit Dev Tools"

_info "Installing: gdb, radare2, objdump, readelf, pwntools..."
apt-get install -yq --no-install-recommends \
    gdb gdb-multiarch radare2 \
    binutils-common upx-ucl \
    2>&1 | tail -3 && _ok "RE base tools" || _fail "Some RE tools"

_info "Installing: pwntools (Python)..."
pip3 install -q pwntools 2>/dev/null && _ok "pwntools" || _fail "pwntools"

_info "Installing: ROPgadget..."
pip3 install -q ROPgadget 2>/dev/null && _ok "ROPgadget" || _fail "ROPgadget"

_info "Installing: one_gadget..."
gem install one_gadget -q 2>/dev/null && _ok "one_gadget" || _fail "one_gadget"

_info "Installing: checksec..."
if ! command -v checksec &>/dev/null; then
    pip3 install -q checksec.py 2>/dev/null || \
    (wget -q "https://github.com/slimm609/checksec.sh/raw/master/checksec" -O /usr/local/bin/checksec && \
     chmod +x /usr/local/bin/checksec)
    command -v checksec &>/dev/null && _ok "checksec" || _fail "checksec"
else
    _ok "checksec already installed"
fi

# ──────────────────────────────────────────────
# STEP 8: OSINT Tools
# ──────────────────────────────────────────────
_head "STEP 8: OSINT & Recon Tools"

_info "Installing: whois, dnsutils (dig, nslookup)..."
apt-get install -yq --no-install-recommends whois dnsutils 2>/dev/null && _ok "whois + dig + nslookup" || _fail "DNS tools"

_info "Installing: theHarvester..."
pip3 install -q theHarvester 2>/dev/null || \
    git clone -q https://github.com/laramies/theHarvester.git /opt/theHarvester 2>/dev/null && \
    pip3 install -q -r /opt/theHarvester/requirements/base.txt 2>/dev/null && \
    echo '#!/bin/bash\npython3 /opt/theHarvester/theHarvester.py "$@"' > /usr/local/bin/theHarvester && \
    chmod +x /usr/local/bin/theHarvester
command -v theHarvester &>/dev/null && _ok "theHarvester" || _fail "theHarvester"

_info "Installing: subfinder..."
if ! command -v subfinder &>/dev/null; then
    SF_VER="2.6.6"
    wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v${SF_VER}/subfinder_${SF_VER}_linux_amd64.zip" \
         -O /tmp/subfinder.zip 2>/dev/null && \
    unzip -q /tmp/subfinder.zip subfinder -d /usr/local/bin/ 2>/dev/null && \
    chmod +x /usr/local/bin/subfinder 2>/dev/null
    command -v subfinder &>/dev/null && _ok "subfinder" || _fail "subfinder"
else
    _ok "subfinder already installed"
fi

_info "Installing: amass..."
if ! command -v amass &>/dev/null; then
    snap install amass 2>/dev/null || \
    (AM_VER="4.2.0"; \
     wget -q "https://github.com/owasp-amass/amass/releases/download/v${AM_VER}/amass_Linux_amd64.zip" \
          -O /tmp/amass.zip 2>/dev/null && \
     unzip -q /tmp/amass.zip 'amass_Linux_amd64/amass' -d /tmp/ 2>/dev/null && \
     mv /tmp/amass_Linux_amd64/amass /usr/local/bin/amass && \
     chmod +x /usr/local/bin/amass 2>/dev/null)
    command -v amass &>/dev/null && _ok "amass" || _fail "amass"
else
    _ok "amass already installed"
fi

_info "Installing: shodan CLI..."
pip3 install -q shodan 2>/dev/null && _ok "shodan" || _fail "shodan"

# ──────────────────────────────────────────────
# STEP 9: GitHub & Secret Leak Tools
# ──────────────────────────────────────────────
_head "STEP 9: GitHub Secret Leak Detection Tools"

_info "Installing: trufflehog..."
if ! command -v trufflehog &>/dev/null; then
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null
    command -v trufflehog &>/dev/null && _ok "trufflehog" || _fail "trufflehog"
else
    _ok "trufflehog already installed"
fi

_info "Installing: gitleaks..."
if ! command -v gitleaks &>/dev/null; then
    GL_VER="8.18.4"
    wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_linux_x64.tar.gz" \
         -O /tmp/gitleaks.tar.gz 2>/dev/null && \
    tar xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks 2>/dev/null && \
    chmod +x /usr/local/bin/gitleaks 2>/dev/null
    command -v gitleaks &>/dev/null && _ok "gitleaks" || _fail "gitleaks"
else
    _ok "gitleaks already installed"
fi

# ──────────────────────────────────────────────
# STEP 10: Malware Analysis Tools
# ──────────────────────────────────────────────
_head "STEP 10: Malware Analysis Tools"

_info "Installing: ClamAV..."
apt-get install -yq --no-install-recommends clamav clamav-daemon 2>/dev/null && \
    freshclam --quiet 2>/dev/null || true
command -v clamscan &>/dev/null && _ok "ClamAV" || _fail "ClamAV"

_info "Installing: detect-it-easy (die)..."
if ! command -v die &>/dev/null && ! command -v diec &>/dev/null; then
    DIE_VER="3.09"
    wget -q "https://github.com/horsicq/Detect-It-Easy/releases/download/${DIE_VER}/die_${DIE_VER}_Ubuntu_22.04_amd64.deb" \
         -O /tmp/die.deb 2>/dev/null && \
    apt-get install -yq /tmp/die.deb 2>/dev/null
    (command -v die &>/dev/null || command -v diec &>/dev/null) && _ok "detect-it-easy" || _fail "detect-it-easy"
else
    _ok "detect-it-easy already installed"
fi

# ──────────────────────────────────────────────
# STEP 11: Container Security Tools
# ──────────────────────────────────────────────
_head "STEP 11: Container Security Tools"

_info "Installing: trivy..."
if ! command -v trivy &>/dev/null; then
    wget -q "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh" | bash -s -- -b /usr/local/bin 2>/dev/null || \
    (TRIVY_VER="0.52.0"; \
     wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-64bit.deb" \
          -O /tmp/trivy.deb 2>/dev/null && apt-get install -yq /tmp/trivy.deb 2>/dev/null)
    command -v trivy &>/dev/null && _ok "trivy" || _fail "trivy"
else
    _ok "trivy already installed"
fi

# ──────────────────────────────────────────────
# STEP 12: Wordlists
# ──────────────────────────────────────────────
_head "STEP 12: Wordlists & Dictionaries"

_info "Installing: wordlists (dirb, seclists)..."
apt-get install -yq --no-install-recommends wordlists dirb seclists 2>/dev/null || \
    apt-get install -yq --no-install-recommends wordlists dirb 2>/dev/null
_ok "wordlists installed"

_info "Extracting rockyou.txt..."
if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null && _ok "rockyou.txt extracted" || _warn "rockyou already extracted"
elif [ -f /usr/share/wordlists/rockyou.txt ]; then
    _ok "rockyou.txt already extracted"
else
    _warn "rockyou.txt not found — install wordlists package"
fi

_info "Creating CTF mini-wordlist..."
cat > /usr/share/wordlists/ctf_mini.txt << 'EOF'
admin
administrator
root
user
guest
test
password
password123
pass
123456
1234
admin123
qwerty
letmein
welcome
flag
ctf
hackme
secret
login
EOF
_ok "CTF mini-wordlist created at /usr/share/wordlists/ctf_mini.txt"

# ──────────────────────────────────────────────
# STEP 13: Python Packages (kiibot deps)
# ──────────────────────────────────────────────
_head "STEP 13: Python Packages for KIIBOT"

_info "Installing Python packages..."
pip3 install -q \
    python-telegram-bot \
    google-generativeai \
    python-dotenv \
    pycryptodome \
    Pillow \
    scapy \
    dpkt \
    pyOpenSSL \
    requests \
    beautifulsoup4 \
    python-docx \
    markdown \
    pdfkit \
    cryptography \
    paramiko \
    2>/dev/null && _ok "Python packages installed" || _warn "Some packages may have failed"

# ──────────────────────────────────────────────
# STEP 14: Final Verification
# ──────────────────────────────────────────────
_head "STEP 14: Final Tool Verification"

declare -A TOOLS=(
    ["file"]="file"
    ["strings"]="strings"
    ["exiftool"]="exiftool"
    ["hexdump"]="hexdump"
    ["xxd"]="xxd"
    ["binwalk"]="binwalk"
    ["foremost"]="foremost"
    ["volatility3"]="vol3"
    ["steghide"]="steghide"
    ["stegseek"]="stegseek"
    ["zsteg"]="zsteg"
    ["pngcheck"]="pngcheck"
    ["tesseract"]="tesseract"
    ["zbarimg"]="zbarimg"
    ["hashid"]="hashid"
    ["john"]="john"
    ["hashcat"]="hashcat"
    ["fcrackzip"]="fcrackzip"
    ["tshark"]="tshark"
    ["tcpdump"]="tcpdump"
    ["nmap"]="nmap"
    ["masscan"]="masscan"
    ["curl"]="curl"
    ["whatweb"]="whatweb"
    ["wafw00f"]="wafw00f"
    ["sqlmap"]="sqlmap"
    ["nikto"]="nikto"
    ["gobuster"]="gobuster"
    ["ffuf"]="ffuf"
    ["nuclei"]="nuclei"
    ["wpscan"]="wpscan"
    ["hydra"]="hydra"
    ["medusa"]="medusa"
    ["gdb"]="gdb"
    ["radare2"]="r2"
    ["pwntools"]="python3 -c 'import pwn' 2>/dev/null"
    ["ROPgadget"]="ROPgadget"
    ["checksec"]="checksec"
    ["whois"]="whois"
    ["dig"]="dig"
    ["nslookup"]="nslookup"
    ["theHarvester"]="theHarvester"
    ["subfinder"]="subfinder"
    ["amass"]="amass"
    ["trufflehog"]="trufflehog"
    ["gitleaks"]="gitleaks"
    ["clamscan"]="clamscan"
    ["trivy"]="trivy"
    ["shodan"]="shodan"
    ["RsaCtfTool"]="RsaCtfTool.py"
    ["jwt_tool"]="jwt_tool"
    ["crunch"]="crunch"
)

INSTALLED=0
MISSING=0
echo ""
for DISPLAY_NAME in "${!TOOLS[@]}"; do
    BIN="${TOOLS[$DISPLAY_NAME]}"
    if command -v $BIN &>/dev/null 2>&1 || eval "$BIN" &>/dev/null 2>&1; then
        printf "  ${GREEN}✓${NC} %-20s\n" "$DISPLAY_NAME"
        ((INSTALLED++))
    else
        printf "  ${RED}✗${NC} %-20s ${YELLOW}(missing)${NC}\n" "$DISPLAY_NAME"
        ((MISSING++))
    fi
done

TOTAL=$((INSTALLED + MISSING))
PCT=$(( INSTALLED * 100 / TOTAL ))

echo ""
echo -e "${CYAN}══════════════════════════════════${NC}"
echo -e "${GREEN}  HASIL INSTALASI: ${INSTALLED}/${TOTAL} Tools (${PCT}% Ready)${NC}"
echo -e "${CYAN}══════════════════════════════════${NC}"

if [ "$MISSING" -gt 0 ]; then
    echo -e "${YELLOW}  [!] ${MISSING} tools belum terpasang. Bot tetap berjalan dengan Zero-Failure Fallback Mode.${NC}"
fi

echo -e "\n${GREEN}  ✓ Instalasi selesai! Restart bot dengan:${NC}"
echo -e "    ${CYAN}source venv/bin/activate && python3 scripts/kiibot_telegram_bot.py${NC}"
echo -e "    ${CYAN}# atau: sudo systemctl restart kiibot${NC}\n"
