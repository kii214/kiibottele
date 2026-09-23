#!/usr/bin/env bash
# ==============================================================================
# KIIBOT — Complete External Tools Installer
# Targets: Ubuntu 22.04 / Debian 12 / Kali Linux / WSL2
# Dioptimalkan untuk Ubuntu VPS
# ==============================================================================

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}   KIIBOT — CTF Competitions Ultimate Tool Suite Installer      ${NC}"
echo -e "${CYAN}   Target OS: Ubuntu 22.04 / Debian 12 / Kali Linux             ${NC}"
echo -e "${CYAN}================================================================${NC}"

# Check for root / sudo
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# Deteksi OS
OS_ID=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "unknown")
OS_VER=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "unknown")
echo -e "${CYAN}[*] Detected OS: ${OS_ID} ${OS_VER}${NC}"

echo -e "\n${YELLOW}[+] Step 1: Updating system packages...${NC}"
$SUDO apt-get update -y

# Aktifkan universe & multiverse repo di Ubuntu
if [[ "$OS_ID" == "ubuntu" ]]; then
    echo -e "${YELLOW}[*] Enabling Ubuntu universe & multiverse repositories...${NC}"
    $SUDO add-apt-repository universe -y 2>/dev/null || true
    $SUDO add-apt-repository multiverse -y 2>/dev/null || true
    $SUDO apt-get update -y
fi

echo -e "\n${YELLOW}[+] Step 2: Installing Core System Packages (Ubuntu & Kali compatible)...${NC}"
$SUDO apt-get install -y \
  binutils \
  binwalk \
  build-essential \
  bulk-extractor \
  checksec \
  clang \
  curl \
  dirb \
  dnsutils \
  exiftool \
  ffmpeg \
  file \
  foremost \
  gdb \
  git \
  hashcat \
  hydra \
  john \
  jq \
  libssl-dev \
  libffi-dev \
  ltrace \
  masscan \
  medusa \
  nasm \
  ncat \
  netcat-openbsd \
  net-tools \
  nmap \
  openssl \
  patchelf \
  pngcheck \
  procps \
  python3-pip \
  python3-dev \
  python3-venv \
  radare2 \
  rsync \
  sleuthkit \
  smbclient \
  socat \
  sqlmap \
  steghide \
  stegsnow \
  strace \
  tcpdump \
  tcpflow \
  tcpreplay \
  tesseract-ocr \
  tshark \
  traceroute \
  unrar \
  unzip \
  upx-ucl \
  wget \
  whatweb \
  whois \
  wkhtmltopdf \
  wireshark-common \
  xxd \
  yara \
  zbar-tools \
  aircrack-ng \
  crunch \
  nikto \
  || true

echo -e "\n${YELLOW}[+] Step 3: Installing optional Kali-specific tools (graceful skip jika tidak tersedia)...${NC}"
OPTIONAL_TOOLS=(
  apktool
  dnsrecon
  dsniff
  ettercap-text-only
  feh
  feroxbuster
  ffuf
  gobuster
  httpx-toolkit
  jadx
  nuclei
  pdf-parser
  pwndbg
  sublist3r
  wafw00f
  wfuzz
  whatweb
  zeek
  zsteg
)

for tool in "${OPTIONAL_TOOLS[@]}"; do
    if $SUDO apt-get install -y "$tool" 2>/dev/null; then
        echo -e "${GREEN}  [+] $tool installed${NC}"
    else
        echo -e "${YELLOW}  [~] $tool tidak tersedia di repo ini, skip${NC}"
    fi
done

echo -e "\n${YELLOW}[+] Step 4: Installing CTF Python & Reversing Modules (PIP)...${NC}"
python3 -m pip install --break-system-packages --quiet \
  angr \
  capstone \
  cryptography \
  factordb-pycli \
  hashid \
  keystone-engine \
  openai \
  pillow \
  pycryptodome \
  pwntools \
  pyjwt \
  python-magic \
  python-telegram-bot \
  requests \
  ropgadget \
  ropper \
  scapy \
  volatility3 \
  z3-solver \
  aiosqlite \
  pydantic \
  rich \
  click \
  pyyaml \
  markdown \
  pdfkit \
  prompt_toolkit \
  python-dotenv \
  wafw00f \
  wapiti3 \
  || true

echo -e "\n${YELLOW}[+] Step 5: Installing gobuster (langsung dari GitHub release)...${NC}"
if ! command -v gobuster &>/dev/null; then
    GOBUSTER_VER="3.6.0"
    wget -q "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VER}/gobuster_Linux_amd64.tar.gz" \
        -O /tmp/gobuster.tar.gz && \
    tar -xzf /tmp/gobuster.tar.gz -C /tmp && \
    $SUDO mv /tmp/gobuster /usr/local/bin/gobuster && \
    $SUDO chmod +x /usr/local/bin/gobuster && \
    rm -f /tmp/gobuster.tar.gz && \
    echo -e "${GREEN}  [+] gobuster installed${NC}" || \
    echo -e "${YELLOW}  [~] gobuster gagal diinstall, skip${NC}"
fi

echo -e "\n${YELLOW}[+] Step 6: Installing ffuf (langsung dari GitHub release)...${NC}"
if ! command -v ffuf &>/dev/null; then
    wget -q "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz" \
        -O /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /tmp && \
    $SUDO mv /tmp/ffuf /usr/local/bin/ffuf && \
    $SUDO chmod +x /usr/local/bin/ffuf && \
    rm -f /tmp/ffuf.tar.gz && \
    echo -e "${GREEN}  [+] ffuf installed${NC}" || \
    echo -e "${YELLOW}  [~] ffuf gagal diinstall, skip${NC}"
fi

echo -e "\n${YELLOW}[+] Step 7: Installing StegSeek...${NC}"
if ! command -v stegseek &>/dev/null; then
    STEGSEEK_URL="https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb"
    wget -q "$STEGSEEK_URL" -O /tmp/stegseek.deb && \
    $SUDO dpkg -i /tmp/stegseek.deb && \
    rm -f /tmp/stegseek.deb && \
    echo -e "${GREEN}  [+] stegseek installed${NC}" || \
    echo -e "${YELLOW}  [~] stegseek gagal diinstall, skip${NC}"
fi

echo -e "\n${YELLOW}[+] Step 8: Setup Wordlists (rockyou.txt + CTF mini-wordlist)...${NC}"
$SUDO mkdir -p /usr/share/wordlists
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "[*] Uncompressing rockyou.txt..."
    $SUDO gzip -d -k /usr/share/wordlists/rockyou.txt.gz || true
fi
if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "[*] Downloading rockyou.txt..."
    $SUDO wget -q "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
        -O /usr/share/wordlists/rockyou.txt || true
fi

# CTF Mini-Wordlist — Top ~250 password paling sering muncul di lomba CTF
# Jauh lebih cepat dari rockyou.txt (14 juta baris) untuk login brute-force CTF
if [ ! -f /usr/share/wordlists/ctf_mini.txt ]; then
    echo "[*] Membuat CTF mini-wordlist (250 password CTF umum)..."
    $SUDO tee /usr/share/wordlists/ctf_mini.txt > /dev/null << 'WORDLIST_EOF'
admin
password
123456
password123
admin123
root
toor
flag
ctf
hackthebox
picoctf
tryh4ckm3
letmein
welcome
qwerty
abc123
master
secret
guest
test
user
login
1234
12345
123456789
000000
password1
admin1
superuser
sysadmin
operator
hacker
kali
linux
ubuntu
debian
parrot
pentester
exploit
payload
vulnerable
challenge
solution
competition
ctfchallenge
flag{test}
FLAG
1qaz2wsx
zxcvbnm
qwertyuiop
asdfghjkl
zxcvbn
qazwsx
1q2w3e
1q2w3e4r
password@123
P@ssword
P@ssw0rd
Admin@123
Admin123!
Welcome1
Welcome123
change_me
changeme
default
blank
null
undefined
true
false
none
demo
sample
example
test123
dev
developer
staging
production
prod
stage
backup
db
database
dbpass
dbpassword
mysql
postgres
postgresql
mongodb
redis
elastic
kibana
logstash
solr
hadoop
spark
oracle
root123
toor123
super
SuperUser
administrator
Administrator
Password
Password123
Secret
Secret123
Hidden
hidden
found
answer
solvethis
findme
crackme
hashme
decryptme
decodeme
binary
hex
base64
rot13
xor
aes
rsa
md5
sha1
sha256
jwt
token
apikey
api_key
api-key
secret_key
secret-key
private_key
public_key
encryption
decryption
cipher
plaintext
watermark
steganography
metadata
exif
flag_is_here
youfoundit
welldonehacker
congrats
bravo
nicework
well_done
goodwork
1337
l33t
h4x0r
h4cker
w00t
p4ssw0rd
p@55w0rd
4dm1n
r00t
WORDLIST_EOF
    echo -e "${GREEN}  [+] CTF mini-wordlist dibuat: /usr/share/wordlists/ctf_mini.txt${NC}"
fi

echo -e "\n${YELLOW}[+] Step 9: Configure tshark (izinkan capture tanpa root)...${NC}"
echo "wireshark-common wireshark-common/install-setuid boolean true" | $SUDO debconf-set-selections 2>/dev/null || true
$SUDO dpkg-reconfigure -f noninteractive wireshark-common 2>/dev/null || true
$SUDO usermod -aG wireshark "$USER" 2>/dev/null || true

echo -e "\n${YELLOW}[+] Step 10: Installing Go tools (jika Go tersedia)...${NC}"
if command -v go &>/dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true
    echo -e "${GREEN}  [+] Go tools installed${NC}"
else
    echo -e "${YELLOW}  [~] Go tidak ditemukan, Go tools dilewati${NC}"
fi

echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}  [✓] KIIBOT Tool Suite Installation Selesai!                  ${NC}"
echo -e "${GREEN}  Jalankan '/doctor' di Telegram untuk verifikasi tools.        ${NC}"
echo -e "${GREEN}================================================================${NC}"
