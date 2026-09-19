<#
.SYNOPSIS
    KIIBOT Windows CTF Environment & Tools Installer
.DESCRIPTION
    Installs Python CTF modules and native Windows binaries (via winget/choco),
    or configures WSL2 Kali Linux for the ultimate CTF experience.
#>

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   KIIBOT — Windows CTF Tools & Environment Installer           " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Pip CTF Tools for Python 3.11+
Write-Host "`n[+] Installing CTF Python Modules via pip..." -ForegroundColor Yellow
py -3.11 -m pip install --upgrade pip setuptools wheel
py -3.11 -m pip install --upgrade `
    cryptography `
    pycryptodome `
    hashid `
    requests `
    pillow `
    pyjwt `
    factordb-pycli `
    z3-solver `
    scapy `
    ropper

# 2. Check for winget tools
if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "`n[+] Installing Windows native tools via Winget..." -ForegroundColor Yellow
    winget install --id WiresharkFoundation.Wireshark -e --silent --accept-source-agreements --accept-package-agreements
    winget install --id Insecure.Nmap -e --silent --accept-source-agreements --accept-package-agreements
    winget install --id Git.Git -e --silent --accept-source-agreements --accept-package-agreements
    winget install --id 7zip.7zip -e --silent --accept-source-agreements --accept-package-agreements
}

# 3. WSL2 Recommendation
Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host " [INFO] NOTE FOR PWN / REVERSE / FORENSICS IN CTF LOMBA:" -ForegroundColor Green
Write-Host " Many CTF tools (gdb, pwndbg, checksec, radare2, binwalk, zsteg)" -ForegroundColor White
Write-Host " are Linux-native. For 100% full power in CTF competitions:" -ForegroundColor White
Write-Host " 1. Install WSL2 Kali: wsl --install -d kali-linux" -ForegroundColor Yellow
Write-Host " 2. Inside WSL2, run: ./scripts/install_all_tools.sh" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Cyan
