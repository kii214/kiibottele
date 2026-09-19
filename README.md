# KIIBOT — Intelligent Local CTF & Cybersecurity Operations Toolkit

```
 ██╗  ██╗ ██╗ ██╗ ██████╗  ██████╗ ████████╗
 ██║ ██╔╝ ██║ ██║ ██╔══██╗ ██╔═══██╗╚══██╔══╝
 █████╔╝  ██║ ██║ ██████╔╝ ██║   ██║   ██║   
 ██╔═██╗  ██║ ██║ ██╔══██╗ ██║   ██║   ██║   
 ██║  ██╗ ██║ ██║ ██████╔╝ ╚██████╔╝   ██║   
 ╚═╝  ╚═╝ ╚═╝ ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   
```

**KIIBOT** is an open-source, local-first cybersecurity workstation and CTF assistant designed for authorized security competitions, educational laboratories, digital forensics, incident response, reverse engineering, and defensive research.

---

## ⚠️ Authorized Use & Ethical Disclaimer

KIIBOT is built **strictly for authorized security research, CTF competitions, educational environments, and defensive operations**.

- Do **NOT** use KIIBOT against unauthorized targets, networks, or systems.
- Default security guardrails restrict active scanning/probing to authorized targets (e.g. `localhost`, `127.0.0.1`).
- Targets must be explicitly added to `~/.kiibot/config.yaml` or via `kiibot config targets add <target>`.
- Read [SECURITY.md](SECURITY.md) for detailed policies and guardrails.

---

## 🚀 Features

- **26 Interactive Modules & CLI Subcommands**: Cover Web, Cryptography, Forensics, Reverse Engineering, Binary Exploitation (PWN), Network Analysis, OSINT, Steganography, Log Analysis, Blue Team defense, and Malware Lab.
- **Smart System Diagnostics (`kiibot doctor`)**: Categorizes and verifies 120+ standard cybersecurity tools across apt and pip, with one-click fix suggestions.
- **Standardized Challenge Workspaces (`kiibot workspace`)**: Auto-creates organized challenge folders (`input/`, `evidence/`, `output/`, `extracted/`, `screenshots/`, `notes.md`, `commands.log`, `findings.md`, `report.md`).
- **Comprehensive Tool Registry (`kiibot tools`)**: Integrated database of 120+ tools with metadata, risk levels, and installation guidance.
- **Safe Subprocess Execution**: Strict argument arrays, timeouts, and authorization controls prevent shell injection and uncontrolled execution.
- **Async SQLite Backend**: Stores challenges, flags, findings, and evidence locally without storing plaintext credentials.

---

## 📦 Quick Start

### Prerequisites
- Python 3.11+
- Linux (Kali Linux, Debian, Ubuntu, WSL2) or macOS / Windows

### Installation (Linux / Kali / WSL2)

```bash
git clone https://github.com/kiibot/kiibot.git
cd kiibot
chmod +x install.sh
./install.sh
```

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Run diagnostics
kiibot doctor
```

---

## 🛠️ Basic Usage

```bash
# Launch interactive menu
kiibot

# Run system diagnostics
kiibot doctor --verbose

# Create a new challenge workspace
kiibot new web my-target-chall
# or
kiibot workspace new crypto rsa-leak

# List installed & missing tools
kiibot tools list
kiibot tools list --category web
kiibot tools info nmap

# Manage configuration & authorized targets
kiibot config show
kiibot config targets add 10.10.10.100
```

---

## 📁 Directory Structure

```
~/.kiibot/
├── config/
│   └── config.yaml          # User settings & authorized target allowlist
├── logs/
│   └── kiibot.log           # Structured JSON application logs
├── challenges/              # Challenge workspaces
├── workspaces/              # Active working data
└── kiibot.db                # SQLite database (findings, flags, history)
```

---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
