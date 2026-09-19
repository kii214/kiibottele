"""KIIBOT core constants, paths, and enumerations."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path

# ── App Identity ──────────────────────────────────────────────────────────────
APP_NAME = "KIIBOT"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Intelligent Local CTF & Cybersecurity Operations Toolkit"
APP_BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║                     K I I B O T                          ║
║                                                          ║
║        Intelligent Local CTF Security Workstation        ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""

# ── Paths ─────────────────────────────────────────────────────────────────────
HOME_DIR = Path.home()
KIIBOT_DIR = Path(os.environ.get("KIIBOT_HOME", HOME_DIR / ".kiibot"))
CONFIG_DIR = KIIBOT_DIR / "config"
DB_PATH = KIIBOT_DIR / "kiibot.db"
LOG_DIR = KIIBOT_DIR / "logs"
WORKSPACE_DIR = KIIBOT_DIR / "workspaces"
CHALLENGES_DIR = KIIBOT_DIR / "challenges"
CACHE_DIR = KIIBOT_DIR / "cache"
TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "templates"
CONFIGS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "configs"
CHEATSHEETS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "cheatsheets"

# CTF Attack & Defense
CTF_REPORTS_DIR = KIIBOT_DIR / "reports"

# User config file
USER_CONFIG_PATH = CONFIG_DIR / "config.yaml"

# Default authorized targets
DEFAULT_AUTHORIZED_TARGETS = [
    "127.0.0.1",
    "localhost",
    "::1",
]


# ── Enumerations ──────────────────────────────────────────────────────────────
class Category(str, Enum):
    """Challenge/analysis categories."""
    WEB = "web"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    PWN = "pwn"
    REVERSE = "reverse"
    STEGO = "stego"
    NETWORK = "network"
    OSINT = "osint"
    MISC = "misc"
    MOBILE = "mobile"
    BLUE_TEAM = "blue_team"
    RED_TEAM = "red_team"
    MALWARE = "malware"
    LOG_ANALYSIS = "log_analysis"
    PCAP = "pcap"
    HARDWARE = "hardware"


class RiskLevel(str, Enum):
    """Tool risk levels."""
    SAFE = "safe"          # Read-only, local analysis
    LOW = "low"            # Local modifications, file extraction
    MEDIUM = "medium"      # Network requests to authorized targets
    HIGH = "high"          # Active scanning, exploitation attempts
    CRITICAL = "critical"  # Destructive or invasive operations


class ToolStatus(str, Enum):
    """Tool availability status."""
    INSTALLED = "installed"
    MISSING = "missing"
    BROKEN = "broken"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Menu Items ────────────────────────────────────────────────────────────────
MAIN_MENU_ITEMS = [
    ("01", "Solve Challenge", "solve"),
    ("02", "Analyze File", "analyze"),
    ("03", "Analyze Image", "image"),
    ("04", "Analyze PCAP", "pcap"),
    ("05", "Analyze Web Target", "web"),
    ("06", "Analyze Binary", "rev"),
    ("07", "Analyze Logs", "log"),
    ("08", "Analyze Hash", "hash"),
    ("09", "Crypto Analysis", "crypto"),
    ("10", "Steganography", "steg"),
    ("11", "Reverse Engineering", "rev"),
    ("12", "Pwn / Binary", "pwn"),
    ("13", "Network", "network"),
    ("14", "OSINT", "osint"),
    ("15", "Forensics", "forensics"),
    ("16", "Blue Team", "blue"),
    ("17", "Red Team Lab", "redlab"),
    ("18", "Malware Lab", "malware"),
    ("19", "Tool Manager", "tools"),
    ("20", "Tool Doctor", "doctor"),
    ("21", "Workspace", "workspace"),
    ("22", "Cheatsheets", "cheat"),
    ("23", "Training Lab", "training"),
    ("24", "Reports", "report"),
    ("25", "Configuration", "config"),
    ("26", "Update", "update"),
    ("27", "CTF Attack & Defense [Kucing Oyenn]", "ctf"),
    ("00", "Exit", "exit"),
]
