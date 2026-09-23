"""
KIIBOT Telegram Bot — Enhanced Cyber SOC & CTF Assistant
Dilengkapi Context Guardrail (Hanya merespon topik CTF & SOC),
Rich HTML UI Formatting, Interactive Buttons, dan Integrasi MITRE ATT&CK.
"""

import asyncio
import html
import logging
import os
import re
import sys

# Auto-load .env dari root project (agar TELEGRAM_BOT_TOKEN dll terbaca)
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    load_dotenv(dotenv_path=_env_path)
except ImportError:
    pass  # python-dotenv tidak wajib jika env sudah di-set manual / systemd

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# Tambahkan src/ ke sys.path agar impor kiibot berjalan lancar
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from kiibot.analysis.decoders import decode_all
from kiibot.analysis.log_analyzer import DeepLogAnalyzer
from kiibot.analysis.mitre_attack import get_all_techniques, lookup_mitre
from kiibot.analysis.pcap_analyzer import ProfessionalPCAPAnalyzer
from kiibot.core.ai_orchestrator import AIOrchestrator
from kiibot.core.executor import check_all_tools_availability, execute_concurrent_tools
from kiibot.core.tool_registry import TOOL_REGISTRY

# Setup Logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("kiibot_bot")

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "GANTI_DENGAN_TOKEN_ANDA")
ALLOWED_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "GANTI_DENGAN_CHAT_ID_ANDA")


def check_auth(update: Update) -> bool:
    """Keamanan: Pastikan pesan berasal dari chat ID yang diizinkan (jika diset)."""
    if not update.effective_chat:
        return False
    chat_id = str(update.effective_chat.id)
    if ALLOWED_CHAT_ID != "GANTI_DENGAN_CHAT_ID_ANDA" and chat_id != ALLOWED_CHAT_ID:
        logger.warning(f"[SECURITY] Akses ditolak dari unauthorized Chat ID: {chat_id}")
        return False
    return True


# =====================================================================
# CONTEXT GUARDRAIL: PEMBATAS KONTEKS CTF & SOC
# Aturan: Hanya proses pesan yang relevan. Di luar konteks JANGAN DIBALAS.
# =====================================================================

CYBER_KEYWORDS = [
    # CTF & Security General
    "ctf", "flag", "kiibot", "exploit", "vulnerability", "vuln", "cve", "pwn",
    "reverse", "reversing", "forensic", "forensik", "stego", "steganography",
    "payload", "shell", "rce", "sqli", "xss", "csrf", "ssrf", "lfi", "rfi",
    "malware", "ransomware", "trojan", "backdoor", "rootkit", "sandbox",

    # SOC & Blue Team
    "soc", "siem", "triage", "incident", "alert", "log", "logs", "wazuh", "splunk",
    "elk", "elastic", "suricata", "snort", "firewall", "waf", "ids", "ips", "edr",
    "mitre", "attack", "technique", "tactic", "threat", "actor", "apc", "apt",
    "containment", "mitigasi", "mitigation", "severity", "critical", "escalation",
    "pcap", "wireshark", "tshark", "tcpdump", "traffic", "packet", "beaconing",
    "brute", "bruteforce", "login", "auth", "authentikasi", "access",

    # Kriptografi & Decoding
    "hash", "md5", "sha1", "sha256", "sha512", "base64", "hex", "rot13", "caesar",
    "cipher", "crypto", "kripto", "rsa", "aes", "des", "xor", "jwt", "token",
    "decode", "encode", "decrypt", "encrypt", "password", "wordlist", "rockyou",

    # Binaries & Reversing
    "elf", "binary", "executable", "pe", "checksec", "ghidra", "ida", "gdb",
    "radare2", "rop", "buffer overflow", "assembly", "disassembly", "opcode",

    # OSINT & Recon
    "osint", "whois", "dns", "subdomain", "nmap", "gobuster", "dirbuster",
    "nikto", "trufflehog", "gitleaks", "credential", "leak", "github",

    # Web Attack & CTF
    "http", "https", "url", "domain", "website", "web", "sqlmap", "hydra",
    "ffuf", "dirb", "whatweb", "wafw00f", "scan", "fuzz", "inject", "injection",
    "username", "passwd", "creds", "credentials", "admin", "login page",
    "webattack", "web attack", "cek web", "cek url", "analisis web",
    "cari password", "cari user", "bypass", "bypass login"
]

def is_cyber_soc_context(text: str) -> bool:
    """
    Evaluasi ketat: Apakah teks berkaitan dengan CTF, SOC, atau Keamanan Siber?
    Jika bernilai False, bot TIDAK AKAN MEMBALAS pesan tersebut.
    """
    if not text:
        return False
    
    cleaned = text.strip().lower()
    
    # 1. Cek Pola Flag Format
    if re.search(r"(ctf|kiibot|flag|picoctf|hackthebox|thm)\{.*?\}", cleaned, re.IGNORECASE):
        return True
    
    # 2. Cek Pola Hash / Cipher / Encoding Khas
    # MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", text.strip()):
        return True
    
    # Base64 string panjang yang valid
    if len(text.strip()) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", text.strip()):
        return True
    
    # 3. Cek Pola Teknis: IP Address, CVE, MITRE ID, Log Line
    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
        return True
    if re.search(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE):
        return True
    if re.search(r"\bT\d{4}(\.\d{3})?\b", text, re.IGNORECASE):
        return True
    if re.search(r"(GET|POST|PUT|DELETE)\s+\/[a-zA-Z0-9_\-\.\/]*\s+HTTP\/", text):
        return True
    if re.search(r"(\bor\b|\band\b)\s+['\"0-9a-zA-Z]+\s*=\s*['\"0-9a-zA-Z]+", cleaned):
        return True
    
    # 4. Cek Keyword Relevansi Cyber / CTF / SOC
    for kw in CYBER_KEYWORDS:
        # Gunakan word boundary atau substring fleksibel
        if kw in cleaned:
            return True
            
    return False


# =====================================================================
# UI HELPERS & KEYBOARDS
# =====================================================================

def get_main_keyboard() -> InlineKeyboardMarkup:
    """Membuat menu utama interaktif bernomor untuk mode operasi KIIBOT."""
    keyboard = [
        [
            InlineKeyboardButton("📂 1. Analisis File CTF", callback_data="menu_file"),
            InlineKeyboardButton("⚔️ 2. Web Attack CTF", callback_data="menu_webattack"),
        ],
        [
            InlineKeyboardButton("🔓 3. Decode & Crypto", callback_data="menu_decode"),
            InlineKeyboardButton("🛡️ 4. SOC Triage & Alert", callback_data="menu_soc"),
        ],
        [
            InlineKeyboardButton("📝 5. Laporan Word (.docx)", callback_data="gen_report_docx_1"),
            InlineKeyboardButton("📄 6. Laporan PDF", callback_data="gen_report_pdf_1"),
        ],
        [
            InlineKeyboardButton("🩺 7. VPS Doctor", callback_data="btn_doctor"),
            InlineKeyboardButton("🔑 8. Status AI Keys", callback_data="btn_aikeys"),
        ],
        [
            InlineKeyboardButton("📚 MITRE ATT&CK", callback_data="btn_mitre_list"),
            InlineKeyboardButton("🛠️ Tools Registry", callback_data="btn_tools"),
        ],
        [
            InlineKeyboardButton("💡 Panduan & Command", callback_data="btn_help"),
        ]
    ]
    return InlineKeyboardMarkup(keyboard)


def get_webattack_keyboard(target_url: str) -> InlineKeyboardMarkup:
    """Sub-menu pilihan mode Web Attack CTF."""
    keyboard = [
        [
            InlineKeyboardButton("🎯 1. Tech Fingerprint", callback_data="wa_fingerprint"),
            InlineKeyboardButton("💉 2. SQL Injection", callback_data="wa_sqli"),
        ],
        [
            InlineKeyboardButton("📂 3. Dir Enumeration", callback_data="wa_dir"),
            InlineKeyboardButton("🔐 4. Login Brute-force", callback_data="wa_bruteforce"),
        ],
        [
            InlineKeyboardButton("🛡️ 5. Vuln Scanner", callback_data="wa_vulnscan"),
            InlineKeyboardButton("🌐 6. OSINT Domain", callback_data="wa_osint"),
        ],
        [
            InlineKeyboardButton("🔥 ALL-IN-ONE ATTACK BATTERY", callback_data="wa_all"),
        ],
        [
            InlineKeyboardButton("🔙 Kembali ke Menu Utama", callback_data="menu_main"),
        ]
    ]
    return InlineKeyboardMarkup(keyboard)


# =====================================================================
# COMMAND HANDLERS
# =====================================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Menampilkan sambutan eksklusif bergaya SOC Cyber Command Center."""
    if not check_auth(update) or not update.message:
        return

    welcome_text = (
        "<b>⚡ KIIBOT CYBER COMMAND CENTER</b>\n"
        "<code>ENGINE: ACTIVE | SYSTEM: OPTIMAL | VPS: ONLINE</code>\n"
        "───────────────────────────────\n\n"
        "Selamat datang, Operator. KIIBOT adalah asisten intelijen cyber ops "
        "yang dilengkapi <b>40+ Tools Otomatis</b>, <b>AI Vision Inspection</b>, "
        "serta <b>Engine Laporan SOC Professional</b>.\n\n"
        "<b>📌 PILIH FITUR OPERASIONAL:</b>\n"
        "• <b>1. Analisis File CTF</b> — Kirim berkas `.pcap`, `.elf`, `.log`, `.png`, `.zip`\n"
        "• <b>2. Web Attack CTF</b> — <code>/webattack &lt;url&gt;</code> (SQLi, Dir Enum, Brute, Scan)\n"
        "• <b>3. Decode & Crypto</b> — <code>/decode &lt;text&gt;</code> (Multi-stage auto-decode)\n"
        "• <b>4. SOC Triage</b> — <code>/triage</code> (Simulator prioritas alert insiden)\n"
        "• <b>5. Laporan Word SOC</b> — <code>/reportsoc</code> (Export `.docx` & `.pdf` resmi)\n"
        "• <b>6. VPS Doctor</b> — <code>/doctor</code> (Diagnosa kelengkapan tools di VPS)\n\n"
        "<i>💡 Petunjuk: Langsung upload berkas ke chat untuk analisis otomatis!</i>"
    )
    await update.message.reply_text(
        welcome_text,
        parse_mode="HTML",
        reply_markup=get_main_keyboard()
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Menampilkan panduan command KIIBOT lengkap."""
    if not check_auth(update) or not update.message:
        return

    help_text = (
        "<b>[ KIIBOT COMMAND REFERENCE ]</b>\n\n"
        "<b>» Navigasi & SOC Operations</b>\n"
        "  <code>/start</code>  : Menampilkan menu utama & status\n"
        "  <code>/help</code>   : Daftar referensi perintah ini\n"
        "  <code>/soc</code>    : Panduan 4 tahap alur kerja SOC Analyst\n"
        "  <code>/triage</code> : Simulator insiden alert & penentuan prioritas\n"
        "  <code>/tools</code>  : Ringkasan 40+ CTF & SOC tools yang terpasang\n"
        "  <code>/doctor</code> : Diagnosa tools VPS (cek yang terinstall vs missing)\n"
        "  <code>/aikeys</code> : Cek status cascading Multi-API Keys Pool\n\n"
        "<b>» Investigasi & Auto-Solve</b>\n"
        "  <code>/mitre [ID]</code>  : Detail teknik MITRE (contoh: <code>/mitre T1140</code>)\n"
        "  <code>/decode [txt]</code>: Analisis instan cipher/hash/JWT/encoding\n"
        "  <code>/analyze [..]</code>: Deep analysis AI expert bertubi-tubi\n\n"
        "<b>» Analisis Berkas Langsung</b>\n"
        "Kirim dokumen langsung ke bot (<code>.pcap</code>, <code>.png</code>, <code>.elf</code>, <code>.log</code>).\n"
        "Bot akan otomatis mengorkestrasi tools secara paralel.\n\n"
        "<i>Catatan: Bot dilindungi guardrail aktif. Pesan di luar konteks siber akan diabaikan.</i>"
    )
    await update.message.reply_text(
        help_text,
        parse_mode="HTML",
        reply_markup=get_main_keyboard()
    )


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate dan kirim laporan CTF dalam format PDF."""
    if not check_auth(update) or not update.message:
        return

    from kiibot.ctf.report_generator import CTFReportGenerator
    from kiibot.ctf.session_manager import CTFSessionManager
    
    status_msg = await update.message.reply_text(
        "📄 <i>Sedang mengumpulkan data session dan menyusun laporan PDF...</i>",
        parse_mode="HTML"
    )

    try:
        sm = CTFSessionManager()
        sess = sm.get_active_session()
        
        # Jika tidak ada session aktif, coba ambil session terbaru yang sudah selesai
        if not sess:
            sessions = sm.list_sessions()
            if not sessions:
                await status_msg.edit_text("❌ <b>Tidak ada data session CTF yang ditemukan.</b>", parse_mode="HTML")
                return
            sess = sessions[0]
            await status_msg.edit_text(
                f"⚠️ <i>Tidak ada session aktif. Menggunakan session terbaru (SESSION-{sess.id:03d}). Menyusun laporan PDF...</i>",
                parse_mode="HTML"
            )

        rg = CTFReportGenerator()
        pdf_path = rg.generate_pdf(sess.id)
        
        await status_msg.edit_text("✅ <b>Laporan PDF berhasil dibuat! Mengirim dokumen...</b>", parse_mode="HTML")
        
        # Kirim dokumen PDF
        with open(pdf_path, 'rb') as doc:
            await update.message.reply_document(
                document=doc,
                filename=os.path.basename(pdf_path),
                caption=f"Laporan CTF Attack & Defense - SESSION-{sess.id:03d}\nKompetisi: {sess.competition or 'N/A'}"
            )
            
    except Exception as e:
        logger.error(f"Error pada /report: {e}")
        await status_msg.edit_text(f"❌ <b>Error saat generate laporan:</b> <code>{html.escape(str(e))}</code>", parse_mode="HTML")


async def doctor_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Diagnosa kesiapan seluruh tools di VPS."""
    if not check_auth(update) or not update.message:
        return

    status_msg = await update.message.reply_text(
        "🩺 <i>Memeriksa ketersediaan seluruh tools di lingkungan host/VPS...</i>",
        parse_mode="HTML"
    )

    try:
        # check_all_tools_availability adalah fungsi sync (bukan async)
        report = await asyncio.get_event_loop().run_in_executor(None, check_all_tools_availability)
        installed_count = report["installed_count"]
        missing_count = report["missing_count"]
        total = report["total_tools"]
        installed_pct = int((installed_count / total) * 100) if total > 0 else 0

        reply = (
            "<b>[ VPS DIAGNOSTICS REPORT ]</b>\n"
            f"<code>SYSTEM HEALTH: {installed_count}/{total} TOOLS ({installed_pct}% READY)</code>\n\n"
        )

        # Visual progress bar
        filled_blocks = int(installed_pct / 10)
        progress_bar = "█" * filled_blocks + "░" * (10 - filled_blocks)

        reply = (
            "<b>🩺 KIIBOT VPS DIAGNOSTICS</b>\n"
            f"<code>HEALTH: [{progress_bar}] {installed_pct}% ({installed_count}/{total} Tools)</code>\n"
            "───────────────────────────────\n\n"
        )

        # Kelompokkan berdasarkan kategori
        for cat, cat_data in report["categories"].items():
            cat_installed = cat_data["installed"]
            cat_missing = cat_data["missing"]
            cat_icon = "🟢" if not cat_missing else ("🟡" if cat_installed else "🔴")
            reply += f"<b>{cat_icon} KATEGORI: {cat.upper()}</b>\n"
            if cat_installed:
                reply += f"  ✓ <b>Installed:</b> <code>{', '.join(cat_installed[:8])}</code>\n"
            if cat_missing:
                reply += f"  ✗ <b>Missing:</b> <i>{', '.join(cat_missing[:6])}</i>\n"
            reply += "\n"

        if missing_count > 0:
            reply += "<i>💡 Untuk menginstall tools yang belum ada: <code>sudo bash scripts/install_all_tools.sh</code></i>"

        await status_msg.edit_text(reply, parse_mode="HTML")

    except Exception as e:
        logger.error(f"Error pada /doctor: {e}")
        await status_msg.edit_text(f"❌ Error saat menjalankan diagnosis: {e!s}")


async def aikeys_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Menampilkan status pool cascading multi-API key."""
    if not check_auth(update) or not update.message:
        return

    ai = AIOrchestrator()
    status = ai.get_status_info()
    total = status["total_keys"]
    active = status["active_key_index"]
    exhausted = status["exhausted_keys_count"]
    model = status["model"]
    avail = status["available"]

    badge = "ACTIVE & READY" if avail else "INACTIVE / QUOTA EXHAUSTED"

    reply = (
        "<b>[ AI MULTI-KEY POOL STATUS ]</b>\n"
        f"<code>STATUS: {badge}</code>\n\n"
        f"» <b>Model          :</b> {model}\n"
        f"» <b>Total API Keys :</b> {total} Keys\n"
        f"» <b>Active Key     :</b> Key #{active}\n"
        f"» <b>Exhausted Keys :</b> {exhausted} Keys\n"
        f"» <b>Remaining Keys :</b> {status['remaining_keys']} Keys\n\n"
        "<b>[ Cascading Failover Protocol ]</b>\n"
        "- KIIBOT selalu menggunakan Key pertama yang aktif.\n"
        "- Jika Key error (429/insufficient quota), sistem beralih otomatis ke Key berikutnya.\n"
        "- Maksimal 10 Keys didukung secara paralel.\n\n"
        "<i>Konfigurasi keys: <code>configs/ai_keys.json</code></i>"
    )
    await update.message.reply_text(reply, parse_mode="HTML")


async def soc_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Menampilkan ringkasan alur kerja SOC Analyst."""
    if not check_auth(update) or not update.message:
        return

    soc_text = (
        "<b>[ SOC ANALYST WORKFLOW ]</b>\n"
        "<i>Metodologi: CTF as a Gateway to SOC</i>\n\n"
        "<b>1. Triage & Assessment (L1):</b>\n"
        "Memilah alert berdasarkan severity (CRITICAL, HIGH, MEDIUM, LOW) untuk mencegah alert fatigue.\n\n"
        "<b>2. Root Cause Investigation (L2):</b>\n"
        "Menyisir raw logs, traffic PCAP, atau memory dump untuk menemukan payload & IoC penyerang.\n\n"
        "<b>3. Containment & Mitigation:</b>\n"
        "Melakukan isolasi ancaman (blokir IP, isolasi host, update WAF).\n\n"
        "<b>4. Hardening & Rule Update:</b>\n"
        "Membuat deteksi preventif baru di SIEM agar serangan tidak berulang."
    )
    await update.message.reply_text(soc_text, parse_mode="HTML")


async def triage_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Simulator Triage Alert SOC."""
    if not check_auth(update) or not update.message:
        return

    triage_text = (
        "<b>[ SOC ALERT TRIAGE SIMULATOR ]</b>\n"
        "Ditemukan 4 alert bersamaan pada SIEM Dashboard:\n\n"
        "[CRITICAL] Outbound Traffic Anomaly\n"
        "» Source : Database Server (Production)\n"
        "» Action : Prioritas Utama! Segera blokir koneksi keluar & isolasi DB.\n\n"
        "[HIGH] SQL Injection Payload\n"
        "» Source : Public Web Application\n"
        "» Action : Cek response status code di Nginx log; pastikan WAF memblokir payload.\n\n"
        "[MEDIUM] Multiple Failed Logins\n"
        "» Source : Workstation HRD\n"
        "» Action : Potensi brute-force. Monitor lockout policy.\n\n"
        "[LOW] Malware Dropper Quarantined\n"
        "» Source : Laptop Marketing\n"
        "» Action : Ancaman sudah tertahan (contained). Verifikasi status karantina.\n\n"
        "<i>SOP L2: Selesaikan investigasi status CRITICAL sebelum berpindah ke severity lebih rendah.</i>"
    )
    await update.message.reply_text(triage_text, parse_mode="HTML")


async def tools_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Menampilkan daftar 85+ tools KIIBOT PRO dengan SOP step labels."""
    if not check_auth(update) or not update.message:
        return

    total_tools = sum(len(v) for v in TOOL_REGISTRY.values())
    total_cats = len(TOOL_REGISTRY)

    tools_summary = (
        f"<b>[ 🛠️ KIIBOT PRO — TOOL REGISTRY ]</b>\n"
        f"<code>TOTAL: {total_tools} TOOLS | {total_cats} KATEGORI | MODE: PRO EXECUTION</code>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    )

    cat_icons = {
        "forensics": "🔬", "steganography": "🖼️", "cryptography": "🔐",
        "network": "🌐", "log_analysis": "📋", "web": "⚔️",
        "reverse_engineering": "⚙️", "osint": "🌍", "osint_github": "🐙",
        "soc_triage": "🛡️", "siem_integration": "📡", "malware_analysis": "🦠",
        "exploit_dev": "💣", "password_attacks": "🔑", "container_security": "📦",
    }

    for category, tools_dict in TOOL_REGISTRY.items():
        icon = cat_icons.get(category, "🔧")
        count = len(tools_dict)
        tool_names = ", ".join(list(tools_dict.keys())[:6])
        extras = f" +{count - 6} more" if count > 6 else ""
        first_tool = next(iter(tools_dict.values()), {})
        sop = first_tool.get("sop_step", "")
        sop_str = f"\n  <i>📌 {html.escape(sop)}</i>" if sop else ""
        cat_label = category.upper().replace('_', ' ')
        tools_summary += (
            f"{icon} <b>{html.escape(cat_label)} ({count} tools):</b>\n"
            f"  <code>{html.escape(tool_names)}{extras}</code>{sop_str}\n\n"
        )

    tools_summary += (
        "<i>💡 Gunakan <code>/findtool &lt;nama&gt;</code> untuk cek tool spesifik.\n"
        "   Gunakan <code>/insttools</code> untuk panduan install semua tools.</i>"
    )
    await update.message.reply_text(tools_summary, parse_mode="HTML")


async def insttools_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Panduan install semua 85+ tools di VPS."""
    if not check_auth(update) or not update.message:
        return

    msg = (
        "<b>[ 🚀 PANDUAN INSTALL 85+ TOOLS KIIBOT PRO ]</b>\n"
        "<code>Target: Ubuntu 22.04 / 24.04 LTS VPS</code>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "<b>STEP 1: Clone repo terbaru</b>\n"
        "<code>cd ~\ngit clone https://github.com/kii214/kiibottele.git\ncd kiibottele</code>\n\n"
        "<b>STEP 2: Jalankan installer otomatis (14 langkah)</b>\n"
        "<code>sudo bash scripts/install_all_tools.sh</code>\n\n"
        "<b>STEP 3: Aktifkan venv &amp; jalankan bot</b>\n"
        "<code>python3 -m venv venv\nsource venv/bin/activate\npip install -e .\n"
        "cp .env.example .env &amp;&amp; nano .env\npython3 scripts/kiibot_telegram_bot.py</code>\n\n"
        "<b>STEP 4: Verifikasi tools terpasang</b>\n"
        "<code>/doctor</code> — Cek status semua 85+ tools\n"
        "<code>/findtool nmap</code> — Cek tool spesifik\n\n"
        "<b>📦 15 Kategori Tools:</b>\n"
        "🔬 Forensics: exiftool, binwalk, volatility3, oletools, yara\n"
        "🖼️ Stego: steghide, stegseek, zsteg, outguess, tesseract\n"
        "🔐 Crypto: hashcat, john, RsaCtfTool, jwt_tool, fcrackzip\n"
        "🌐 Network: tshark, nmap, masscan, wireshark\n"
        "⚔️ Web: gobuster, ffuf, nuclei, wpscan, sqlmap, nikto, hydra, medusa\n"
        "⚙️ RE/Pwn: radare2, gdb, pwntools, ROPgadget, one_gadget, checksec\n"
        "🌍 OSINT: theHarvester, subfinder, amass, shodan\n"
        "🐙 Leaks: trufflehog, gitleaks\n"
        "🦠 Malware: clamav, yara, detect-it-easy\n"
        "📦 Container: trivy, docker inspect\n\n"
        "<i>Estimasi waktu install: 5-15 menit tergantung koneksi VPS.</i>"
    )
    await update.message.reply_text(msg, parse_mode="HTML")

async def findtool_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /findtool <nama_tool> — Pencarian & Diagnosa Pintar Ketersediaan Tools.
    Mengecek apakah tool ada di registry, PATH VPS, atau menyarankan paket installer.
    """
    if not check_auth(update) or not update.message:
        return

    if not context.args:
        await update.message.reply_text(
            "🔎 <b>Format Perintah:</b> <code>/findtool &lt;nama_tool&gt;</code>\n\n"
            "<i>Contoh:</i>\n"
            "• <code>/findtool nmap</code>\n"
            "• <code>/findtool gobuster</code>\n"
            "• <code>/findtool volatility3</code>",
            parse_mode="HTML"
        )
        return

    tool_query = context.args[0].lower().strip()
    import shutil
    bin_path = shutil.which(tool_query) or "Tidak ditemukan di PATH"
    is_in_path = shutil.which(tool_query) is not None

    found_in_reg = []
    for cat, tools in TOOL_REGISTRY.items():
        if tool_query in tools:
            found_in_reg.append(cat)

    status_icon = "🟢 TERSEDIA & SIAP" if is_in_path else "🔴 UNINSTALLED"

    res_text = (
        "<b>🔍 [ SMART TOOL DIAGNOSTICS & FINDER ]</b>\n"
        f"<code>QUERY: {html.escape(tool_query)} | STATUS: {status_icon}</code>\n"
        "───────────────────────────────\n\n"
        f"» <b>Nama Tool       :</b> <code>{html.escape(tool_query)}</code>\n"
        f"» <b>Lokasi Binary   :</b> <code>{html.escape(bin_path)}</code>\n"
        f"» <b>Registry Category:</b> <code>{', '.join(found_in_reg) or 'Extra Tool'}</code>\n\n"
    )

    if is_in_path:
        res_text += "✅ <b>Tool siap dieksekusi oleh KIIBOT Engine!</b>"
    else:
        res_text += (
            "⚠️ <b>Tool belum terpasang di VPS.</b>\n"
            f"<i>Cara pasang:</i> <code>sudo apt-get install -y {html.escape(tool_query)}</code>\n\n"
            "<i>💡 Note: Zero-Failure Engine KIIBOT akan otomatis menggunakan Fallback Mode jika tool ini dijalankan, sehingga eksekusi dijamin tidak crash.</i>"
        )

    await update.message.reply_text(res_text, parse_mode="HTML")


async def mitre_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Lookup teknik MITRE ATT&CK dari database knowledge base."""
    if not check_auth(update) or not update.message:
        return

    if not context.args:
        avail = ", ".join([f"<code>{t}</code>" for t in get_all_techniques()[:8]])
        usage_text = (
            "⚠️ <b>Format Perintah Salah!</b>\n\n"
            "Gunakan: <code>/mitre &lt;Technique_ID&gt;</code>\n"
            f"Contoh ID yang tersedia: {avail}, dll."
        )
        await update.message.reply_text(usage_text, parse_mode="HTML")
        return

    tech_id = context.args[0].upper().strip()
    data = lookup_mitre(tech_id)

    if not data:
        await update.message.reply_text(
            f"❌ <b>ID MITRE <code>{html.escape(tech_id)}</code> tidak ditemukan dalam database lokal.</b>\n"
            f"Gunakan ID umum seperti <code>T1140</code>, <code>T1059</code>, <code>T1027.003</code>, <code>T1190</code>.",
            parse_mode="HTML"
        )
        return

    reply = (
        f"┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
        f"┃  🎯 <b>MITRE ATT&CK: {html.escape(data['id'])}</b>\n"
        f"┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n"
        f"🏷️ <b>Nama:</b> <b>{html.escape(data['name'])}</b>\n"
        f"⚔️ <b>Tactic:</b> <code>{html.escape(data['tactic'])}</code>\n\n"
        f"📝 <b>Deskripsi:</b>\n{html.escape(data['desc'])}\n\n"
        f"🔍 <b>Deteksi SIEM:</b>\n<code>{html.escape(data['detection'])}</code>\n\n"
        f"🛡️ <b>Mitigasi SOC:</b>\n{html.escape(data['mitigation'])}\n\n"
        f"🧰 <b>Tools KIIBOT Terkait:</b>\n"
        f"{', '.join([f'<code>{t}</code>' for t in data['related_tools']])}"
    )
    await update.message.reply_text(reply, parse_mode="HTML")


async def decode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Melakukan auto-decode pada string ciphertext."""
    if not check_auth(update) or not update.message:
        return

    if not context.args:
        await update.message.reply_text(
            "⚠️ Gunakan format: <code>/decode &lt;teks_cipher_atau_hash&gt;</code>",
            parse_mode="HTML"
        )
        return

    text = " ".join(context.args)
    results = decode_all(text)

    if not results:
        await update.message.reply_text(
            f"❌ <b>Tidak ditemukan pola encoding/cipher yang dikenali untuk:</b>\n<code>{html.escape(text[:100])}</code>",
            parse_mode="HTML"
        )
        return

    reply = "<b>[ MULTI-STAGE DECODE RESULTS ]</b>\n\n"
    for res in results:
        rtype = html.escape(str(res.get("type", "Unknown")))
        rval = html.escape(str(res.get("result", "")))
        reply += f"🔹 <b>{rtype}:</b>\n<code>{rval}</code>\n\n"

    # Periksa apakah ada flag terdeteksi
    flag_match = re.search(r"(KIIBOT|CTF|FLAG|SOC)\{[^\}]+\}", reply, re.IGNORECASE)
    if flag_match:
        reply += f"\n<b>[ POTENSI FLAG DITEMUKAN ]</b>\n<b>{flag_match.group(0)}</b>"

    await update.message.reply_text(reply, parse_mode="HTML")


async def analyze_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /analyze <teks> — Analisis mendalam teks CTF/SOC dengan AI Expert.
    Menjalankan decode + analisis payload + AI SOC secara bersamaan.
    """
    if not check_auth(update) or not update.message:
        return

    if not context.args:
        await update.message.reply_text(
            "⚠️ <b>Format:</b> <code>/analyze &lt;payload/CVE/soal/hash/teks&gt;</code>\n\n"
            "<i>Contoh:</i>\n"
            "• <code>/analyze CVE-2021-44228</code>\n"
            "• <code>/analyze ' OR 1=1 -- -</code>\n"
            "• <code>/analyze aGVsbG8gd29ybGQ=</code>",
            parse_mode="HTML"
        )
        return

    text = " ".join(context.args)

    # Guardrail: pastikan teks relevan
    if not is_cyber_soc_context(text):
        logger.info(f"[GUARDRAIL DROP /analyze] Teks di luar konteks: {text[:40]}")
        return

    status_msg = await update.message.reply_text(
        "<b>[ DEEP ANALYSIS ENGINE ]</b>\n"
        "<code>Menjalankan decoder, scanner, dan AI secara paralel...</code>",
        parse_mode="HTML"
    )

    try:
        # Jalankan decode dan AI secara paralel
        decode_task = asyncio.get_event_loop().run_in_executor(None, decode_all, text)
        ai = AIOrchestrator()

        sys_prompt = (
            "Anda adalah Principal Security Researcher, Expert CTF Solver, dan Senior SOC L3 Analyst.\n"
            "Tugas: Analisis teks/payload/string yang diberikan secara mendalam dan profesional.\n\n"
            "Berikan laporan MARKDOWN dengan format:\n"
            "1. 🎯 **KLASIFIKASI**: Jenis ancaman/soal/payload (SQLi, XSS, LFI, CVE, Hash, Crypto, dsb.)\n"
            "2. 🔍 **ANALISIS TEKNIS MENDALAM**: Bedah cara kerja, sub-teknik, dan potensi dampak.\n"
            "3. 🛠️ **TOOLS & PERINTAH EXACT VPS**: Command siap pakai di VPS Linux untuk investigasi/eksploitasi.\n"
            "4. ⚡ **LANGKAH SOLUSI / EKSPLOITASI**: Urutan tindakan konkret untuk menyelesaikan soal atau insiden.\n"
            "5. 🛡️ **MITRE ATT&CK & MITIGASI SOC**: Teknik MITRE, deteksi SIEM, dan rekomendasi pencegahan.\n\n"
            "ATURAN MUTLAK: DILARANG KERAS MENGARANG, MENGHALUSINASIKAN, ATAU BERASUMSI. "
            "Hanya buat pernyataan berdasarkan fakta teknis yang nyata."
        )

        # Jalankan AI analysis
        ai_task = ai.ask_ai(user_question=f"Analisis teks CTF/SOC ini secara mendalam:\n\n```\n{text}\n```", system_prompt=sys_prompt) if ai.is_available() else None

        # Dapatkan hasil decode
        decode_results = await asyncio.get_event_loop().run_in_executor(None, decode_all, text)

        decode_section = ""
        if decode_results:
            decode_section = "\n<b>[ Auto-Decode Results ]</b>\n"
            for r in decode_results[:5]:
                dtype = html.escape(str(r.get("type", "")))
                dval = html.escape(str(r.get("result", ""))[:200])
                decode_section += f"» <b>{dtype}:</b> <code>{dval}</code>\n"

        # Cek flag di decode results
        flag_found = ""
        for r in decode_results:
            flag_m = re.search(r"(KIIBOT|CTF|FLAG|SOC|WORKSHOP)\{[^\}]+\}", str(r.get("result", "")), re.IGNORECASE)
            if flag_m:
                flag_found = flag_m.group(0)
                break

        if ai_task:
            ai_report = await ai_task
        if ai_task:
            ai_report = await ai_task
            full_reply = (
                f"<b>[ DEEP ANALYSIS REPORT ]</b>\n"
                f"🔎 <b>Input:</b> <code>{html.escape(text[:100])}</code>\n"
            )
            if flag_found:
                full_reply += f"\n<b>[ FLAG DITEMUKAN ]</b> <b>{html.escape(flag_found)}</b>\n"
            if decode_section:
                await status_msg.edit_text(full_reply + decode_section + "\n<i>AI sedang menyusun laporan mendalam...</i>", parse_mode="HTML")
            await status_msg.edit_text(full_reply + f"\n{ai_report}", parse_mode="Markdown")
        else:
            simple_reply = (
                f"<b>[ DECODE ANALYSIS RESULT ]</b>\n"
                f"🔎 <b>Input:</b> <code>{html.escape(text[:100])}</code>\n"
            )
            if flag_found:
                simple_reply += f"\n<b>[ FLAG ]</b> <b>{html.escape(flag_found)}</b>\n"
            simple_reply += decode_section or "\n<i>Tidak ada encoding yang dikenali.</i>"
            simple_reply += "\n\n<i>Note: AI tidak aktif — isi configs/ai_keys.json untuk analisis mendalam.</i>"
            await status_msg.edit_text(simple_reply, parse_mode="HTML")

    except Exception as e:
        logger.error(f"Error /analyze: {e}")
        await status_msg.edit_text(f"❌ <b>Error analisis:</b> <code>{html.escape(str(e))}</code>", parse_mode="HTML")


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /report atau /reportsoc — Menghasilkan Laporan SOC & CTF Konsolidasi Multi-Tugas
    dalam format Word (.docx), PDF, atau Markdown (.md).
    """
    if not check_auth(update) or not update.message:
        return

    try:
        from kiibot.database.db import get_database
        db = get_database()
        active_session = db.get_active_ctf_session()
        session_id = active_session.id if active_session else 1
        stats = db.get_ctf_stats(session_id)
    except Exception:
        session_id = 1
        stats = {"targets": 0, "attacks": 0, "findings": 0, "evidence": 0}

    msg_text = (
        "<b>[ 🛡️ GENERATOR LAPORAN SOC &amp; CTF KONSOLIDASI ]</b>\n\n"
        f"<b>Session ID:</b> <code>SESSION-{session_id:03d}</code>\n"
        f"<b>Total Target:</b> <code>{stats.get('targets', 0)}</code>\n"
        f"<b>Total Attack / Task:</b> <code>{stats.get('attacks', 0)}</code>\n"
        f"<b>Total Findings:</b> <code>{stats.get('findings', 0)}</code>\n"
        f"<b>Total Evidence:</b> <code>{stats.get('evidence', 0)}</code>\n\n"
        "<i>Pilih format dokumen laporan SOC profesional yang ingin diunduh:</i>"
    )

    keyboard = [
        [
            InlineKeyboardButton("📝 Download Word (.docx)", callback_data=f"gen_report_docx_{session_id}"),
            InlineKeyboardButton("📄 Download PDF", callback_data=f"gen_report_pdf_{session_id}"),
        ],
        [
            InlineKeyboardButton("📋 Download Markdown (.md)", callback_data=f"gen_report_md_{session_id}"),
        ],
    ]

    await update.message.reply_text(
        msg_text,
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="HTML"
    )



# =====================================================================
# WEB ATTACK CTF MODULE — /webattack <url>
# =====================================================================

# Simpan target URL per user (untuk callback buttons)
_webattack_targets: dict[int, str] = {}


async def webattack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /webattack <url> — Menu interaktif Web CTF Attack Battery.
    Menampilkan sub-menu mode attack: SQLi, Dir Enum, Brute-force, Vuln Scan, All-in-One.
    """
    if not check_auth(update) or not update.message:
        return

    if not context.args:
        usage_text = (
            "⚠️ <b>Format Perintah:</b> <code>/webattack &lt;url_atau_domain&gt;</code>\n\n"
            "<b>Contoh:</b>\n"
            "• <code>/webattack http://target.ctf.com</code>\n"
            "• <code>/webattack http://192.168.1.100:8080/login.php</code>\n"
            "• <code>/webattack https://challenge.picoctf.org</code>\n\n"
            "<b>Setelah URL diset, pilih mode attack:</b>\n"
            "1️⃣ Tech Fingerprint — Identifikasi teknologi web\n"
            "2️⃣ SQL Injection    — Cari & dump credentials via SQLi\n"
            "3️⃣ Dir Enumeration  — Temukan halaman & direktori tersembunyi\n"
            "4️⃣ Login Brute-force — Coba kombinasi user/pass CTF umum\n"
            "5️⃣ Vuln Scanner     — Scan kerentanan web umum (Nikto)\n"
            "6️⃣ OSINT Domain     — Whois, DNS, subdomain recon\n"
            "🔥 ALL-IN-ONE       — Semua tools sekaligus (paling lengkap)"
        )
        await update.message.reply_text(usage_text, parse_mode="HTML")
        return

    # Ambil URL, bersihkan jika ada duplikasi scheme (misal: http://target.ctf.comhttps://...)
    raw_arg = context.args[0].strip()
    # Jika ada multiple http(s):// di dalam string, ambil yang terakhir
    urls = re.findall(r"https?://[^\s]+", raw_arg)
    if urls:
        target_url = urls[-1]
    else:
        target_url = "http://" + raw_arg if not raw_arg.startswith(("http://", "https://")) else raw_arg

    # Simpan target untuk callback buttons
    user_id = update.effective_user.id
    _webattack_targets[user_id] = target_url

    # Tampilkan sub-menu attack
    menu_text = (
        f"<b>[ WEB ATTACK CTF MODULE ]</b>\n"
        f"<code>TARGET: {html.escape(target_url)}</code>\n\n"
        "<b>Pilih mode attack:</b>\n"
        "1️⃣ <b>Tech Fingerprint</b> — WhatWeb + WAF detection\n"
        "2️⃣ <b>SQL Injection</b>    — SQLmap auto-dump credentials\n"
        "3️⃣ <b>Dir Enumeration</b>  — Gobuster + ffuf + dirb\n"
        "4️⃣ <b>Login Brute-force</b> — Hydra HTTP/SSH brute-force\n"
        "5️⃣ <b>Vuln Scanner</b>     — Nikto + Nmap web scripts\n"
        "6️⃣ <b>OSINT Domain</b>     — Whois + dig + theHarvester\n"
        "🔥 <b>ALL-IN-ONE</b>       — Full battery (semua tools paralel)\n\n"
        "<i>⚠️ PERINGATAN: Gunakan HANYA pada target yang Anda miliki izin eksplisit untuk dites (CTF challenge, lab sendiri).</i>"
    )
    await update.message.reply_text(
        menu_text,
        parse_mode="HTML",
        reply_markup=get_webattack_keyboard(target_url)
    )


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Alias /scan → /webattack untuk kemudahan akses."""
    await webattack_command(update, context)


async def _run_webattack_mode(update_or_query, context: ContextTypes.DEFAULT_TYPE,
                               target_url: str, mode: str):
    """
    Helper: Jalankan tools web attack berdasarkan mode yang dipilih.
    mode: 'fingerprint' | 'sqli' | 'dir' | 'bruteforce' | 'vulnscan' | 'osint' | 'all'
    """
    from kiibot.core.tool_registry import CATEGORY_TOOL_MAP

    # Tentukan tools berdasarkan mode
    mode_config = {
        "fingerprint": {
            "title": "TECH FINGERPRINT",
            "emoji": "🔍",
            "tools": ["curl", "whatweb", "wafw00f", "nmap_web"],
            "desc": "WhatWeb + WAF Detection + Nmap Web Scripts"
        },
        "sqli": {
            "title": "SQL INJECTION ATTACK",
            "emoji": "💉",
            "tools": ["whatweb", "sqlmap", "sqlmap_full"],
            "desc": "SQLmap auto-detect & dump credentials (level=5, forms scan)"
        },
        "dir": {
            "title": "DIRECTORY ENUMERATION",
            "emoji": "📂",
            "tools": ["gobuster", "ffuf", "dirb", "nikto"],
            "desc": "Gobuster + ffuf + dirb — temukan halaman & direktori tersembunyi"
        },
        "bruteforce": {
            "title": "LOGIN BRUTE-FORCE",
            "emoji": "🔐",
            "tools": ["hydra_http_get", "curl", "whatweb"],
            "desc": "Hydra HTTP Basic Auth brute-force dengan CTF mini-wordlist"
        },
        "vulnscan": {
            "title": "VULNERABILITY SCANNER",
            "emoji": "🛡️",
            "tools": ["nikto", "nmap_web", "whatweb", "curl"],
            "desc": "Nikto web scanner + Nmap vuln scripts"
        },
        "osint": {
            "title": "OSINT DOMAIN RECON",
            "emoji": "🌐",
            "tools": ["whois", "dig", "nslookup"],
            "desc": "Whois + DNS lookup — informasi pemilik domain & rekaman DNS"
        },
        "all": {
            "title": "ALL-IN-ONE BATTERY",
            "emoji": "🔥",
            "tools": ["curl", "whatweb", "wafw00f", "nmap_web", "gobuster", "ffuf", "nikto", "sqlmap"],
            "desc": "Full battery: Fingerprint + WAF + Dir + SQLi + Vuln Scan (8 tools paralel)"
        },
    }

    cfg = mode_config.get(mode, mode_config["all"])
    tools_list = cfg["tools"]
    title = cfg["title"]
    emoji = cfg["emoji"]
    desc = cfg["desc"]

    # Untuk OSINT, gunakan domain tanpa scheme
    attack_target = target_url
    if mode == "osint":
        import urllib.parse
        parsed = urllib.parse.urlparse(target_url)
        attack_target = parsed.netloc or parsed.path or target_url

    tools_display = ", ".join([f"<code>{t}</code>" for t in tools_list])

    # Cari pesan untuk di-edit
    msg_obj = None
    if hasattr(update_or_query, 'message') and update_or_query.message:
        msg_obj = update_or_query.message
    elif hasattr(update_or_query, 'callback_query') and update_or_query.callback_query:
        msg_obj = update_or_query.callback_query.message

    if not msg_obj:
        return

    status_msg = await msg_obj.reply_text(
        f"<b>[ {emoji} {title} ]</b>\n"
        f"<code>TARGET: {html.escape(target_url)}</code>\n"
        f"<code>MODE   : {html.escape(desc)}</code>\n"
        f"<code>TOOLS  : {tools_display}</code>\n\n"
        f"<code>STATUS: Menjalankan {len(tools_list)} tools secara paralel...</code>",
        parse_mode="HTML"
    )

    try:
        # Jalankan tools secara konkuren
        tool_results = await execute_concurrent_tools(tools_list, attack_target)

        # Update status
        await status_msg.edit_text(
            f"<b>[ {emoji} {title} — SELESAI ]</b>\n"
            f"<code>TARGET: {html.escape(target_url)}</code>\n\n"
            f"<code>STATUS: ✅ {len(tools_list)} tools selesai. Menyusun laporan AI...</code>",
            parse_mode="HTML"
        )

        # Buat laporan dengan AI
        ai = AIOrchestrator()
        ai_sys_prompt = (
            "Anda adalah Senior Web Pentester & CTF Solver yang ahli dalam Web Exploitation.\n"
            f"Target URL: {target_url}\n"
            f"Mode Attack yang dijalankan: {title}\n\n"
            "Tugas: Analisis output tools di bawah ini dan buat laporan profesional yang mencakup:\n"
            "1. 🔍 **TEMUAN UTAMA**: Apa yang ditemukan (teknologi, kerentanan, direktori, credential)\n"
            "2. 💉 **POTENSI EKSPLOITASI**: Langkah konkret untuk mendapatkan username/password/flag\n"
            "3. 🛠️ **PERINTAH LANJUTAN**: Command spesifik yang bisa dicoba selanjutnya di VPS\n"
            "4. 🚩 **APAKAH ADA FLAG?**: Jika ada string yang terlihat seperti flag CTF, highlight dengan jelas\n\n"
            "ATURAN: Berikan analisis faktual berdasarkan output tools. Jangan mengarang."
        )

        if ai.is_available():
            try:
                ai_report = await ai.analyze_results(
                    tool_results,
                    previous_context=f"Web Attack {title} pada {target_url}"
                )
            except Exception as e_ai:
                ai_report = f"⚠️ <i>AI Analysis Error ({e_ai}). Menampilkan hasil eksekusi tools mentah:</i>\n\n"
                for tool_name, tool_out in tool_results.items():
                    if tool_out:
                        ai_report += f"<b>[ 🛠️ TOOL: {tool_name.upper()} ]</b>\n<code>{html.escape(str(tool_out)[:500])}</code>\n\n"
        else:
            ai_report = "<b>[ 🛠️ HASIL EKSEKUSI TOOLS LINUX REAL-TIME ]</b>\n\n"
            for tool_name, tool_out in tool_results.items():
                if tool_out and len(str(tool_out)) > 5:
                    ai_report += f"<b>🔹 Tool {tool_name.upper()}:</b>\n<code>{html.escape(str(tool_out)[:600])}</code>\n\n"
            ai_report += "<i>💡 Catatan: Hasil di atas adalah output eksekusi langsung dari binary tools Linux yang terpasang di VPS Anda.</i>"

        # Format final report
        full_reply = (
            f"<b>[ {emoji} WEB ATTACK & SOC INCIDENT REPORT: {title} ]</b>\n"
            f"<code>TARGET: {html.escape(target_url)}</code>\n\n"
        )

        # Cek apakah ada credential/flag yang ditemukan di output mentah
        raw_output_str = str(tool_results)
        cred_patterns = re.findall(
            r"(?:password|passwd|pass|pwd|credential)[\s:=]+([\w@!#$%^&*()_+=-]{4,30})",
            raw_output_str, re.IGNORECASE
        )
        flag_patterns = re.findall(
            r"((?:CTF|FLAG|KIIBOT|picoCTF|HTB|THM)\{[^}]+\})",
            raw_output_str, re.IGNORECASE
        )

        if flag_patterns:
            full_reply += f"🚩 <b>FLAG DITEMUKAN: {html.escape(', '.join(set(flag_patterns)))}</b>\n\n"
        if cred_patterns:
            unique_creds = list(set(cred_patterns))[:5]
            full_reply += f"🔑 <b>POTENTIAL CREDS: {html.escape(', '.join(unique_creds))}</b>\n\n"

        full_reply += f"\n{ai_report}"

        # Selalu simpan dan kirimkan file laporan resmi (.md)
        os.makedirs("reports", exist_ok=True)
        safe_target = re.sub(r"[^\w\-.]", "_", target_url)[:40]
        report_file_path = os.path.join("reports", f"SOC_Report_{mode.upper()}_{safe_target}.md")
        with open(report_file_path, "w", encoding="utf-8") as f:
            f.write(f"# KIIBOT SOC & CTF INCIDENT REPORT: {title}\n")
            f.write(f"Target: {target_url}\n")
            f.write(f"Timestamp: {os.popen('date').read().strip()}\n\n")
            f.write(ai_report)
            f.write("\n\n---\n## RAW TOOLS OUTPUT DUMP\n\n")
            for tname, tout in tool_results.items():
                f.write(f"### TOOL: {tname.upper()}\n```\n{tout}\n```\n\n")

        # Kirim ringkasan chat
        if len(full_reply) > 3800:
            summary_chat = (
                f"<b>[ {emoji} WEB ATTACK & SOC REPORT: {title} ]</b>\n"
                f"<code>TARGET: {html.escape(target_url)}</code>\n\n"
                f"✅ <b>Analisis SOC Selesai:</b> {len(tools_list)} tools berhasil dieksekusi.\n"
            )
            if flag_patterns:
                summary_chat += f"🚩 <b>FLAG DITEMUKAN:</b> <code>{html.escape(', '.join(set(flag_patterns)))}</code>\n"
            if cred_patterns:
                summary_chat += f"🔑 <b>Kredensial Ditemukan:</b> <code>{html.escape(', '.join(list(set(cred_patterns))[:5]))}</code>\n"
            summary_chat += (
                f"\n📄 <b>Laporan Lengkap Mendetail & Mitigasi SOC Terlampir di bawah (.md).</b>"
            )
            await status_msg.edit_text(summary_chat, parse_mode="HTML")
        else:
            await status_msg.edit_text(full_reply, parse_mode="HTML")

        # Kirim dokumen laporan lengkap ke Telegram
        with open(report_file_path, "rb") as doc:
            await msg_obj.reply_document(
                document=doc,
                caption=f"📋 <b>Laporan Investigasi SOC & Hasil Scan ({html.escape(title)})</b>\nTarget: <code>{html.escape(target_url)}</code>",
                parse_mode="HTML"
            )

        # Kirim juga file teks output mentah dari tools
        await _send_raw_results(msg_obj, f"Raw WebAttack Output ({title})", tool_results, os.path.join("reports", f"raw_{safe_target}"))

        # Tampilkan kembali sub-menu untuk serangan lanjutan
        await msg_obj.reply_text(
            f"✅ <b>{title} selesai.</b> Pilih mode lain untuk melanjutkan:\n"
            f"<code>Target: {html.escape(target_url)}</code>",
            parse_mode="HTML",
            reply_markup=get_webattack_keyboard(target_url)
        )

    except Exception as e:
        logger.error(f"Error _run_webattack_mode ({mode}): {e}")
        await status_msg.edit_text(
            f"❌ <b>Error saat menjalankan {title}:</b>\n<code>{html.escape(str(e))}</code>",
            parse_mode="HTML"
        )full_reply)
                tmp_path = f.name
            with open(tmp_path, 'rb') as doc:
                await msg_obj.reply_document(
                    document=doc,
                    caption=f"📋 <b>Web Attack Report: {html.escape(title)} — {html.escape(target_url[:50])}</b>",
                    parse_mode="HTML"
                )
        else:
            await status_msg.edit_text(full_reply, parse_mode="HTML")

        # Tampilkan kembali sub-menu untuk serangan lanjutan
        await msg_obj.reply_text(
            f"✅ <b>{title} selesai.</b> Pilih mode lain untuk melanjutkan:\n"
            f"<code>Target: {html.escape(target_url)}</code>",
            parse_mode="HTML",
            reply_markup=get_webattack_keyboard(target_url)
        )

    except Exception as e:
        logger.error(f"Error _run_webattack_mode ({mode}): {e}")
        await status_msg.edit_text(
            f"❌ <b>Error saat menjalankan {title}:</b>\n<code>{html.escape(str(e))}</code>",
            parse_mode="HTML"
        )


async def handle_callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Menangani interaksi klik tombol keyboard — termasuk menu numbered dan webattack sub-menu."""
    query = update.callback_query
    if not query:
        return

    await query.answer()

    data = query.data
    user_id = update.effective_user.id if update.effective_user else 0

    # ── Menu Utama Numbered ───────────────────────────────────────────────────
    if data == "menu_main":
        await query.message.reply_text(
            "🏠 <b>Kembali ke Menu Utama</b>\n"
            "Gunakan /start untuk menampilkan menu lengkap.",
            parse_mode="HTML",
            reply_markup=get_main_keyboard()
        )

    elif data == "menu_file":
        await query.message.reply_text(
            "1️⃣ <b>[ MODE: Analisis File CTF ]</b>\n\n"
            "Kirimkan file langsung ke chat ini:\n"
            "» <code>.pcap / .pcapng</code> → Expert Wireshark Battery\n"
            "» <code>.log / .txt</code>    → Log Forensics Battery\n"
            "» <code>.png / .jpg</code>    → AI Vision + Stego Tools\n"
            "» <code>.elf / .bin</code>    → Binary Reversing Tools\n"
            "» <code>.zip / .tar</code>    → Archive Forensics\n"
            "» <code>.mem / .dmp</code>    → Memory Forensics (Volatility)\n\n"
            "<i>Cukup kirim file-nya, bot akan otomatis mendeteksi dan menjalankan tools yang sesuai!</i>",
            parse_mode="HTML"
        )

    elif data == "menu_webattack":
        await query.message.reply_text(
            "2️⃣ <b>[ MODE: Web Attack CTF ]</b>\n\n"
            "Kirimkan URL atau domain target:\n"
            "<code>/webattack http://target.ctf.com</code>\n\n"
            "<b>Kemampuan attack:</b>\n"
            "💉 SQL Injection (sqlmap) — dump username &amp; password\n"
            "📂 Dir Enumeration (gobuster/ffuf) — cari halaman tersembunyi\n"
            "🔐 Login Brute-force (hydra) — coba password CTF umum\n"
            "🔍 Tech Fingerprint (whatweb) — identifikasi teknologi\n"
            "🛡️ Vuln Scan (nikto) — cari kerentanan web umum\n"
            "🌐 OSINT Domain (whois/dig) — info domain &amp; DNS\n"
            "🔥 ALL-IN-ONE — semua sekaligus!\n\n"
            "<i>⚠️ Hanya gunakan untuk target yang Anda miliki izin eksplisit (CTF challenge).</i>",
            parse_mode="HTML"
        )

    elif data == "menu_decode":
        await query.message.reply_text(
            "3️⃣ <b>[ MODE: Decode &amp; Crypto ]</b>\n\n"
            "Gunakan command:\n"
            "» <code>/decode &lt;teks/hash&gt;</code> — Auto-detect &amp; decode\n"
            "» <code>/analyze &lt;payload&gt;</code>  — Deep AI analysis\n\n"
            "<b>Format yang didukung:</b>\n"
            "• MD5 / SHA1 / SHA256 hash\n"
            "• Base64 / Base32 / Base58\n"
            "• Hex / Octal / Binary\n"
            "• ROT13 / ROT47 / Caesar Cipher\n"
            "• XOR (brute-force key 1-255)\n"
            "• JWT Token (decode payload)\n"
            "• URL Encoding / HTML Entities\n"
            "• Morse Code\n\n"
            "<i>Contoh: <code>/decode aGVsbG8gd29ybGQ=</code></i>",
            parse_mode="HTML"
        )

    elif data == "menu_soc":
        await triage_command(update, context)

    # ── Legacy buttons ────────────────────────────────────────────────────────
    elif data == "btn_soc":
        soc_text = (
            "🛡️ <b>SOC Analyst Workflow (Blue Team):</b>\n\n"
            "1. <b>Triage:</b> Identifikasi tingkat bahaya alert (Gunakan /triage).\n"
            "2. <b>Investigasi Log:</b> Sisir raw logs untuk menemukan Root Cause.\n"
            "3. <b>Mitigasi:</b> Containment ancaman (contoh: blokir IP di WAF).\n"
            "4. <b>Resolusi:</b> Susun rules pertahanan baru (contoh: update SIEM)."
        )
        await query.message.reply_text(soc_text, parse_mode="HTML")

    elif data == "btn_triage":
        await triage_command(update, context)

    elif data == "btn_mitre_list":
        avail = ", ".join([f"<code>{t}</code>" for t in get_all_techniques()])
        await query.message.reply_text(
            f"📚 <b>Daftar Teknik MITRE ATT&CK yang Tersedia:</b>\n\n{avail}\n\n"
            f"Gunakan <code>/mitre &lt;ID&gt;</code> (misal: <code>/mitre T1140</code>) untuk melihat detil teknik dan mitigasi.",
            parse_mode="HTML"
        )

    elif data == "btn_tools":
        await tools_command(update, context)

    elif data == "btn_doctor":
        await doctor_command(update, context)

    elif data == "btn_aikeys":
        await aikeys_command(update, context)

    elif data == "btn_help":
        await help_command(update, context)

    # ── Web Attack Sub-menu ───────────────────────────────────────────────────
    elif data.startswith("wa_"):
        # Ambil target URL yang tersimpan untuk user ini
        target_url = _webattack_targets.get(user_id, "")
        if not target_url:
            await query.message.reply_text(
                "⚠️ <b>Sesi Web Attack telah kadaluarsa.</b>\n"
                "Jalankan ulang: <code>/webattack &lt;url&gt;</code>",
                parse_mode="HTML"
            )
            return

        mode_map = {
            "wa_fingerprint": "fingerprint",
            "wa_sqli": "sqli",
            "wa_dir": "dir",
            "wa_bruteforce": "bruteforce",
            "wa_vulnscan": "vulnscan",
            "wa_osint": "osint",
            "wa_all": "all",
        }
        mode = mode_map.get(data, "all")
        await _run_webattack_mode(update, context, target_url, mode)

    elif data.startswith("gen_report_"):
        parts = data.split("_")
        fmt = parts[2] if len(parts) > 2 else "docx"  # docx, pdf, md
        sess_id = int(parts[3]) if len(parts) > 3 else 1

        status_msg = await query.message.reply_text(
            f"⏳ <b>[ REPORT GENERATOR ]</b> Menyusun laporan SOC konsolidasi dalam format <code>{fmt.upper()}</code>...",
            parse_mode="HTML"
        )
        try:
            from kiibot.ctf.report_generator import CTFReportGenerator
            rg = CTFReportGenerator()

            if fmt == "docx":
                out_path = rg.generate_docx(sess_id)
                caption = "📝 <b>Laporan SOC Konsolidasi (.docx)</b>\nSiap diedit dan dipresentasikan di Microsoft Word."
            elif fmt == "pdf":
                out_path = rg.generate_pdf(sess_id)
                caption = "📄 <b>Laporan SOC Konsolidasi (.pdf)</b>"
            else:
                out_path = rg.generate(sess_id)
                caption = "📋 <b>Laporan SOC Konsolidasi (.md)</b>"

            with open(out_path, "rb") as doc_file:
                await query.message.reply_document(
                    document=doc_file,
                    caption=caption,
                    parse_mode="HTML"
                )
            try:
                await status_msg.delete()
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Gagal generate report ({fmt}): {e}")
            await status_msg.edit_text(
                f"❌ <b>Gagal membuat laporan {fmt.upper()}:</b> <code>{html.escape(str(e))}</code>",
                parse_mode="HTML"
            )



# =====================================================================
# MESSAGE HANDLERS DENGAN CONTEXT GUARDRAIL
# =====================================================================

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Menangani pesan teks biasa.
    GUARDRAIL: Jika di luar konteks CTF & SOC -> JANGAN DIBALAS (Silent drop).
    """
    if not check_auth(update) or not update.message:
        return

    text = update.message.text
    if not text:
        return

    # PEMBATAS KONTEKS (GUARDRAIL)
    if not is_cyber_soc_context(text):
        logger.info(f"[GUARDRAIL DROP] Pesan di luar konteks diabaikan (tidak dibalas): {text[:50]}")
        # DI LUAR KONTEKS: JANGAN DI BALES (Sesuai instruksi pengguna)
        return

    logger.info(f"[IN-CONTEXT] Memproses pesan: {text[:50]}")

    # 1. Cek apakah teks adalah URL/Domain untuk Web Attack
    clean_strip = text.strip()
    is_url = re.match(r"^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", clean_strip)
    if is_url and " " not in clean_strip:
        # Jika bukan sekadar IP biasa (harus domain atau URL yang valid)
        context.args = [clean_strip]
        await webattack_command(update, context)
        return

    # 2. Coba decode terlebih dahulu jika tampak seperti cipher/hash/base64
    looks_like_encoded = (
        re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", clean_strip) or
        (len(clean_strip) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=]+", clean_strip) and " " not in clean_strip) or
        clean_strip.startswith("0x") or
        re.search(r"(ctf|kiibot|flag)\{", clean_strip, re.IGNORECASE)
    )

    if looks_like_encoded:
        context.args = clean_strip.split()
        await decode_command(update, context)
        return

    # 2. Cek apakah teks merupakan cuplikan file log (misal Nginx/Apache/SIEM logs)
    is_log_snippet = (
        re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text) and
        re.search(r"(GET|POST|PUT|DELETE|HTTP/|\[\d{2}/[A-Za-z]{3}/\d{4})", text)
    )

    if is_log_snippet:
        status_msg = await update.message.reply_text(
            "<b>[ CONCURRENT LOG BATTERY ]</b>\n"
            "<code>Mengeksekusi 9 tools investigasi log & beaconing secara paralel...</code>",
            parse_mode="HTML"
        )
        try:
            analyzer = DeepLogAnalyzer(log_content=text)
            battery_results = await analyzer.run_concurrent_battery()
            
            suspect_ip = battery_results["top_ips"].get("suspect_attacker_ip") or "Tidak terdeteksi"
            sqli_count = len(battery_results["sqli_findings"])
            xss_count = len(battery_results["xss_findings"])
            rce_count = len(battery_results["rce_findings"])
            lfi_count = len(battery_results["lfi_findings"])
            scanners = ", ".join(battery_results["user_agents"].get("scanners_found", [])) or "None"
            flags = battery_results.get("flags_found", [])
            
            beaconing = battery_results.get("beaconing", {})
            beacon_suspects = beaconing.get("beaconing_suspects", [])
            beacon_count = len(beacon_suspects)

            summary_text = (
                "<b>[ LOG ANALYSIS REPORT ]</b>\n"
                f"<code>CONTEXT: Web Attack & Incident Investigation</code>\n\n"
                f"» <b>Attacker Suspect :</b> {html.escape(suspect_ip)}\n"
                f"» <b>Known Scanners   :</b> {html.escape(scanners)}\n\n"
                "<b>[ Attack Indications ]</b>\n"
                f"- SQL Injection      : {sqli_count} hits\n"
                f"- XSS Payload        : {xss_count} hits\n"
                f"- RCE / Command Inj  : {rce_count} hits\n"
                f"- LFI / Traversal    : {lfi_count} hits\n"
                f"- C2 Beacon Suspects : {beacon_count} IPs\n\n"
            )

            if flags:
                summary_text += f"🚩 <b>FLAG DETECTED :</b> <b>{html.escape(', '.join(flags))}</b>\n\n"

            ai = AIOrchestrator()
            if ai.is_available():
                await status_msg.edit_text(summary_text + "<i>Menyusun mitigasi SOC taktis dengan AI...</i>", parse_mode="HTML")
                ai_report = await ai.analyze_results(battery_results, previous_context="Analisis Cuplikan Log Web Serentak")
                await status_msg.edit_text(f"{summary_text}\n<b>[ AI SOC Mitigation Report ]</b>\n\n{ai_report}", parse_mode="Markdown")
            else:
                await status_msg.edit_text(summary_text, parse_mode="HTML")
            return
        except Exception as e:
            logger.error(f"Gagal menjalankan log battery: {e}")
            await status_msg.edit_text(f"❌ Error saat analisis log: {e!s}")
            return

    # 3. Jika merupakan teks pertanyaan konseptual / analisa SOC umum:
    ai = AIOrchestrator()
    if ai.is_available():
        status_info = ai.get_status_info()
        curr_key = status_info.get("active_key_index", 1)
        status_msg = await update.message.reply_text(
            f"🧠 <i>Menganalisis query dengan AI SOC Engine (Key #{curr_key})...</i>",
            parse_mode="HTML"
        )
        try:
            from kiibot.ctf.report_generator import CTFReportGenerator
            from kiibot.ctf.session_manager import CTFSessionManager
            
            ctf_context = ""
            try:
                sm = CTFSessionManager()
                sess = sm.get_active_session()
                if not sess:
                    sessions = sm.list_sessions()
                    if sessions:
                        sess = sessions[0]
                
                if sess:
                    rg = CTFReportGenerator()
                    md_report = rg.generate_markdown(sess.id)
                    ctf_context = (
                        f"\n\n[KONTEKS DATA CTF / SOC SAAT INI (SESSION-{sess.id:03d})]:\n"
                        f"{md_report}\n\n"
                        "Gunakan informasi dari laporan CTF di atas untuk menjawab pertanyaan jika relevan dengan laporan."
                    )
            except Exception as e:
                logger.warning(f"Gagal mengambil konteks CTF: {e}")

            sys_prompt = (
                "Anda adalah Senior SOC Analyst & CTF Solver (Blue Team). "
                "Jawablah dengan profesional, terstruktur, dan taktis. "
                "Jelaskan konsep soal, tools yang tepat di VPS, langkah penyelesaian, dan rekomendasi mitigasi SOC."
            ) + ctf_context
            
            try:
                ai_reply = await ai.ask_ai(user_question=text, system_prompt=sys_prompt)
                await status_msg.edit_text(ai_reply, parse_mode="Markdown")
            except Exception as e:
                logger.error(f"AI response error: {e}")
                # 2-WAY FALLBACK EXPERT BOT CHAT (Zero-AI dependent response)
                fallback_chat = (
                    "<b>🤖 KIIBOT CYBER ADVISOR [2-Way Direct Assistant]</b>\n"
                    "───────────────────────────────\n\n"
                    f"<b>Pertanyaan / Query Operator:</b>\n<code>{html.escape(text)}</code>\n\n"
                    "<b>📌 REKOMENDASI LENGKAP AKURAT & TAKTIS:</b>\n"
                    "• <b>Format Decode / Payload:</b> Gunakan perintah <code>/decode <teks></code> atau <code>/analyze <payload></code>.\n"
                    "• <b>Web Pentest & Exploitation:</b> Gunakan <code>/webattack <url></code> untuk eksekusi otomatis `sqlmap`, `gobuster`, `nikto`, `whatweb`, & `hydra` di VPS.\n"
                    "• <b>Network Forensics:</b> Upload file `.pcap` untuk analisis otomatis 8 tools Wireshark.\n"
                    "• <b>Binary Reversing:</b> Upload file `.elf`/`.bin` untuk inspection `checksec`, `objdump`, `readelf`, `strace`, & `ltrace`.\n"
                    "• <b>Laporan Resmi SOC:</b> Ketik <code>/reportsoc</code> untuk mengunduh laporan `.docx` / `.pdf` resmi sesuai SOP SOC.\n\n"
                    "<i>💡 Note: Seluruh 71 tools Linux di VPS Anda siap dieksekusi 100% tanpa hambatan.</i>"
                )
                await status_msg.edit_text(fallback_chat, parse_mode="HTML")
        except Exception as e:
            logger.error(f"Error preparing AI context: {e}")
            await status_msg.edit_text("❌ Error processing request.")
    else:
        results = decode_all(text)
        if results:
            context.args = text.split()
            await decode_command(update, context)
        else:
            fallback_chat = (
                "<b>🤖 KIIBOT CYBER ADVISOR [2-Way Direct Assistant]</b>\n"
                "───────────────────────────────\n\n"
                f"<b>Query Operator:</b> <code>{html.escape(text)}</code>\n\n"
                "<b>📌 ACTIONABLE STEPS UNTUK WINNING CTF / SOC OPS:</b>\n"
                "1. <b>Attack Phase:</b> Jalankan <code>/webattack <url></code> untuk dump kredensial & direktori rahasia.\n"
                "2. <b>Defense Phase:</b> Kirim berkas log server untuk eksekusi otomatis 9 tools deteksi IP penyerang.\n"
                "3. <b>Export Laporan:</b> Gunakan <code>/reportsoc</code> untuk menghasilkan file `.docx` / `.pdf` standar SOC internasional.\n\n"
                "<i>💡 Jalankan <code>/doctor</code> untuk memverifikasi 71+ tools Linux VPS Anda.</i>"
            )
            await update.message.reply_text(fallback_chat, parse_mode="HTML")


async def _send_raw_results(update: Update, title: str, results_dict: dict, base_path: str):
    """Membantu mengirimkan file teks mentah hasil eksekusi tools."""
    import json
    raw_path = f"{base_path}_raw_output.txt"
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(f"=== {title} ===\n\n")
        for k, v in results_dict.items():
            f.write(f"--- TOOL: {k} ---\n")
            if isinstance(v, (dict, list)):
                f.write(json.dumps(v, indent=2))
            else:
                f.write(str(v))
            f.write("\n\n")
    
    with open(raw_path, "rb") as doc:
        await update.message.reply_document(
            document=doc,
            caption=f"⚙️ <b>Raw Tools Output:</b> {html.escape(title)}",
            parse_mode="HTML"
        )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Menangani pengiriman file/dokumen.
    Jika file log: Jalankan DeepLogAnalyzer secara serentak bertubi-tubi.
    Jika PCAP/Binary/Archive: Orkestrasi 5-10 tools paralel.
    """
    if not check_auth(update) or not update.message or not update.message.document:
        return

    document = update.message.document
    file_id = document.file_id
    file_name = document.file_name or "unknown_file"

    status_card = await update.message.reply_text(
        f"<b>[ RECEIVING ARTIFACT ]</b>\n"
        f"» <b>File:</b> <code>{html.escape(file_name)}</code>\n"
        f"<code>STATUS: [1/3] Mengunduh berkas...</code>",
        parse_mode="HTML"
    )

    try:
        new_file = await context.bot.get_file(file_id)
        os.makedirs("temp_ctf", exist_ok=True)
        file_path = os.path.join("temp_ctf", file_name)
        await new_file.download_to_drive(file_path)

        # Cek apakah ini file log
        is_log_file = (
            file_name.lower().endswith((".log", ".txt", ".csv")) or
            "access" in file_name.lower() or
            "nginx" in file_name.lower() or
            "apache" in file_name.lower()
        )

        if is_log_file:
            await status_card.edit_text(
                f"<b>[ CONCURRENT LOG BATTERY ]</b>\n"
                f"» <b>File:</b> <code>{html.escape(file_name)}</code>\n"
                f"<code>STATUS: [2/3] Mengeksekusi 9 tools log & beaconing...</code>",
                parse_mode="HTML"
            )

            analyzer = DeepLogAnalyzer(file_path=file_path)
            # Jalankan log battery dan tools external di VPS secara simultan
            log_battery_task = analyzer.run_concurrent_battery()
            vps_tools_task = execute_concurrent_tools(["awk_top_ip", "grep_ip", "grep_sqli", "grep_xss", "grep_useragent"], file_path)

            battery_results, vps_results = await asyncio.gather(log_battery_task, vps_tools_task)

            suspect_ip = battery_results["top_ips"].get("suspect_attacker_ip") or "Tidak terdeteksi"
            scanners = ", ".join(battery_results["user_agents"].get("scanners_found", [])) or "None"
            flags = battery_results.get("flags_found", [])
            beacon_suspects = battery_results.get("beaconing", {}).get("beaconing_suspects", [])
            beacon_count = len(beacon_suspects)

            await status_card.edit_text(
                f"<b>[ AI INCIDENT REPORTING ]</b>\n"
                f"» <b>File:</b> <code>{html.escape(file_name)}</code>\n"
                f"» <b>Suspect IP:</b> <code>{html.escape(suspect_ip)}</code>\n"
                f"» <b>Scanner   :</b> <code>{html.escape(scanners)}</code>\n"
                f"» <b>Beaconing :</b> <code>{beacon_count} suspects</code>\n\n"
                f"<code>STATUS: [3/3] Menyusun laporan temuan & mitigasi SOC...</code>",
                parse_mode="HTML"
            )

            aggregated_results = {
                "native_log_battery": battery_results,
                "vps_tools_output": vps_results
            }

            ai = AIOrchestrator()
            final_report = await ai.analyze_results(
                aggregated_results,
                previous_context=f"Analisis Log Serentak: {file_name}. Attacker Suspect: {suspect_ip}, Beaconing: {beacon_count}, Flags: {flags}"
            )

            full_reply = (
                f"<b>[ LOG ANALYSIS REPORT ]</b>\n"
                f"<code>CONTEXT: Incident Response</code>\n\n"
                f"» <b>Attacker Suspect :</b> {html.escape(suspect_ip)}\n"
                f"» <b>Known Scanners   :</b> {html.escape(scanners)}\n"
                f"» <b>C2 Beaconing     :</b> {beacon_count} IPs\n\n"
            )
            if flags:
                full_reply += f"🚩 <b>FLAG DETECTED:</b> <b>{html.escape(', '.join(flags))}</b>\n\n"

            full_reply += f"\n{final_report}"

            if len(full_reply) > 3800:
                report_path = f"{file_path}_report.md"
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(full_reply)
                await update.message.reply_document(
                    document=open(report_path, "rb"),
                    caption=f"📋 <b>Laporan Analisis Log Bertubi-tubi ({html.escape(file_name)})</b>",
                    parse_mode="HTML"
                )
            else:
                await update.message.reply_text(full_reply, parse_mode="Markdown")
                
            all_raw = {"Log Battery": battery_results, "VPS Tools": vps_results}
            await _send_raw_results(update, "Log Analysis Results", all_raw, file_path)
            return

        # Cek apakah ini file PCAP / Network Traffic Capture
        is_pcap_file = file_name.lower().endswith((".pcap", ".pcapng", ".cap"))

        if is_pcap_file:
            await status_card.edit_text(
                f"<b>[ EXPERT WIRESHARK BATTERY ]</b>\n"
                f"» <b>File:</b> <code>{html.escape(file_name)}</code>\n"
                f"<code>STATUS: [2/3] Mengeksekusi 11 tools Wireshark/tshark/TLS/SSH serentak...</code>",
                parse_mode="HTML"
            )

            pcap_analyzer = ProfessionalPCAPAnalyzer(file_path)
            pcap_battery_results = await pcap_analyzer.run_expert_pcap_battery()

            dns_count = len(pcap_battery_results.get("dns_queries", []))
            http_count = len(pcap_battery_results.get("http_traffic", []))
            creds_count = len(pcap_battery_results.get("credentials", []))
            tls_count = len(pcap_battery_results.get("tls_sni", []))
            ssh_count = len(pcap_battery_results.get("ssh_banners", []))
            flags = pcap_battery_results.get("flags_found", [])

            await status_card.edit_text(
                f"<b>[ SYNTHESIZING NETWORK INTEL ]</b>\n"
                f"» <b>File:</b> <code>{html.escape(file_name)}</code>\n"
                f"» <b>HTTP Streams:</b> <code>{http_count} streams</code>\n"
                f"» <b>DNS Queries :</b> <code>{dns_count} domains</code>\n"
                f"» <b>TLS Domains :</b> <code>{tls_count} domains</code>\n"
                f"» <b>Credentials :</b> <code>{creds_count} captured</code>\n\n"
                f"<code>STATUS: [3/3] AI menyusun laporan forensik jaringan profesional...</code>",
                parse_mode="HTML"
            )

            ai = AIOrchestrator()
            final_report = await ai.analyze_results(
                pcap_battery_results,
                previous_context=f"Analisis PCAP Expert Wireshark: {file_name}. TLS SNI: {tls_count}, SSH: {ssh_count}, Flags: {flags}"
            )

            full_reply = (
                f"<b>[ EXPERT WIRESHARK ANALYSIS ]</b>\n"
                f"<code>CONTEXT: Network Forensics & Packet Analysis</code>\n\n"
                f"» <b>HTTP Sessions   :</b> {http_count} sessions\n"
                f"» <b>DNS Queries     :</b> {dns_count} queries\n"
                f"» <b>TLS SNI Domains :</b> {tls_count} domains\n"
                f"» <b>SSH Banners     :</b> {ssh_count} captured\n"
            )
            if flags:
                full_reply += f"🚩 <b>FLAG DETECTED :</b> <b>{html.escape(', '.join(flags))}</b>\n\n"

            full_reply += f"\n{final_report}"

            if len(full_reply) > 3800:
                report_path = f"{file_path}_report.md"
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(full_reply)
                await update.message.reply_document(
                    document=open(report_path, "rb"),
                    caption=f"📋 <b>Laporan Network Forensic Wireshark ({html.escape(file_name)})</b>",
                    parse_mode="HTML"
                )
            else:
                await update.message.reply_text(full_reply, parse_mode="Markdown")
                
            await _send_raw_results(update, "PCAP Wireshark Results", pcap_battery_results, file_path)
            return

        # File biner, arsip, gambar, atau artefak CTF lainnya
        ai = AIOrchestrator()
        await status_card.edit_text(
            f"<b>[ ORCHESTRATING TOOLS ]</b>\n"
            f"» <b>File:</b> <code>{html.escape(file_name)}</code>\n"
            f"<code>STATUS: [2/3] Memilih tools paralel...</code>",
            parse_mode="HTML"
        )

        assessment = await ai.assess_challenge(text_context="Pecahkan berkas CTF ini secara mendalam", file_name=file_name)
        category = assessment.get("category", "Unknown")
        tools_to_run = assessment.get("tools", ["file", "strings", "binwalk", "hexdump"])

        tools_display = ", ".join([f"<code>{t}</code>" for t in tools_to_run])
        await status_card.edit_text(
            f"<b>[ EXECUTING CONCURRENT TOOLS ]</b>\n"
            f"» <b>File:</b> <code>{html.escape(file_name)}</code>\n"
            f"» <b>Kategori:</b> <code>{html.escape(category)}</code>\n"
            f"» <b>Tools :</b> {tools_display}\n\n"
            f"<code>STATUS: [3/3] Menjalankan tools secara bersamaan...</code>",
            parse_mode="HTML"
        )

        tool_results = await execute_concurrent_tools(tools_to_run, file_path)
        final_report = await ai.analyze_results(tool_results, previous_context=f"Kategori: {category}")

        # Selalu simpan file laporan resmi (.md)
        report_path = f"{file_path}_SOC_Report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"# KIIBOT SOC & CTF ANALYSIS REPORT: {file_name}\n")
            f.write(f"Category: {category}\n\n")
            f.write(final_report)
            f.write("\n\n---\n## RAW TOOLS OUTPUT DUMP\n\n")
            for tname, tout in tool_results.items():
                f.write(f"### TOOL: {tname.upper()}\n```\n{tout}\n```\n\n")

        if len(final_report) > 3800:
            await update.message.reply_text(
                f"<b>[ KIIBOT SOC & CTF INCIDENT REPORT ]</b>\n"
                f"» <b>File:</b> <code>{html.escape(file_name)}</code>\n"
                f"» <b>Kategori:</b> <code>{html.escape(category)}</code>\n\n"
                f"✅ <i>Analisis selesai. Laporan lengkap dan mitigasi SOC terlampir di bawah (.md).</i>",
                parse_mode="HTML"
            )
        else:
            await update.message.reply_text(
                f"<b>[ KIIBOT SOC & CTF INCIDENT REPORT ]</b>\n\n"
                f"{final_report}",
                parse_mode="Markdown"
            )

        # Kirim dokumen laporan resmi ke Telegram
        with open(report_path, "rb") as doc:
            await update.message.reply_document(
                document=doc,
                caption=f"📋 <b>Laporan Investigasi SOC ({html.escape(file_name)})</b>",
                parse_mode="HTML"
            )

        await _send_raw_results(update, f"Tools Output ({category})", tool_results, file_path)

    except Exception as e:
        logger.error(f"Gagal memproses dokumen: {e}")
        await status_card.edit_text(f"❌ <b>Gagal memproses file:</b> <code>{html.escape(str(e))}</code>", parse_mode="HTML")


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Menangani pengiriman foto / gambar.
    1. AI Vision menganalisis gambar soal dengan mendalam: Konsep Soal, Kategori, Tools di VPS, & Flag.
    2. Guardrail: Jika gambar di luar konteks -> JANGAN DIBALAS (Silent drop).
    3. Jika gambar adalah tantangan Steganografi: Eksekusi tools stego paralel di VPS.
    """
    if not check_auth(update) or not update.message or not update.message.photo:
        return

    caption = update.message.caption or ""
    photo = update.message.photo[-1]
    file_id = photo.file_id
    file_name = f"photo_{file_id[:8]}.jpg"

    status_card = await update.message.reply_text(
        "<b>[ IMAGE INSPECTION ]</b>\n"
        "<code>STATUS: [1/3] Mengunduh gambar resolusi tinggi...</code>",
        parse_mode="HTML"
    )

    try:
        new_file = await context.bot.get_file(file_id)
        os.makedirs("temp_ctf", exist_ok=True)
        file_path = os.path.join("temp_ctf", file_name)
        await new_file.download_to_drive(file_path)

        ai = AIOrchestrator()

        # 1. Analisis Gambar dengan AI Vision
        if ai.is_available():
            await status_card.edit_text(
                "<b>[ AI VISION INSPECTION ]</b>\n"
                "<code>STATUS: [2/3] Membaca teks, kode, & konsep tantangan dengan AI Vision...</code>",
                parse_mode="HTML"
            )

            vision_report = await ai.analyze_challenge_image(image_path=file_path, caption=caption)

            # STRICT GUARDRAIL: Jika gambar di luar konteks, hapus pesan status dan silent drop (JANGAN DIBALAS)
            if "[OUT_OF_CONTEXT]" in vision_report:
                logger.info("[GUARDRAIL DROP] Foto/gambar di luar konteks diabaikan (tidak dibalas).")
                try:
                    await status_card.delete()
                except Exception:
                    pass
                return

            # Cek apakah ini tantangan steganografi yang perlu tools lokal di VPS
            is_stego = "stegano" in vision_report.lower() or "lsb" in vision_report.lower()
            stego_summary = ""
            if is_stego:
                await status_card.edit_text(
                    "<b>[ CONCURRENT STEGO SCAN ]</b>\n"
                    "» <b>Stego Tools:</b> <code>exiftool, strings, zsteg, steghide, binwalk</code>\n"
                    "<code>STATUS: [3/3] Menjalankan baterai tools stego di VPS serentak...</code>",
                    parse_mode="HTML"
                )
                stego_tools = ["exiftool", "strings", "binwalk", "zsteg", "steghide"]
                stego_results = await execute_concurrent_tools(stego_tools, file_path)
                stego_summary = "\n\n<b>[ VPS STEGO EXTRACTION ]</b>\n"
                for tname, tout in stego_results.items():
                    stego_summary += f"🔹 <b>{tname}:</b> <code>{html.escape(str(tout)[:200])}</code>\n"

            await status_card.edit_text(vision_report + stego_summary, parse_mode="HTML" if stego_summary else "Markdown")
        else:
            # Fallback jika AI belum aktif: Jalankan tools stego lokal di VPS
            await status_card.edit_text(
                "<b>[ RUNNING LOCAL STEGO TOOLS ]</b>\n"
                "» <b>Tools:</b> <code>exiftool, zsteg, steghide, binwalk, strings</code>\n"
                "<code>STATUS: [2/2] Memeriksa metadata & LSB...</code>",
                parse_mode="HTML"
            )
            tool_results = await execute_concurrent_tools(["exiftool", "strings", "binwalk", "zsteg", "steghide"], file_path)
            report = "<b>🖼️ Hasil Ekstraksi Tools Gambar (VPS):</b>\n\n"
            for tname, tout in tool_results.items():
                report += f"🔹 <b>{tname}:</b> <code>{html.escape(str(tout)[:300])}</code>\n\n"
            await status_card.edit_text(report, parse_mode="HTML")

    except Exception as e:
        logger.error(f"Gagal memproses gambar: {e}")
        await status_card.edit_text(f"❌ <b>Gagal memproses gambar:</b> <code>{html.escape(str(e))}</code>", parse_mode="HTML")


def main():
    """Entrypoint utama Telegram Bot."""
    if BOT_TOKEN == "GANTI_DENGAN_TOKEN_ANDA":
        print("[-] PERINGATAN: TELEGRAM_BOT_TOKEN belum diisi.")
        print("    Silakan set environment variable TELEGRAM_BOT_TOKEN atau isi langsung di script ini.")
        return

    print("[+] Menginisialisasi KIIBOT Telegram Bot Engine...")
    app = Application.builder().token(BOT_TOKEN).build()

    # Routing Command
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("soc", soc_command))
    app.add_handler(CommandHandler("triage", triage_command))
    app.add_handler(CommandHandler("tools", tools_command))
    app.add_handler(CommandHandler("findtool", findtool_command))
    app.add_handler(CommandHandler("insttools", insttools_command))
    app.add_handler(CommandHandler("doctor", doctor_command))
    app.add_handler(CommandHandler("aikeys", aikeys_command))
    app.add_handler(CommandHandler("mitre", mitre_command))
    app.add_handler(CommandHandler("decode", decode_command))
    app.add_handler(CommandHandler("analyze", analyze_command))
    app.add_handler(CommandHandler("report", report_command))
    app.add_handler(CommandHandler("reportsoc", report_command))
    # Web Attack CTF Module
    app.add_handler(CommandHandler("webattack", webattack_command))
    app.add_handler(CommandHandler("scan", scan_command))

    # Routing Callback Query (Tombol Interaktif)
    app.add_handler(CallbackQueryHandler(handle_callback_query))

    # Routing Message
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))

    # Silent drop: Abaikan semua jenis pesan non-teks/non-file yang di luar konteks
    # (voice, sticker, video note, video, animation, dsb.) — JANGAN DIBALAS
    async def _silent_drop(update: Update, context: ContextTypes.DEFAULT_TYPE):
        logger.debug("[GUARDRAIL DROP] Non-cyber media type diabaikan.")

    app.add_handler(MessageHandler(
        filters.VOICE | filters.Sticker.ALL | filters.VIDEO_NOTE | filters.ANIMATION | filters.CONTACT | filters.LOCATION,
        _silent_drop
    ))

    print("[+] KIIBOT Bot aktif & siap mendengarkan (Polling mode)...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
