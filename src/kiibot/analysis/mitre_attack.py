"""
KIIBOT MITRE ATT&CK Knowledge Base
Memetakan ID teknik MITRE ATT&CK ke Tactic, Deskripsi, Deteksi SIEM, dan Mitigasi SOC.
"""

MITRE_TECHNIQUES = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "desc": "Penyerang menyalahgunakan command dan script interpreter (PowerShell, Bash, Python) untuk mengeksekusi perintah jahat.",
        "detection": "Monitor process creation (Sysmon Event ID 1, Linux auditd/fork), baris perintah yang mencurigakan (contoh: -enc, -w hidden, curl | sh).",
        "mitigation": "Terapkan PowerShell Constrained Language Mode, script block logging, dan batasi eksekusi skrip melalui AppLocker / WDAC.",
        "related_tools": ["strace", "ltrace", "strings"]
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactic": "Defense Evasion",
        "desc": "Penyerang mendekripsi atau men-decode file, string, atau payload yang disamarkan (Base64, XOR, Hex, ROT13, Packed binary).",
        "detection": "Analisis file entropy yang tinggi, pola decoding runtime pada memori atau temporary directory (/tmp, %TEMP%).",
        "mitigation": "Inspect command-line arguments yang mencurigakan (certutil -decode, base64 -d), proteksi endpoint dengan EDR modern.",
        "related_tools": ["decode_all", "hexdump", "xxd", "binwalk", "foremost", "strings"]
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "desc": "Penyerang mengumpulkan data sensitif, file konfigurasi, atau flag dari penyimpanan lokal target.",
        "detection": "Akses massal ke folder pengguna, dokumen, database backup, atau pembacaan metadata sensitif (EXIF).",
        "mitigation": "Prinsip Least Privilege, enkripsi data at-rest, audit file integrity monitoring (FIM / Wazuh syscheck).",
        "related_tools": ["exiftool", "volatility3", "strings", "awk_top_ip"]
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "desc": "Penyerang menyamarkan konten executable atau payload untuk menghindari signature-based detection.",
        "detection": "YARA rules untuk string terkompresi, entropy analysis, alert anti-virus/EDR.",
        "mitigation": "Gunakan heuristic & behavior-based analysis (bukan hanya static signature).",
        "related_tools": ["binwalk", "xxd", "strings"]
    },
    "T1027.003": {
        "name": "Steganography",
        "tactic": "Defense Evasion",
        "desc": "Menyembunyikan pesan, file, atau payload di dalam file media lain (gambar JPEG/PNG/BMP, audio) tanpa merusak tampilan visual.",
        "detection": "Analisis anomali statistik LSB (Least Significant Bit), anomali ukuran file relatif terhadap resolusi, custom chunks di PNG.",
        "mitigation": "Content Disarm & Reconstruction (CDR), sanitasi metadata file yang diunggah ke portal publik.",
        "related_tools": ["steghide", "zsteg", "stegsolve", "pngcheck", "outguess"]
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "desc": "Mencoba password berulang kali (dictionary attack, credential stuffing, password spraying) untuk menembus autentikasi.",
        "detection": "SIEM alert pada lonjakan Event ID 4625 (Failed Logon) di Windows atau 'Failed password' di /var/log/auth.log.",
        "mitigation": "Account lockout policy, Multi-Factor Authentication (MFA), rate limiting IP pada login gateway.",
        "related_tools": ["hashid", "john", "hashcat"]
    },
    "T1110.002": {
        "name": "Password Cracking",
        "tactic": "Credential Access",
        "desc": "Memecahkan hash password offline menggunakan wordlist (rockyou) dan akselerasi GPU.",
        "detection": "Pencurian file SAM/NTDS.dit atau /etc/shadow mendahului cracking offline.",
        "mitigation": "Gunakan algoritma hashing modern yang lambat (Argon2id, bcrypt, PBKDF2), cegah privilege escalation ke kredensial sistem.",
        "related_tools": ["john", "hashcat", "hashid"]
    },
    "T1040": {
        "name": "Network Sniffing",
        "tactic": "Credential Access / Discovery",
        "desc": "Merekam paket jaringan untuk menguping kredensial cleartext (HTTP, FTP, Telnet) atau informasi sensitif.",
        "detection": "Deteksi interface network yang berjalan dalam Promiscuous Mode pada host kritis.",
        "mitigation": "Enkripsi semua saluran komunikasi (HTTPS/TLS, SSH, IPsec), segmentasi jaringan VLAN.",
        "related_tools": ["tshark", "tshark_http", "tshark_follow", "tcpdump"]
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "desc": "Memindai port dan layanan aktif di target (port scanning / host discovery).",
        "detection": "Log firewall/IDS (Suricata/Snort) mendeteksi SYN flood, sequential port probes.",
        "mitigation": "Drop scanning packet di edge firewall, nonaktifkan layanan yang tidak diperlukan (hardened attack surface).",
        "related_tools": ["nmap", "tshark"]
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "desc": "Mengeksploitasi celah web (SQL Injection, Command Injection, SSRF, RFI) pada aplikasi yang terekspos ke internet.",
        "detection": "WAF log mendeteksi payload SQLi (UNION SELECT, OR 1=1), Web Access log 4xx/5xx errors abnormal.",
        "mitigation": "Input validation, parameterized queries (Prepared Statements), WAF virtual patching, regular patching.",
        "related_tools": ["sqlmap", "nikto", "grep_sqli", "grep_xss"]
    },
    "T1071.001": {
        "name": "Web Protocols (C2 Traffic)",
        "tactic": "Command and Control",
        "desc": "Menggunakan protokol HTTP/HTTPS umum untuk menyamarkan komunikasi C2 (Command & Control).",
        "detection": "Analisis beaconing interval reguler pada proxy/firewall log, request ke domain baru (Newly Registered Domains).",
        "mitigation": "Web proxy filtering, TLS inspection, DNS sinkholing untuk malicious domain.",
        "related_tools": ["tshark_http", "grep_useragent", "curl"]
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "desc": "Mencari informasi spesifik arsitektur OS, patch level, hostname, dan versi kernel.",
        "detection": "Eksekusi command seperti uname -a, systeminfo, ver, cat /etc/os-release.",
        "mitigation": "Minimalkan akses terminal untuk unprivileged users, monitor abnormal audit logs.",
        "related_tools": ["file", "checksec", "wazuh_agent_check"]
    },
    "T1595.002": {
        "name": "Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "desc": "Pemindaian otomatis untuk mencari kerentanan web atau CMS yang diketahui (Nikto, Nuclei).",
        "detection": "User-Agent scanner di access log, ribuan request 404 dalam rentang waktu singkat.",
        "mitigation": "Blokir user-agent scanner di WAF/Nginx, terapkan IP reputation feed.",
        "related_tools": ["nikto", "gobuster"]
    },
    "T1592.004": {
        "name": "Client Configurations (Public Code Leaks)",
        "tactic": "Reconnaissance",
        "desc": "Pencarian rahasia (API key, password, token) yang bocor di repository publik (GitHub, GitLab).",
        "detection": "GitHub secret scanning alert, SIEM alert mendeteksi penggunaan API key dari IP asing.",
        "mitigation": "Secret scanner di pipeline CI/CD (TruffleHog, GitLeaks), git-secrets, rotasi kredensial segera jika bocor.",
        "related_tools": ["trufflehog", "gitleaks"]
    }
}

def lookup_mitre(technique_id: str) -> dict | None:
    """Mencari informasi teknik MITRE berdasarkan ID (misal T1140, T1059)."""
    clean_id = technique_id.strip().upper()
    if clean_id in MITRE_TECHNIQUES:
        data = MITRE_TECHNIQUES[clean_id].copy()
        data["id"] = clean_id
        return data
    
    # Cek tanpa sub-technique jika tidak ketemu
    if "." in clean_id:
        parent_id = clean_id.split(".")[0]
        if parent_id in MITRE_TECHNIQUES:
            data = MITRE_TECHNIQUES[parent_id].copy()
            data["id"] = f"{clean_id} (Parent: {parent_id})"
            return data

    return None

def get_all_techniques() -> list[str]:
    """Mengembalikan daftar semua ID teknik yang didukung."""
    return list(MITRE_TECHNIQUES.keys())
