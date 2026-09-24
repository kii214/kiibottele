"""
KIIBOT Tool Registry PRO — 85+ Tools CTF & SOC
Kategori: Forensics, Steganography, Cryptography, Network/PCAP,
           Log Analysis, Web Exploitation, RE/Pwn, OSINT,
           GitHub Leaks, SOC Triage, SIEM, Threat Intel,
           Password Attacks, Wireless, Exploit Dev, Container Sec,
           Cloud & AWS Recon, IDS/IPS, Malware Analysis
"""

# ================================================================
# TOOL REGISTRY PRO — 85+ Tools CTF & SOC
# ================================================================

TOOL_REGISTRY = {

    # ============================================================
    # KATEGORI 1: FORENSICS & STEGANOGRAPHY
    # ============================================================
    "forensics": {
        "file": {
            "cmd": ["file"],
            "args_append_target": True,
            "desc": "Identifikasi tipe file berdasarkan magic bytes. Langkah PERTAMA untuk setiap file CTF.",
            "output_limit": 1000,
            "when_to_use": "SELALU dijalankan pertama kali pada sembarang file yang dikirim.",
            "mitre_technique": "T1082",
            "sop_step": "SOC-FOR-001: Initial File Triage"
        },
        "strings": {
            "cmd": ["strings", "-n", "6"],
            "args_append_target": True,
            "desc": "Ekstrak semua string printable dari binary/file. Sering langsung menemukan flag tersembunyi.",
            "output_limit": 3000,
            "when_to_use": "File binary ELF, PDF, DOCX, gambar.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-FOR-002: String Extraction"
        },
        "exiftool": {
            "cmd": ["exiftool"],
            "args_append_target": True,
            "desc": "Baca semua metadata EXIF dari file (gambar, PDF, DOCX). Flag sering tersembunyi di metadata.",
            "output_limit": 2000,
            "when_to_use": "Gambar JPEG/PNG, PDF, file Office.",
            "mitre_technique": "T1005",
            "sop_step": "SOC-FOR-003: Metadata Analysis"
        },
        "hexdump": {
            "cmd": ["hexdump", "-C"],
            "args_append_target": True,
            "desc": "Tampilkan isi file dalam format hex + ASCII. Berguna untuk menemukan header file palsu.",
            "output_limit": 3000,
            "when_to_use": "File rusak/korup, file dengan ekstensi salah, file unknown.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-FOR-004: Hex Analysis"
        },
        "xxd": {
            "cmd": ["xxd"],
            "args_append_target": True,
            "desc": "Alternatif hexdump dengan tampilan lebih rapi. Wajib untuk analisis header file.",
            "output_limit": 3000,
            "when_to_use": "Analisis hex untuk menemukan flag atau magic bytes tersembunyi.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-FOR-004: Hex Analysis"
        },
        "binwalk": {
            "cmd": ["binwalk", "-e", "-M"],
            "args_append_target": True,
            "desc": "Scan dan ekstrak file tersembunyi di dalam file lain (file carving). Tool wajib forensics.",
            "output_limit": 2000,
            "when_to_use": "Gambar atau binary yang dicurigai menyembunyikan file di dalamnya.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-FOR-005: File Carving"
        },
        "foremost": {
            "cmd": ["foremost", "-o", "/tmp/foremost_out"],
            "args_append_target": True,
            "desc": "File carving berdasarkan header & footer. Alternatif binwalk untuk recovery file.",
            "output_limit": 1500,
            "when_to_use": "Disk image, binary yang menyimpan banyak file tersembunyi.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-FOR-005: File Carving"
        },
        "volatility3": {
            "cmd": ["vol3", "-f"],
            "args_append_target": True,
            "desc": "Analisis memory dump (RAM forensics). Digunakan untuk mencari proses, koneksi jaringan, dan kredensial di RAM.",
            "output_limit": 3000,
            "timeout": 60.0,
            "when_to_use": "File .mem, .dmp, .vmem — soal Memory Forensics.",
            "mitre_technique": "T1005",
            "sop_step": "SOC-MEM-001: Memory Triage"
        },
        "vol_pslist": {
            "cmd": ["vol3", "-f", None, "windows.pslist.PsList"],
            "args_target_index": 2,
            "desc": "Volatility3: Daftar semua proses yang sedang berjalan di memory dump Windows.",
            "output_limit": 3000,
            "timeout": 90.0,
            "when_to_use": "Memory dump Windows — mencari proses mencurigakan (malware, injected DLL).",
            "mitre_technique": "T1005",
            "sop_step": "SOC-MEM-002: Process Analysis"
        },
        "vol_netscan": {
            "cmd": ["vol3", "-f", None, "windows.netscan.NetScan"],
            "args_target_index": 2,
            "desc": "Volatility3: Scan koneksi jaringan aktif dan listening ports di memory dump Windows.",
            "output_limit": 3000,
            "timeout": 90.0,
            "when_to_use": "Memory dump Windows — menemukan koneksi C2, reverse shell, atau beaconing.",
            "mitre_technique": "T1040",
            "sop_step": "SOC-MEM-003: Network Artifact Analysis"
        },
        "vol_cmdline": {
            "cmd": ["vol3", "-f", None, "windows.cmdline.CmdLine"],
            "args_target_index": 2,
            "desc": "Volatility3: Ekstrak command line dari setiap proses. Menemukan perintah berbahaya yang dijalankan.",
            "output_limit": 3000,
            "timeout": 90.0,
            "when_to_use": "Memory dump Windows — audit command line untuk detect living-off-the-land attacks.",
            "mitre_technique": "T1059",
            "sop_step": "SOC-MEM-004: Command Line Audit"
        },
        "vol_dumpfiles": {
            "cmd": ["vol3", "-f", None, "windows.dumpfiles.DumpFiles", "--output-dir", "/tmp/vol_dump"],
            "args_target_index": 2,
            "desc": "Volatility3: Dump file artifact dari memory (DLL, executable, dokumen) untuk analisis lebih lanjut.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "Memory dump Windows — ekstrak file tersembunyi atau malware yang berjalan di memori.",
            "mitre_technique": "T1005",
            "sop_step": "SOC-MEM-005: Artifact Extraction"
        },
        "pdf_parser": {
            "cmd": ["pdf-parser", "--stats"],
            "args_append_target": True,
            "desc": "Parse dan analisis struktur file PDF untuk menemukan payload embedded, JavaScript, atau objek tersembunyi.",
            "output_limit": 3000,
            "timeout": 20.0,
            "when_to_use": "File PDF — forensics dokumen CTF atau malware dropper berbasis PDF.",
            "mitre_technique": "T1027",
            "sop_step": "SOC-FOR-006: Document Analysis"
        },
        "oletools": {
            "cmd": ["bash", "-c", "olevba %TARGET% 2>&1 | head -100"],
            "args_template": True,
            "desc": "Analisis macro VBA berbahaya dalam file Office (DOCX, XLSM, PPTM). Deteksi phishing macro dropper.",
            "output_limit": 3000,
            "timeout": 30.0,
            "when_to_use": "File Office DOCX/XLSM yang berisi macro VBA mencurigakan.",
            "mitre_technique": "T1204.002",
            "sop_step": "SOC-FOR-007: Macro Analysis"
        },
        "yara_scan": {
            "cmd": ["bash", "-c", "yara /usr/share/yara-rules/*.yar %TARGET% 2>&1"],
            "args_template": True,
            "desc": "Scan file dengan YARA rules untuk deteksi malware, exploit kit, dan IoC yang dikenal.",
            "output_limit": 3000,
            "timeout": 30.0,
            "when_to_use": "Binary atau file mencurigakan — mencocokkan dengan signature malware yang dikenal.",
            "mitre_technique": "T1027",
            "sop_step": "SOC-MAL-001: Malware Signature Scan"
        },
        "bulk_extractor": {
            "cmd": ["bulk_extractor", "-o", "/tmp/bulk_out"],
            "args_append_target": True,
            "desc": "Ekstrak data sensitif (email, URL, kredensial, nomor kartu) dari disk image atau file besar.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "Disk image forensics — mencari PII, credential, atau IoC dalam jumlah besar.",
            "mitre_technique": "T1005",
            "sop_step": "SOC-FOR-008: Bulk Data Extraction"
        },
    },

    # ============================================================
    # KATEGORI 2: STEGANOGRAPHY
    # ============================================================
    "steganography": {
        "steghide": {
            "cmd": ["steghide", "info", "-p", ""],
            "args_append_target": True,
            "desc": "Cek dan ekstrak payload tersembunyi di JPEG/BMP menggunakan passphrase.",
            "output_limit": 1000,
            "timeout": 15.0,
            "when_to_use": "File JPEG atau BMP yang dicurigai menyimpan pesan tersembunyi.",
            "mitre_technique": "T1027.003",
            "sop_step": "SOC-STEG-001: JPEG Stego Analysis"
        },
        "stegseek": {
            "cmd": ["stegseek", "--crack"],
            "args_append_target": True,
            "desc": "Fast steghide cracker menggunakan wordlist rockyou. Jauh lebih cepat dari steghide brute-force manual.",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "JPEG/BMP yang terpassword — crack passphrase secara otomatis.",
            "mitre_technique": "T1027.003",
            "sop_step": "SOC-STEG-002: Stego Passphrase Crack"
        },
        "zsteg": {
            "cmd": ["zsteg", "-a"],
            "args_append_target": True,
            "desc": "Deteksi dan ekstrak payload tersembunyi di PNG/BMP menggunakan berbagai teknik LSB.",
            "output_limit": 2000,
            "timeout": 20.0,
            "when_to_use": "File PNG — tool utama untuk LSB steganography.",
            "mitre_technique": "T1027.003",
            "sop_step": "SOC-STEG-003: PNG LSB Analysis"
        },
        "pngcheck": {
            "cmd": ["pngcheck", "-v"],
            "args_append_target": True,
            "desc": "Validasi integritas file PNG dan deteksi chunk tersembunyi.",
            "output_limit": 2000,
            "when_to_use": "File PNG — mencari custom chunk data yang tidak standar.",
            "mitre_technique": "T1027.003",
            "sop_step": "SOC-STEG-004: PNG Chunk Analysis"
        },
        "stegsnow": {
            "cmd": ["stegsnow", "-C"],
            "args_append_target": True,
            "desc": "Ekstraksi whitespace steganography tersembunyi pada file teks / code.",
            "output_limit": 2000,
            "when_to_use": "File teks, source code, ASCII art dengan whitespace mencurigakan.",
            "mitre_technique": "T1027.003",
            "sop_step": "SOC-STEG-005: Whitespace Stego"
        },
        "zbarimg": {
            "cmd": ["zbarimg", "--raw"],
            "args_append_target": True,
            "desc": "Scan & decode QR code atau barcode langsung dari gambar CTF.",
            "output_limit": 1000,
            "when_to_use": "Gambar berisi QR code / Barcode.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-STEG-006: QR/Barcode Decode"
        },
        "tesseract": {
            "cmd": ["tesseract", None, "stdout"],
            "args_target_index": 1,
            "desc": "Optical Character Recognition (OCR) — ekstrak teks/flag dari gambar soal CTF.",
            "output_limit": 2000,
            "when_to_use": "Gambar teks yang sulit dicopy.",
            "mitre_technique": "T1005",
            "sop_step": "SOC-STEG-007: OCR Extraction"
        },
        "outguess": {
            "cmd": ["outguess", "-r"],
            "args_append_target": True,
            "desc": "Ekstraksi pesan tersembunyi menggunakan algoritma outguess.",
            "output_limit": 1000,
            "when_to_use": "JPEG yang dicurigai menggunakan outguess untuk menyembunyikan data.",
            "mitre_technique": "T1027.003",
            "sop_step": "SOC-STEG-008: Outguess Extract"
        },
        "jsteg": {
            "cmd": ["bash", "-c", "cat %TARGET% | strings | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$' | base64 -d 2>/dev/null"],
            "args_template": True,
            "desc": "Extrak base64 strings tersembunyi dalam JPEG menggunakan teknik jsteg analisis.",
            "output_limit": 2000,
            "when_to_use": "JPEG CTF yang diduga menggunakan jsteg embedding.",
            "mitre_technique": "T1027.003",
            "sop_step": "SOC-STEG-009: JPEG Base64 Extract"
        },
    },

    # ============================================================
    # KATEGORI 3: CRYPTOGRAPHY
    # ============================================================
    "cryptography": {
        "hashid": {
            "cmd": ["hashid"],
            "args_append_target": True,
            "desc": "Identifikasi tipe hash (MD5, SHA1, SHA256, bcrypt, dll).",
            "output_limit": 500,
            "timeout": 10.0,
            "when_to_use": "Diberikan sebuah string hash, identifikasi jenisnya sebelum cracking.",
            "mitre_technique": "T1110",
            "sop_step": "SOC-CRYPTO-001: Hash Identification"
        },
        "hash_identifier": {
            "cmd": ["hash-identifier"],
            "args_append_target": True,
            "desc": "Alternatif hashid untuk identifikasi format hash.",
            "output_limit": 500,
            "timeout": 10.0,
            "when_to_use": "Identifikasi hash yang tidak jelas formatnya.",
            "mitre_technique": "T1110",
            "sop_step": "SOC-CRYPTO-001: Hash Identification"
        },
        "john": {
            "cmd": ["john", "--wordlist=/usr/share/wordlists/rockyou.txt"],
            "args_append_target": True,
            "desc": "Password/Hash cracker menggunakan wordlist. Gunakan rockyou.txt untuk CTF.",
            "output_limit": 1000,
            "timeout": 120.0,
            "when_to_use": "File hash, file ZIP terpassword, file SSH key terenkripsi.",
            "mitre_technique": "T1110.002",
            "sop_step": "SOC-CRYPTO-002: Hash Cracking"
        },
        "hashcat": {
            "cmd": ["hashcat", "-a", "0", "-m", "0"],
            "args_append_target": False,
            "desc": "GPU-accelerated hash cracker. Jauh lebih cepat dari john untuk hash yang kuat.",
            "output_limit": 1000,
            "timeout": 120.0,
            "when_to_use": "Hash MD5/SHA256 yang perlu di-crack dengan GPU.",
            "mitre_technique": "T1110.002",
            "sop_step": "SOC-CRYPTO-002: Hash Cracking GPU"
        },
        "openssl": {
            "cmd": ["openssl", "enc", "-d", "-base64", "-in"],
            "args_append_target": True,
            "desc": "Enkripsi/Dekripsi OpenSSL (base64, AES, RSA). Swiss-army knife kriptografi.",
            "output_limit": 1000,
            "timeout": 15.0,
            "when_to_use": "Data terenkripsi dengan library OpenSSL standar, sertifikat, RSA key.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-CRYPTO-003: OpenSSL Decrypt"
        },
        "rsactftool": {
            "cmd": ["RsaCtfTool.py", "--publickey"],
            "args_append_target": True,
            "desc": "Toolkit otomatis untuk mengeksploitasi kelemahan RSA CTF (small-e, wiener, dll).",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "Soal RSA CTF — diberikan public key dan ciphertext untuk didekripsi.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-CRYPTO-004: RSA Attack"
        },
        "jwt_tool": {
            "cmd": ["jwt_tool"],
            "args_append_target": True,
            "desc": "Analisis dan uji kerentanan JWT (none algorithm, weak secret, RS256->HS256 confusion).",
            "output_limit": 2000,
            "timeout": 20.0,
            "when_to_use": "JWT token — soal Web CTF atau SOC yang menemukan token mencurigakan.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-CRYPTO-005: JWT Analysis"
        },
        "gpg": {
            "cmd": ["gpg", "--list-packets"],
            "args_append_target": True,
            "desc": "Analisis struktur file GPG terenkripsi untuk menemukan informasi cipher dan recipient.",
            "output_limit": 1000,
            "timeout": 15.0,
            "when_to_use": "File .gpg atau .asc terenkripsi untuk CTF crypto.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-CRYPTO-006: GPG Analysis"
        },
        "fcrackzip": {
            "cmd": ["fcrackzip", "-u", "-D", "-p", "/usr/share/wordlists/rockyou.txt"],
            "args_append_target": True,
            "desc": "Crack password arsip ZIP terproteksi menggunakan dictionary attack.",
            "output_limit": 1000,
            "timeout": 120.0,
            "when_to_use": "File ZIP berpassword — crack password menggunakan wordlist CTF.",
            "mitre_technique": "T1110.002",
            "sop_step": "SOC-CRYPTO-007: ZIP Password Crack"
        },
    },

    # ============================================================
    # KATEGORI 4: NETWORK & PCAP
    # ============================================================
    "network": {
        "tshark": {
            "cmd": ["tshark", "-r"],
            "args_append_target": True,
            "desc": "CLI version of Wireshark. Analisis PCAP dari command line. Tool utama untuk soal network.",
            "output_limit": 3000,
            "when_to_use": "Semua file .pcap atau .pcapng.",
            "mitre_technique": "T1040",
            "sop_step": "SOC-NET-001: PCAP Triage"
        },
        "tshark_http": {
            "cmd": ["tshark", "-r", None, "-Y", "http", "-T", "fields",
                    "-e", "http.request.method", "-e", "http.request.uri",
                    "-e", "http.response.code", "-e", "http.file_data"],
            "args_target_index": 2,
            "desc": "Filter dan ekstrak konten HTTP dari PCAP (URL, form data, payload, response code).",
            "output_limit": 3000,
            "when_to_use": "PCAP dengan traffic HTTP — mencari credential, flag dalam HTTP request/response.",
            "mitre_technique": "T1040",
            "sop_step": "SOC-NET-002: HTTP Traffic Analysis"
        },
        "tshark_follow": {
            "cmd": ["tshark", "-r", None, "-q", "-z", "follow,tcp,ascii,0"],
            "args_target_index": 2,
            "desc": "Ikuti TCP stream penuh untuk melihat percakapan lengkap dalam PCAP.",
            "output_limit": 3000,
            "when_to_use": "PCAP dengan data yang perlu dilihat sebagai satu sesi komunikasi utuh.",
            "mitre_technique": "T1040",
            "sop_step": "SOC-NET-003: TCP Stream Reconstruction"
        },
        "tshark_dns": {
            "cmd": ["tshark", "-r", None, "-Y", "dns", "-T", "fields",
                    "-e", "dns.qry.name", "-e", "dns.resp.addr"],
            "args_target_index": 2,
            "desc": "Ekstrak semua query dan response DNS dari PCAP. Detect DNS tunneling atau C2 via DNS.",
            "output_limit": 3000,
            "when_to_use": "PCAP — mencari DNS tunneling, data exfiltration via DNS, atau C2 domain.",
            "mitre_technique": "T1071.004",
            "sop_step": "SOC-NET-004: DNS Analysis"
        },
        "tshark_creds": {
            "cmd": ["tshark", "-r", None, "-Y",
                    "ftp || pop || imap || http.authbasic",
                    "-T", "fields", "-e", "ftp.request.arg",
                    "-e", "http.authorization"],
            "args_target_index": 2,
            "desc": "Ekstrak kredensial cleartext dari PCAP (FTP, POP3, IMAP, HTTP Basic Auth).",
            "output_limit": 2000,
            "when_to_use": "PCAP yang mungkin mengandung password dalam plaintext.",
            "mitre_technique": "T1040",
            "sop_step": "SOC-NET-005: Credential Extraction"
        },
        "tcpdump": {
            "cmd": ["tcpdump", "-r"],
            "args_append_target": True,
            "desc": "Analisis PCAP cepat dengan filter packet yang fleksibel.",
            "output_limit": 2000,
            "when_to_use": "Analisis ringkas PCAP untuk menemukan paket anomali.",
            "mitre_technique": "T1040",
            "sop_step": "SOC-NET-006: Quick Packet Analysis"
        },
        "nmap": {
            "cmd": ["nmap", "-sV", "-sC", "--script=default,vuln", "-oN", "/tmp/nmap_scan.txt"],
            "args_append_target": True,
            "target_type": "host",
            "desc": "Port scanner & service fingerprinting + vulnerability detection scripts. Tool utama recon.",
            "output_limit": 3000,
            "when_to_use": "Soal network yang memberikan alamat IP target yang diizinkan.",
            "mitre_technique": "T1046",
            "sop_step": "SOC-RECON-001: Port & Service Discovery"
        },
        "nmap_os": {
            "cmd": ["nmap", "-O", "--osscan-guess"],
            "args_append_target": True,
            "target_type": "host",
            "desc": "Deteksi sistem operasi target menggunakan nmap OS fingerprinting.",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "Identifikasi OS target sebelum pemilihan exploit spesifik.",
            "mitre_technique": "T1592.001",
            "sop_step": "SOC-RECON-002: OS Fingerprinting"
        },
        "masscan": {
            "cmd": ["masscan", "--rate=1000", "-p", "1-65535"],
            "args_append_target": True,
            "desc": "Ultra-fast port scanner. Lebih cepat dari nmap untuk scan seluruh port secara cepat.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "Scan semua 65535 port pada IP target dengan kecepatan tinggi.",
            "mitre_technique": "T1046",
            "sop_step": "SOC-RECON-003: Full Port Scan"
        },
        "netstat_live": {
            "cmd": ["bash", "-c", "netstat -tulnp 2>/dev/null | head -50"],
            "args_append_target": False,
            "desc": "Tampilkan semua koneksi jaringan aktif dan port yang sedang listening di VPS.",
            "output_limit": 2000,
            "when_to_use": "SOC triage lokal — memeriksa layanan yang berjalan dan koneksi mencurigakan.",
            "mitre_technique": "T1049",
            "sop_step": "SOC-NET-007: Active Connection Audit"
        },
        "ss_sockets": {
            "cmd": ["bash", "-c", "ss -tulnp | head -60"],
            "args_append_target": False,
            "desc": "Modern replacement netstat — tampilkan socket statistics dan listening services.",
            "output_limit": 2000,
            "when_to_use": "Audit socket aktif di sistem Linux (lebih cepat dari netstat).",
            "mitre_technique": "T1049",
            "sop_step": "SOC-NET-007: Socket Analysis"
        },
    },

    # ============================================================
    # KATEGORI 5: LOG ANALYSIS
    # ============================================================
    "log_analysis": {
        "grep_ip": {
            "cmd": ["grep", "-oE", r"\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"],
            "args_append_target": True,
            "desc": "Ekstrak semua alamat IP dari file log.",
            "output_limit": 2000,
            "when_to_use": "File log akses web (nginx/apache) untuk mencari IP sumber serangan.",
            "mitre_technique": "T1005",
            "sop_step": "SOC-LOG-001: IP Extraction"
        },
        "awk_top_ip": {
            "cmd": ["bash", "-c", "awk '{print $1}' %TARGET% | sort | uniq -c | sort -rn | head -20"],
            "args_template": True,
            "desc": "Temukan 20 IP dengan jumlah request terbanyak dari log NGINX/Apache. Cocok untuk soal DoS.",
            "output_limit": 1000,
            "when_to_use": "Log file nginx/apache — mencari IP penyerang (soal DoS/DDoS di slide).",
            "mitre_technique": "T1498",
            "sop_step": "SOC-LOG-002: Top Attacker IPs"
        },
        "grep_useragent": {
            "cmd": ["bash", "-c", "grep -oP '\"([^\"]+)\"\\s+[0-9]+\\s+[0-9]+' %TARGET% | awk '{print $NF}' | sort | uniq -c | sort -rn | head -20"],
            "args_template": True,
            "desc": "Identifikasi User-Agent paling sering muncul di log. Bot/scanner biasanya sangat repetitif.",
            "output_limit": 1000,
            "when_to_use": "Log file web — mencari User-Agent mencurigakan (curl, python-requests, bot scanner).",
            "mitre_technique": "T1071.001",
            "sop_step": "SOC-LOG-003: User-Agent Analysis"
        },
        "grep_sqli": {
            "cmd": ["grep", "-iE", r"(union|select|insert|drop|or\s+1=1|'--|benchmark|sleep\(|waitfor|concat\(|char\()", "--color=always"],
            "args_append_target": True,
            "desc": "Cari payload SQL Injection di log. Deteksi serangan SQLi seperti yang ada di slide.",
            "output_limit": 2000,
            "when_to_use": "Log web server — mencari payload SQLi (OR 1=1, UNION SELECT, dsb).",
            "mitre_technique": "T1190",
            "sop_step": "SOC-LOG-004: SQLi Detection"
        },
        "grep_xss": {
            "cmd": ["grep", "-iE", r"(<script|onerror|onload|javascript:|alert\(|document\.cookie|eval\(|fromCharCode)", "--color=always"],
            "args_append_target": True,
            "desc": "Cari payload XSS di dalam log akses web.",
            "output_limit": 2000,
            "when_to_use": "Log web server — mencari upaya serangan Cross-Site Scripting.",
            "mitre_technique": "T1190",
            "sop_step": "SOC-LOG-005: XSS Detection"
        },
        "grep_lfi": {
            "cmd": ["grep", "-iE", r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|php://filter|php://input|phar://)", "--color=always"],
            "args_append_target": True,
            "desc": "Deteksi upaya Local File Inclusion (LFI) / Path Traversal dalam log web.",
            "output_limit": 2000,
            "when_to_use": "Log web server — mencari payload LFI atau directory traversal.",
            "mitre_technique": "T1190",
            "sop_step": "SOC-LOG-006: LFI Detection"
        },
        "grep_rce": {
            "cmd": ["grep", "-iE", r"(cmd=|exec=|system\(|passthru|shell_exec|`|%60|;ls|;id|;cat|;whoami|;wget|;curl)", "--color=always"],
            "args_append_target": True,
            "desc": "Deteksi upaya Remote Code Execution (RCE) dalam log request.",
            "output_limit": 2000,
            "when_to_use": "Log web — mencari RCE attempt melalui command injection.",
            "mitre_technique": "T1190",
            "sop_step": "SOC-LOG-007: RCE Detection"
        },
        "log_status_count": {
            "cmd": ["bash", "-c", "awk '{print $9}' %TARGET% | sort | uniq -c | sort -rn | head -20"],
            "args_template": True,
            "desc": "Hitung distribusi HTTP status code dari log (200, 301, 404, 500). Identifikasi anomali.",
            "output_limit": 1000,
            "when_to_use": "Log nginx/apache — melihat distribusi response code untuk deteksi scan/brute.",
            "mitre_technique": "T1595.002",
            "sop_step": "SOC-LOG-008: Status Code Analysis"
        },
        "grep_auth_fail": {
            "cmd": ["grep", "-iE", r"(failed|failure|invalid|incorrect|wrong|unauthorized|denied|bad password|authentication error)", "--color=always"],
            "args_append_target": True,
            "desc": "Ekstrak semua baris log yang menunjukkan kegagalan autentikasi. Deteksi brute-force.",
            "output_limit": 2000,
            "when_to_use": "Log auth/syslog — identifikasi brute-force atau credential stuffing.",
            "mitre_technique": "T1110",
            "sop_step": "SOC-LOG-009: Auth Failure Analysis"
        },
        "journalctl_security": {
            "cmd": ["bash", "-c", "journalctl -u ssh --since '1 hour ago' --no-pager 2>/dev/null | grep -iE '(failed|accepted|invalid|error)' | tail -50"],
            "args_append_target": False,
            "desc": "Ambil log SSH terbaru dari journald — deteksi brute-force SSH dalam 1 jam terakhir.",
            "output_limit": 2000,
            "when_to_use": "Audit SSH login di server Linux — deteksi intrusion attempt.",
            "mitre_technique": "T1110.001",
            "sop_step": "SOC-LOG-010: SSH Audit"
        },
    },

    # ============================================================
    # KATEGORI 6: WEB EXPLOITATION
    # ============================================================
    "web": {
        "curl": {
            "cmd": ["curl", "-v", "-L", "--max-time", "15", "-A", "Mozilla/5.0"],
            "args_append_target": True,
            "desc": "HTTP client verbose — analisis response header, cookie, redirect, dan konten web secara manual.",
            "output_limit": 3000,
            "timeout": 20.0,
            "when_to_use": "URL target web CTF — cek header, redirect, dan isi halaman.",
            "mitre_technique": "T1071.001",
            "sop_step": "SOC-WEB-001: HTTP Recon"
        },
        "whatweb": {
            "cmd": ["whatweb", "--no-errors", "-a", "3"],
            "args_append_target": True,
            "desc": "Fingerprint teknologi web: CMS, framework, server, versi. Langkah awal wajib sebelum attack.",
            "output_limit": 2000,
            "timeout": 30.0,
            "when_to_use": "URL target web — identifikasi WordPress, PHP, Apache, Nginx, framework, dll.",
            "mitre_technique": "T1592.002",
            "sop_step": "SOC-WEB-002: Tech Stack Fingerprint"
        },
        "wafw00f": {
            "cmd": ["wafw00f"],
            "args_append_target": True,
            "desc": "Deteksi Web Application Firewall (WAF). Penting sebelum SQLi/XSS attack untuk tahu ada proteksi atau tidak.",
            "output_limit": 1500,
            "timeout": 30.0,
            "when_to_use": "URL target sebelum attack — cek apakah ada Cloudflare, ModSecurity, AWS WAF, dll.",
            "mitre_technique": "T1595.002",
            "sop_step": "SOC-WEB-003: WAF Detection"
        },
        "sqlmap": {
            "cmd": ["sqlmap", "-u", None, "--batch", "--level=3", "--risk=2", "--threads=4"],
            "args_target_index": 2,
            "desc": "Automated SQL Injection tool (level=3 untuk deteksi lebih komprehensif). HANYA untuk target yang diizinkan.",
            "output_limit": 2000,
            "timeout": 300.0,
            "when_to_use": "URL dengan parameter GET/POST yang dicurigai vulnerable terhadap SQLi.",
            "mitre_technique": "T1190",
            "sop_step": "SOC-WEB-004: SQLi Scan"
        },
        "sqlmap_full": {
            "cmd": ["sqlmap", "-u", None, "--batch", "--level=5", "--risk=3", "--threads=4",
                    "--dbs", "--dump-all", "--exclude-sysdbs", "--forms"],
            "args_target_index": 2,
            "desc": "SQLmap mode FULL: enumerate semua database, dump tabel users, cari username & password.",
            "output_limit": 3000,
            "timeout": 600.0,
            "when_to_use": "Soal CTF SQLi — dump semua data termasuk tabel users, kredensial, dan flag.",
            "mitre_technique": "T1190",
            "sop_step": "SOC-WEB-004: SQLi Full Dump"
        },
        "nikto": {
            "cmd": ["nikto", "-h"],
            "args_append_target": True,
            "desc": "Web vulnerability scanner yang mencari misconfiguration dan celah umum.",
            "output_limit": 2000,
            "timeout": 180.0,
            "when_to_use": "URL target web CTF untuk menemukan direktori tersembunyi, celah default.",
            "mitre_technique": "T1595.002",
            "sop_step": "SOC-WEB-005: Web Vuln Scan"
        },
        "gobuster": {
            "cmd": ["gobuster", "dir", "-u", None, "-w", "%DIR_WORDLIST%",
                    "-q", "-t", "50", "-k", "--status-codes", "200,301,302,403,500"],
            "args_target_index": 3,
            "desc": "Directory/endpoint brute-forcer cepat (50 threads) untuk menemukan halaman tersembunyi.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "URL target web CTF — mencari direktori tersembunyi seperti /admin, /backup, /flag.",
            "mitre_technique": "T1595.003",
            "sop_step": "SOC-WEB-006: Directory Enumeration"
        },
        "ffuf": {
            "cmd": ["ffuf", "-u", "%TARGET%/FUZZ", "-w", "%DIR_WORDLIST%:FUZZ",
                    "-mc", "200,301,302,403", "-c", "-s"],
            "args_template": True,
            "desc": "Fast web fuzzer — support FUZZ placeholder untuk directory, parameter, dan vhost.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "Web fuzzing untuk directory, parameter, atau virtual host enumeration.",
            "mitre_technique": "T1595.003",
            "sop_step": "SOC-WEB-006: Web Fuzzing"
        },
        "dirb": {
            "cmd": ["dirb", None, "%DIR_WORDLIST%", "-S", "-r"],
            "args_target_index": 1,
            "desc": "Directory brute-forcer klasik. Output verbose dengan detail kode HTTP response.",
            "output_limit": 2000,
            "timeout": 90.0,
            "when_to_use": "Alternatif gobuster untuk detail response HTTP per direktori.",
            "mitre_technique": "T1595.003",
            "sop_step": "SOC-WEB-006: Directory Enumeration Alt"
        },
        "hydra_http_get": {
            "cmd": ["hydra", "-L", "/usr/share/wordlists/ctf_mini.txt", "-P",
                    "/usr/share/wordlists/ctf_mini.txt", "-t", "4", "-f"],
            "args_append_target": True,
            "desc": "Hydra: Login brute-force HTTP Basic Auth menggunakan CTF mini-wordlist.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "Target HTTP Basic Auth — coba kombinasi username & password umum CTF.",
            "mitre_technique": "T1110.001",
            "sop_step": "SOC-WEB-007: HTTP Brute-Force"
        },
        "hydra_ssh": {
            "cmd": ["hydra", "-L", "/usr/share/wordlists/ctf_mini.txt", "-P",
                    "/usr/share/wordlists/ctf_mini.txt", "-t", "4", "-f", "-s", "22"],
            "args_append_target": True,
            "desc": "Hydra: SSH login brute-force menggunakan CTF mini-wordlist.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "Target SSH yang diizinkan — coba kombinasi username & password umum CTF.",
            "mitre_technique": "T1110.001",
            "sop_step": "SOC-WEB-007: SSH Brute-Force"
        },
        "nmap_web": {
            "cmd": ["nmap", "-sV", "-p", "80,443,8080,8443,8888,3000,5000,9000",
                    "--script=http-title,http-headers,http-methods,http-robots.txt,http-git"],
            "args_append_target": True,
            "target_type": "host",
            "desc": "Nmap port scan khusus web: cek port HTTP/HTTPS, dapatkan HTTP title, headers, robots.txt, dan git repo.",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "Domain/IP target — temukan semua web service yang berjalan.",
            "mitre_technique": "T1046",
            "sop_step": "SOC-WEB-008: Web Service Discovery"
        },
        "jq": {
            "cmd": ["jq", "."],
            "args_append_target": True,
            "desc": "JSON query dan pretty-print. Berguna untuk menganalisis API response atau JSON yang berisi flag.",
            "output_limit": 3000,
            "timeout": 10.0,
            "when_to_use": "File JSON atau output API yang perlu di-parse untuk mencari data tersembunyi.",
            "mitre_technique": "T1005",
            "sop_step": "SOC-WEB-009: API/JSON Analysis"
        },
        "curl_headers": {
            "cmd": ["curl", "-I", "--max-time", "10"],
            "args_append_target": True,
            "desc": "Ambil hanya HTTP response headers tanpa body. Cepat untuk inspeksi server/framework.",
            "output_limit": 1000,
            "timeout": 15.0,
            "when_to_use": "URL target — cek server type, security headers, cookies, X-Powered-By.",
            "mitre_technique": "T1592.002",
            "sop_step": "SOC-WEB-001: Header Inspection"
        },
        "nuclei": {
            "cmd": ["nuclei", "-u", None, "-severity", "critical,high,medium",
                    "-t", "/root/nuclei-templates/", "-silent"],
            "args_target_index": 2,
            "desc": "Template-based vulnerability scanner — deteksi CVE, misconfiguration, dan kerentanan umum.",
            "output_limit": 3000,
            "timeout": 120.0,
            "when_to_use": "URL target — scan komprehensif berdasarkan template CVE yang diperbarui.",
            "mitre_technique": "T1595.002",
            "sop_step": "SOC-WEB-010: CVE Template Scan"
        },
        "wpscan": {
            "cmd": ["wpscan", "--url", None, "--enumerate", "u,p,t,tt", "--no-banner"],
            "args_target_index": 2,
            "desc": "WordPress security scanner — enumerate users, plugin, theme, dan kerentanan WP.",
            "output_limit": 3000,
            "timeout": 90.0,
            "when_to_use": "URL WordPress — enumerate user admin, plugin vulnerable, dan tema dengan CVE.",
            "mitre_technique": "T1595.002",
            "sop_step": "SOC-WEB-011: WordPress Scan"
        },
    },

    # ============================================================
    # KATEGORI 7: REVERSE ENGINEERING & PWN
    # ============================================================
    "reverse_engineering": {
        "strings_offset": {
            "cmd": ["strings", "-n", "6", "-t", "x"],
            "args_append_target": True,
            "desc": "Cari string di binary dengan offset hex. Sering menemukan flag hardcoded atau URL C2.",
            "output_limit": 3000,
            "when_to_use": "Binary ELF, PE — mencari string flag atau petunjuk lain.",
            "mitre_technique": "T1140",
            "sop_step": "SOC-RE-001: String Extraction with Offset"
        },
        "objdump": {
            "cmd": ["objdump", "-d", "-M", "intel"],
            "args_append_target": True,
            "desc": "Disassemble binary (Linux ELF) menjadi Assembly Intel. Analisis logika program.",
            "output_limit": 3000,
            "when_to_use": "Binary Linux ELF untuk memahami alur eksekusi dan mencari fungsi menarik.",
            "mitre_technique": "T1012",
            "sop_step": "SOC-RE-002: Disassembly"
        },
        "readelf": {
            "cmd": ["readelf", "-a"],
            "args_append_target": True,
            "desc": "Baca semua header ELF (section, symbol, dynamic links). Info penting untuk exploit.",
            "output_limit": 3000,
            "when_to_use": "Binary Linux ELF — melihat proteksi (NX, PIE, RELRO, Canary).",
            "mitre_technique": "T1012",
            "sop_step": "SOC-RE-003: ELF Header Analysis"
        },
        "checksec": {
            "cmd": ["checksec", "--file"],
            "args_append_target": True,
            "desc": "Cek proteksi binary: Stack Canary, NX, PIE, RELRO. Menentukan teknik exploit yang dipakai.",
            "output_limit": 500,
            "when_to_use": "Soal Pwn — langkah pertama sebelum mencari vulnerability.",
            "mitre_technique": "T1012",
            "sop_step": "SOC-RE-004: Binary Protection Check"
        },
        "ltrace": {
            "cmd": ["ltrace"],
            "args_append_target": True,
            "desc": "Trace panggilan library C saat binary dieksekusi. Bisa melihat strcmp untuk bypass password.",
            "output_limit": 2000,
            "when_to_use": "Binary yang melakukan pengecekan password/input.",
            "mitre_technique": "T1012",
            "sop_step": "SOC-RE-005: Library Call Trace"
        },
        "strace": {
            "cmd": ["strace"],
            "args_append_target": True,
            "desc": "Trace system calls binary saat dieksekusi. Lihat file apa yang dibuka, network call, dsb.",
            "output_limit": 2000,
            "when_to_use": "Binary yang berinteraksi dengan sistem/file — lihat apa yang dilakukannya.",
            "mitre_technique": "T1012",
            "sop_step": "SOC-RE-006: Syscall Trace"
        },
        "radare2": {
            "cmd": ["r2", "-qc", "aaa; afl; pdf @main", None],
            "args_target_index": 3,
            "desc": "Disassembly & fungsi analisis mendalam menggunakan Radare2 framework.",
            "output_limit": 3000,
            "when_to_use": "Binary ELF/PE untuk membedah logika fungsi main.",
            "mitre_technique": "T1012",
            "sop_step": "SOC-RE-007: Deep Disassembly"
        },
        "gdb": {
            "cmd": ["gdb", "-batch", "-ex", "info files", "-ex", "disassemble main", None],
            "args_target_index": 6,
            "desc": "GNU Debugger batch inspection untuk analisis file binary.",
            "output_limit": 2500,
            "when_to_use": "Binary inspection sebelum dynamic execution.",
            "mitre_technique": "T1012",
            "sop_step": "SOC-RE-008: Debugger Analysis"
        },
        "upx": {
            "cmd": ["upx", "-t"],
            "args_append_target": True,
            "desc": "Uji dan periksa apakah binary dipack / dikompres dengan UPX packer.",
            "output_limit": 1000,
            "when_to_use": "Binary yang dipack untuk unpacking.",
            "mitre_technique": "T1027.002",
            "sop_step": "SOC-RE-009: Packer Detection"
        },
        "upx_unpack": {
            "cmd": ["upx", "-d", "-o", "/tmp/unpacked_binary"],
            "args_append_target": True,
            "desc": "Unpack binary yang dikompres dengan UPX. Langkah wajib sebelum analisis RE.",
            "output_limit": 1000,
            "when_to_use": "Binary UPX-packed — unpack sebelum disassembly.",
            "mitre_technique": "T1027.002",
            "sop_step": "SOC-RE-009: UPX Unpack"
        },
        "nm_symbols": {
            "cmd": ["nm", "-n"],
            "args_append_target": True,
            "desc": "Tampilkan simbol-simbol dalam binary (fungsi, variabel global). Cari fungsi menarik untuk exploit.",
            "output_limit": 2000,
            "when_to_use": "Binary ELF — mencari fungsi win(), hidden flag(), atau simbol internal lainnya.",
            "mitre_technique": "T1082",
            "sop_step": "SOC-RE-010: Symbol Analysis"
        },
    },

    # ============================================================
    # KATEGORI 8: OSINT & RECON
    # ============================================================
    "osint": {
        "whois": {
            "cmd": ["whois"],
            "args_append_target": True,
            "desc": "Cari informasi registrasi domain (owner, server, tanggal pendaftaran).",
            "output_limit": 2000,
            "when_to_use": "Diberikan nama domain — cari informasi pemiliknya.",
            "mitre_technique": "T1590.002",
            "sop_step": "SOC-OSINT-001: Domain WHOIS"
        },
        "dig": {
            "cmd": ["dig", "ANY"],
            "args_append_target": True,
            "desc": "DNS lookup lengkap (A, MX, TXT, NS, CNAME). Rekaman DNS sering menyimpan flag.",
            "output_limit": 1500,
            "when_to_use": "Soal OSINT berbasis domain — cari TXT record yang sering dipakai menyembunyikan flag.",
            "mitre_technique": "T1590.002",
            "sop_step": "SOC-OSINT-002: DNS Enumeration"
        },
        "dig_zone": {
            "cmd": ["bash", "-c", "dig axfr @$(dig NS %TARGET% +short | head -1) %TARGET% 2>/dev/null || dig ANY %TARGET% +short"],
            "args_template": True,
            "desc": "Coba DNS Zone Transfer (AXFR) untuk mendapatkan semua record DNS sekaligus.",
            "output_limit": 3000,
            "timeout": 30.0,
            "when_to_use": "Domain CTF/OSINT — coba zone transfer untuk mendapatkan seluruh DNS record.",
            "mitre_technique": "T1590.002",
            "sop_step": "SOC-OSINT-003: DNS Zone Transfer"
        },
        "nslookup": {
            "cmd": ["nslookup"],
            "args_append_target": True,
            "desc": "Query DNS server untuk domain atau IP tertentu.",
            "output_limit": 1000,
            "when_to_use": "Resolusi domain ke IP atau sebaliknya (reverse DNS).",
            "mitre_technique": "T1590.002",
            "sop_step": "SOC-OSINT-004: DNS Lookup"
        },
        "theHarvester": {
            "cmd": ["theHarvester", "-d", None, "-b", "all"],
            "args_target_index": 2,
            "desc": "Kumpulkan email, subdomain, IP, dan URL dari berbagai sumber publik.",
            "output_limit": 2000,
            "when_to_use": "Soal OSINT berbasis perusahaan atau domain — enumerasi aset publik.",
            "mitre_technique": "T1589",
            "sop_step": "SOC-OSINT-005: Public Asset Enumeration"
        },
        "subfinder": {
            "cmd": ["subfinder", "-d", None, "-silent"],
            "args_target_index": 2,
            "desc": "Subdomain discovery pasif menggunakan berbagai sumber: certificate, DNS, web archives.",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "Domain target — enumerasi semua subdomain tanpa aktif scan.",
            "mitre_technique": "T1590.002",
            "sop_step": "SOC-OSINT-006: Subdomain Enumeration"
        },
        "amass": {
            "cmd": ["amass", "enum", "-passive", "-d", None],
            "args_target_index": 4,
            "desc": "Advanced OSINT subdomain enumeration menggunakan +40 data source.",
            "output_limit": 3000,
            "timeout": 120.0,
            "when_to_use": "Domain target — enumerasi komprehensif subdomain dan aset terkait.",
            "mitre_technique": "T1590.002",
            "sop_step": "SOC-OSINT-007: Deep Subdomain OSINT"
        },
        "shodan_host": {
            "cmd": ["shodan", "host"],
            "args_append_target": True,
            "desc": "Query Shodan.io untuk mendapatkan informasi host (port terbuka, banner, CVE).",
            "output_limit": 2000,
            "timeout": 30.0,
            "when_to_use": "IP target — cari informasi dari Shodan database (perlu API key).",
            "mitre_technique": "T1596",
            "sop_step": "SOC-OSINT-008: Shodan Recon"
        },
    },

    # ============================================================
    # KATEGORI 9: OSINT GITHUB & SECRET LEAKS
    # ============================================================
    "osint_github": {
        "trufflehog": {
            "cmd": ["trufflehog", "git", None, "--only-verified"],
            "args_target_index": 2,
            "desc": "Mencari hardcoded credential, password, dan API keys di Git repository.",
            "output_limit": 3000,
            "when_to_use": "URL Git repository untuk mencari leaked credentials.",
            "mitre_technique": "T1592.004",
            "sop_step": "SOC-LEAK-001: Git Secret Scan"
        },
        "gitleaks": {
            "cmd": ["gitleaks", "detect", "-v", "--repo-url"],
            "args_append_target": True,
            "desc": "Deteksi secrets dan hardcoded passwords menggunakan Gitleaks.",
            "output_limit": 3000,
            "when_to_use": "URL Git repository untuk mencari leaked credentials.",
            "mitre_technique": "T1592.004",
            "sop_step": "SOC-LEAK-002: Gitleaks Scan"
        },
        "git_log_all": {
            "cmd": ["git", "log", "-p", "--all"],
            "args_append_target": True,
            "desc": "Menampilkan seluruh riwayat commit dan perubahannya untuk mencari data terhapus.",
            "output_limit": 3000,
            "when_to_use": "Direktori lokal repository Git.",
            "mitre_technique": "T1592.004",
            "sop_step": "SOC-LEAK-003: Git History Analysis"
        },
        "git_secrets": {
            "cmd": ["bash", "-c", "grep -rn -E '(api_key|api-key|apikey|access_token|secret_key|password|passwd|credential|aws_access|private_key)\\s*[=:]' %TARGET% --include='*.py' --include='*.js' --include='*.env' --include='*.json' --include='*.yaml' --include='*.yml' 2>/dev/null | head -30"],
            "args_template": True,
            "desc": "Grep seluruh codebase untuk mencari hardcoded secrets, API keys, dan passwords.",
            "output_limit": 3000,
            "timeout": 30.0,
            "when_to_use": "Direktori project lokal — scan seluruh source code untuk secret leaks.",
            "mitre_technique": "T1552.001",
            "sop_step": "SOC-LEAK-004: Hardcoded Secret Grep"
        },
    },

    # ============================================================
    # KATEGORI 10: SOC TRIAGE & INCIDENT RESPONSE
    # ============================================================
    "soc_triage": {
        "wazuh_agent_check": {
            "cmd": ["systemctl", "status", "wazuh-agent"],
            "args_append_target": False,
            "desc": "Memeriksa status Wazuh SIEM agent di server lokal.",
            "output_limit": 1000,
            "when_to_use": "Mengecek infrastruktur SOC/SIEM.",
            "mitre_technique": "T1082",
            "sop_step": "SOC-IR-001: SIEM Agent Health Check"
        },
        "ps_suspicious": {
            "cmd": ["bash", "-c", "ps auxf | grep -vE '(ssh|sshd|systemd|python3|bash|grep|ps)' | head -30"],
            "args_append_target": False,
            "desc": "Tampilkan proses yang berpotensi mencurigakan di sistem Linux.",
            "output_limit": 2000,
            "when_to_use": "Incident Response — audit proses berjalan untuk deteksi malware.",
            "mitre_technique": "T1057",
            "sop_step": "SOC-IR-002: Process Audit"
        },
        "crontab_audit": {
            "cmd": ["bash", "-c", "for u in $(cut -f1 -d: /etc/passwd); do crontab -u $u -l 2>/dev/null && echo '---USER:$u---'; done; ls -la /etc/cron*/ 2>/dev/null"],
            "args_append_target": False,
            "desc": "Audit semua crontab pengguna dan sistem untuk mendeteksi persistence via cron.",
            "output_limit": 2000,
            "when_to_use": "Incident Response — cari backdoor persistent via crontab.",
            "mitre_technique": "T1053.003",
            "sop_step": "SOC-IR-003: Cron Persistence Check"
        },
        "suid_scan": {
            "cmd": ["bash", "-c", "find / -perm /4000 -type f 2>/dev/null | head -30"],
            "args_append_target": False,
            "desc": "Scan seluruh sistem untuk file SUID — potensi privilege escalation.",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "Post-compromise — audit SUID untuk path privilege escalation.",
            "mitre_technique": "T1548.001",
            "sop_step": "SOC-IR-004: SUID Privilege Check"
        },
        "last_logins": {
            "cmd": ["bash", "-c", "last -n 30; echo '---LASTB---'; lastb -n 20 2>/dev/null | head -20"],
            "args_append_target": False,
            "desc": "Tampilkan 30 login terakhir dan 20 login gagal terbaru untuk audit akses.",
            "output_limit": 2000,
            "when_to_use": "Incident Response — audit siapa yang login dan kapan (lateral movement check).",
            "mitre_technique": "T1078",
            "sop_step": "SOC-IR-005: Login Audit"
        },
        "users_audit": {
            "cmd": ["bash", "-c", "cat /etc/passwd | grep -v nologin | grep -v false; echo '---SUDOERS---'; cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'"],
            "args_append_target": False,
            "desc": "Audit akun pengguna aktif dan hak sudo yang terkonfigurasi di sistem.",
            "output_limit": 2000,
            "when_to_use": "Incident Response — identifikasi akun backdoor atau sudo privilege abuse.",
            "mitre_technique": "T1136",
            "sop_step": "SOC-IR-006: User Account Audit"
        },
        "network_connections": {
            "cmd": ["bash", "-c", "ss -tupan 2>/dev/null | grep ESTAB | head -30; echo '---LISTENERS---'; ss -tulnp | head -20"],
            "args_append_target": False,
            "desc": "Audit semua koneksi TCP/UDP yang sedang established dan semua port yang listening.",
            "output_limit": 2000,
            "when_to_use": "Incident Response — deteksi reverse shell aktif atau C2 beaconing.",
            "mitre_technique": "T1049",
            "sop_step": "SOC-IR-007: Network Audit"
        },
        "lsof_network": {
            "cmd": ["bash", "-c", "lsof -i -n -P 2>/dev/null | grep ESTABLISHED | head -30"],
            "args_append_target": False,
            "desc": "Tampilkan proses mana yang membuka koneksi jaringan (kombinasi lsof & network).",
            "output_limit": 2000,
            "when_to_use": "Incident Response — mapping proses ke koneksi jaringan untuk deteksi malware.",
            "mitre_technique": "T1049",
            "sop_step": "SOC-IR-008: Process-Network Mapping"
        },
        "alert_summary": {
            "cmd": ["cat", "/var/log/syslog"],
            "args_append_target": True,
            "desc": "Meringkas log alert berdasarkan prioritas (CRITICAL, HIGH, MEDIUM, LOW).",
            "output_limit": 2000,
            "when_to_use": "Triage alert dari SIEM.",
            "mitre_technique": "T1005",
            "sop_step": "SOC-IR-009: Alert Triage"
        },
        "file_integrity": {
            "cmd": ["bash", "-c", "find /etc /bin /usr/bin /usr/sbin -newer /tmp -type f 2>/dev/null | head -20"],
            "args_append_target": False,
            "desc": "Cari file system yang dimodifikasi baru-baru ini di direktori kritis — indikasi backdoor.",
            "output_limit": 2000,
            "timeout": 30.0,
            "when_to_use": "Incident Response — deteksi file yang baru dimodifikasi oleh attacker.",
            "mitre_technique": "T1565.001",
            "sop_step": "SOC-IR-010: File Integrity Check"
        },
    },

    # ============================================================
    # KATEGORI 11: SIEM INTEGRATION
    # ============================================================
    "siem_integration": {
        "elk_health": {
            "cmd": ["curl", "-XGET", "http://localhost:9200/_cluster/health"],
            "args_append_target": False,
            "desc": "Memeriksa status Elasticsearch cluster (ELK Stack).",
            "output_limit": 1000,
            "when_to_use": "Troubleshooting SIEM ELK.",
            "mitre_technique": "T1082",
            "sop_step": "SOC-SIEM-001: ELK Health Check"
        },
        "elk_indices": {
            "cmd": ["curl", "-XGET", "http://localhost:9200/_cat/indices?v"],
            "args_append_target": False,
            "desc": "Tampilkan semua index Elasticsearch — audit data log yang tersimpan di SIEM.",
            "output_limit": 2000,
            "when_to_use": "Audit ELK SIEM — cek index yang tersedia dan ukuran data.",
            "mitre_technique": "T1082",
            "sop_step": "SOC-SIEM-002: ELK Index Audit"
        },
        "splunk_status": {
            "cmd": ["/opt/splunk/bin/splunk", "status"],
            "args_append_target": False,
            "desc": "Memeriksa status layanan Splunk Enterprise.",
            "output_limit": 1000,
            "when_to_use": "Troubleshooting SIEM Splunk.",
            "mitre_technique": "T1082",
            "sop_step": "SOC-SIEM-003: Splunk Health Check"
        },
        "suricata_status": {
            "cmd": ["systemctl", "status", "suricata"],
            "args_append_target": False,
            "desc": "Cek status IDS/IPS Suricata yang terintegrasi dengan SIEM.",
            "output_limit": 1000,
            "when_to_use": "Audit infrastruktur SOC — pastikan IDS aktif dan beroperasi.",
            "mitre_technique": "T1082",
            "sop_step": "SOC-SIEM-004: Suricata IDS Check"
        },
    },

    # ============================================================
    # KATEGORI 12: MALWARE ANALYSIS
    # ============================================================
    "malware_analysis": {
        "clamav_scan": {
            "cmd": ["clamscan", "--infected", "--recursive"],
            "args_append_target": True,
            "desc": "Scan antivirus menggunakan ClamAV database. Deteksi malware yang sudah diketahui.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "File atau direktori mencurigakan — verifikasi dengan antivirus engine.",
            "mitre_technique": "T1027",
            "sop_step": "SOC-MAL-002: AV Scan"
        },
        "strings_malware": {
            "cmd": ["bash", "-c", "strings -n 6 %TARGET% | grep -iE '(http|ftp|cmd|powershell|wget|curl|base64|decode|eval|exec|CreateRemoteThread|VirtualAlloc|LoadLibrary|GetProcAddress|RegOpenKey|socket|connect|bind|listen|send|recv)' | head -50"],
            "args_template": True,
            "desc": "Ekstrak string yang berkaitan dengan malware behavior: network, registry, API calls berbahaya.",
            "output_limit": 3000,
            "when_to_use": "Binary/file mencurigakan — cari IoC string yang mengindikasikan malware.",
            "mitre_technique": "T1059",
            "sop_step": "SOC-MAL-003: Malware String Analysis"
        },
        "detect_it_easy": {
            "cmd": ["die"],
            "args_append_target": True,
            "desc": "Detect It Easy (DIE) — identifikasi compiler, packer, dan protector binary.",
            "output_limit": 1000,
            "when_to_use": "Binary malware — identifikasi bahasa pemrograman, packer, dan protector.",
            "mitre_technique": "T1027.002",
            "sop_step": "SOC-MAL-004: Binary Identification"
        },
        "ldd_libs": {
            "cmd": ["ldd"],
            "args_append_target": True,
            "desc": "Tampilkan shared library dependencies dari binary ELF. Cek apakah ada library mencurigakan.",
            "output_limit": 1000,
            "when_to_use": "Binary ELF — audit library yang digunakan untuk deteksi library injection.",
            "mitre_technique": "T1574.006",
            "sop_step": "SOC-MAL-005: Library Dependency Audit"
        },
    },

    # ============================================================
    # KATEGORI 13: EXPLOIT DEVELOPMENT
    # ============================================================
    "exploit_dev": {
        "pwntools_cyclic": {
            "cmd": ["python3", "-c", "from pwn import *; print(cyclic(200).decode())"],
            "args_append_target": False,
            "desc": "Generate cyclic pattern untuk menemukan offset buffer overflow menggunakan pwntools.",
            "output_limit": 1000,
            "when_to_use": "Soal Buffer Overflow — buat pattern untuk menemukan EIP/RIP offset.",
            "mitre_technique": "T1203",
            "sop_step": "SOC-EXP-001: BOF Pattern Generate"
        },
        "roi_find": {
            "cmd": ["ROPgadget", "--binary", None, "--rop"],
            "args_target_index": 2,
            "desc": "Temukan ROP gadgets dalam binary untuk membangun ROP chain exploit.",
            "output_limit": 3000,
            "timeout": 30.0,
            "when_to_use": "Binary ELF — ekstrak ROP gadget untuk bypass NX/DEP menggunakan Return-Oriented Programming.",
            "mitre_technique": "T1203",
            "sop_step": "SOC-EXP-002: ROP Gadget Search"
        },
        "one_gadget": {
            "cmd": ["one_gadget"],
            "args_append_target": True,
            "desc": "Temukan one-gadget (magic gadget) dalam libc untuk exploit tanpa ROP chain kompleks.",
            "output_limit": 1000,
            "timeout": 20.0,
            "when_to_use": "Binary yang menggunakan libc standar — temukan exec shell gadget.",
            "mitre_technique": "T1203",
            "sop_step": "SOC-EXP-003: One-Gadget Search"
        },
    },

    # ============================================================
    # KATEGORI 14: PASSWORD ATTACKS
    # ============================================================
    "password_attacks": {
        "medusa": {
            "cmd": ["medusa", "-h", None, "-U", "/usr/share/wordlists/ctf_mini.txt",
                    "-P", "/usr/share/wordlists/rockyou.txt", "-M", "ssh", "-f"],
            "args_target_index": 2,
            "desc": "Medusa: multi-protocol brute-force login tool (SSH, FTP, HTTP, Telnet, dll).",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "Alternatif Hydra untuk brute-force multi-protokol.",
            "mitre_technique": "T1110.001",
            "sop_step": "SOC-PWD-001: Medusa Brute-Force"
        },
        "crack_sha256": {
            "cmd": ["bash", "-c", "echo %TARGET% | hashcat -m 1400 -a 0 /dev/stdin /usr/share/wordlists/rockyou.txt --show 2>/dev/null || echo 'Not found in wordlist'"],
            "args_template": True,
            "desc": "Crack hash SHA-256 menggunakan Hashcat dengan rockyou wordlist.",
            "output_limit": 1000,
            "timeout": 60.0,
            "when_to_use": "Hash SHA-256 yang perlu di-crack.",
            "mitre_technique": "T1110.002",
            "sop_step": "SOC-PWD-002: SHA256 Hash Crack"
        },
        "ssh2john": {
            "cmd": ["bash", "-c", "ssh2john %TARGET% > /tmp/ssh_hash.txt && john /tmp/ssh_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt && john /tmp/ssh_hash.txt --show"],
            "args_template": True,
            "desc": "Ekstrak hash dari SSH private key terenkripsi, lalu crack dengan john the ripper.",
            "output_limit": 1000,
            "timeout": 120.0,
            "when_to_use": "SSH private key berpassword — crack passphrase menggunakan john.",
            "mitre_technique": "T1110.002",
            "sop_step": "SOC-PWD-003: SSH Key Crack"
        },
        "crunch_wordlist": {
            "cmd": ["crunch", "6", "8", "abcdefghijklmnopqrstuvwxyz0123456789", "-o", "/tmp/crunch_wordlist.txt"],
            "args_append_target": False,
            "desc": "Generate custom wordlist dengan pola karakter tertentu menggunakan crunch.",
            "output_limit": 500,
            "timeout": 30.0,
            "when_to_use": "Password dengan pola diketahui — generate wordlist sesuai constraint.",
            "mitre_technique": "T1110.002",
            "sop_step": "SOC-PWD-004: Wordlist Generation"
        },
    },

    # ============================================================
    # KATEGORI 15: CONTAINER SECURITY
    # ============================================================
    "container_security": {
        "docker_inspect": {
            "cmd": ["docker", "inspect"],
            "args_append_target": True,
            "desc": "Inspect Docker container atau image untuk menemukan secrets, env vars, dan konfigurasi.",
            "output_limit": 3000,
            "when_to_use": "CTF Docker challenge — cari secrets, ENV vars, dan mounted volumes.",
            "mitre_technique": "T1552.001",
            "sop_step": "SOC-CONT-001: Container Inspection"
        },
        "docker_history": {
            "cmd": ["docker", "history", "--no-trunc"],
            "args_append_target": True,
            "desc": "Tampilkan layer history Docker image. Sering berisi perintah RUN dengan password hardcoded.",
            "output_limit": 3000,
            "when_to_use": "Docker CTF — cari secrets yang pernah di-ADD atau di-RUN dalam Dockerfile.",
            "mitre_technique": "T1552.001",
            "sop_step": "SOC-CONT-002: Docker Layer History"
        },
        "trivy_scan": {
            "cmd": ["trivy", "image", "--severity", "CRITICAL,HIGH"],
            "args_append_target": True,
            "desc": "Scan Docker image untuk CVE dan kerentanan keamanan dengan Trivy.",
            "output_limit": 3000,
            "timeout": 120.0,
            "when_to_use": "Docker image — vulnerability scan untuk CVE Critical/High.",
            "mitre_technique": "T1190",
            "sop_step": "SOC-CONT-003: Container CVE Scan"
        },
    },
}

# ================================================================
# AI TOOL SELECTOR RULES PRO — Panduan untuk AI Orchestrator
# ================================================================

AI_TOOL_SELECTOR_PROMPT = """
Anda adalah KIIBOT PRO — Senior CTF Solver, SOC L3 Analyst & Threat Intelligence Expert.
Mode: PROFESSIONAL EXECUTION — Setiap tool dieksekusi dengan output DETAIL & AKURAT.

KATEGORI TOOLS (85+ Tools):
1.  Forensics (14 tools)     — Analisis file, memory dump, disk image, malware docs
2.  Steganography (9 tools)  — Data tersembunyi dalam media (gambar, audio, teks)
3.  Cryptography (8 tools)   — Hash, cipher, RSA, enkripsi, JWT, ZIP crack
4.  Network/PCAP (10 tools)  — Analisis traffic jaringan, credential extraction
5.  Log Analysis (10 tools)  — Log web server, SIEM alert, audit SSH
6.  Web Exploitation (12 tools) — SQLi, XSS, RCE, Dir Enum, Brute-force, WAF bypass
7.  Reverse Engineering (10 tools) — Binary analysis, buffer overflow, ROP
8.  OSINT (8 tools)          — Recon domain, subdomain, Shodan, theHarvester
9.  GitHub Leaks (4 tools)   — Secret scan, git history, hardcoded credentials
10. SOC Triage (10 tools)    — Incident Response, process/user/network audit
11. SIEM Integration (4 tools) — ELK, Splunk, Suricata health check
12. Malware Analysis (4 tools) — AV scan, behavior analysis, string IoC
13. Exploit Dev (3 tools)    — BOF pattern, ROP gadget, one-gadget
14. Password Attacks (4 tools) — Medusa, hashcat, ssh2john, crunch
15. Container Security (3 tools) — Docker inspect, trivy, history analysis

ATURAN PEMILIHAN TOOLS (Pro Mode):
- Gambar (JPEG/PNG/BMP)    → file, exiftool, strings, binwalk, zsteg, steghide, stegseek, pngcheck, tesseract, zbarimg
- File .pcap/.pcapng        → tshark, tshark_http, tshark_follow, tshark_dns, tshark_creds, tcpdump
- File log (access.log)     → awk_top_ip, grep_sqli, grep_xss, grep_lfi, grep_rce, grep_ip, log_status_count, grep_auth_fail
- Binary ELF/PE             → file, checksec, strings_offset, objdump, readelf, ltrace, strace, nm_symbols, upx
- File ZIP/RAR terpassword  → file, strings, fcrackzip, john
- Teks hash/cipher          → hashid, hash_identifier, john, hashcat, rsactftool, openssl
- URL web                   → curl, whatweb, wafw00f, gobuster, ffuf, nikto, nuclei, nmap_web
- URL WordPress             → whatweb, wpscan, gobuster, nikto
- Git Repo URL              → trufflehog, gitleaks, git_log_all, git_secrets
- IP target                 → nmap, masscan, nmap_os, shodan_host
- Incident Response         → ps_suspicious, network_connections, last_logins, users_audit, crontab_audit, suid_scan, file_integrity
- Docker image/container    → docker_inspect, docker_history, trivy_scan
- Memory dump               → volatility3, vol_pslist, vol_netscan, vol_cmdline, vol_dumpfiles

PRO EXECUTION PROTOCOL:
- Jalankan MINIMAL 5 tools secara paralel, MAKSIMAL 15 untuk full battery.
- SETIAP output tool harus ditampilkan secara LENGKAP (bukan ringkasan).
- Laporan akhir WAJIB mencakup:
  1. 📋 RINGKASAN EKSEKUTIF (Executive Summary)
  2. 🔍 FINDINGS PER TOOL (output raw + analisis per tool)
  3. ⚠️  SEVERITY MAPPING (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  4. 🎯  MITRE ATT&CK MAPPING (Tactic + Technique per finding)
  5. 🛠️  REKOMENDASI MITIGASI SOC (langkah konkret)
  6. 🚩  FLAG / CREDENTIAL / EVIDENCE (jika ditemukan)
"""

# ================================================================
# KATEGORI → TOOLS MAPPING PRO (85+ Tools)
# ================================================================

CATEGORY_TOOL_MAP = {
    "image":               ["file", "exiftool", "strings", "binwalk", "zsteg", "steghide",
                            "stegseek", "pngcheck", "hexdump", "tesseract", "zbarimg", "outguess"],
    "pcap":                ["tshark", "tshark_http", "tshark_follow", "tshark_dns",
                            "tshark_creds", "tcpdump"],
    "log":                 ["awk_top_ip", "grep_ip", "grep_sqli", "grep_xss", "grep_lfi",
                            "grep_rce", "grep_useragent", "log_status_count", "grep_auth_fail",
                            "journalctl_security", "alert_summary"],
    "binary_elf":          ["file", "checksec", "strings_offset", "objdump", "readelf",
                            "ltrace", "strace", "nm_symbols", "upx", "ldd_libs"],
    "archive":             ["file", "strings", "binwalk", "john", "fcrackzip"],
    "hash_text":           ["hashid", "hash_identifier", "john", "hashcat", "crack_sha256"],
    "web_url":             ["curl", "curl_headers", "whatweb", "wafw00f", "gobuster", "ffuf", "nikto"],
    "web_attack":          ["curl", "whatweb", "wafw00f", "nmap_web", "gobuster", "nikto", "sqlmap", "nuclei"],
    "web_sqli":            ["sqlmap", "sqlmap_full", "curl", "whatweb", "wafw00f"],
    "web_dir":             ["gobuster", "dirb", "ffuf", "nikto", "curl"],
    "web_bruteforce":      ["hydra_http_get", "hydra_ssh", "medusa", "curl", "whatweb"],
    "web_full_battery":    ["curl", "curl_headers", "whatweb", "wafw00f", "nmap_web",
                            "gobuster", "ffuf", "nikto", "sqlmap", "nuclei"],
    "web_wordpress":       ["whatweb", "wpscan", "gobuster", "nikto", "curl"],
    "osint_domain":        ["whois", "dig", "dig_zone", "nslookup", "theHarvester",
                            "subfinder", "amass"],
    "osint_github":        ["trufflehog", "gitleaks", "git_log_all", "git_secrets"],
    "rsa_crypto":          ["openssl", "rsactftool", "hashid"],
    "jwt_crypto":          ["jwt_tool", "hashid"],
    "memory_dump":         ["file", "strings", "volatility3", "vol_pslist", "vol_netscan",
                            "vol_cmdline", "vol_dumpfiles"],
    "pdf":                 ["file", "strings", "pdf_parser", "binwalk", "hexdump"],
    "office_doc":          ["file", "strings", "oletools", "binwalk", "exiftool"],
    "json_data":           ["jq", "strings"],
    "soc_triage":          ["ps_suspicious", "network_connections", "last_logins", "users_audit",
                            "crontab_audit", "suid_scan", "file_integrity", "lsof_network",
                            "journalctl_security"],
    "siem_integration":    ["elk_health", "elk_indices", "splunk_status", "suricata_status"],
    "malware_analysis":    ["clamav_scan", "strings_malware", "detect_it_easy", "ldd_libs",
                            "yara_scan", "strace"],
    "docker_container":    ["docker_inspect", "docker_history", "trivy_scan"],
    "exploit_dev":         ["checksec", "pwntools_cyclic", "roi_find", "one_gadget", "nm_symbols"],
    "password_attack":     ["john", "hashcat", "medusa", "hydra_ssh", "hydra_http_get",
                            "ssh2john", "crack_sha256", "fcrackzip"],
    "general":             ["file", "strings", "hexdump", "binwalk", "exiftool"],
    "network_recon":       ["nmap", "masscan", "nmap_os", "nmap_web", "netstat_live",
                            "ss_sockets", "shodan_host"],
}
