"""
KIIBOT Tool Registry — Berdasarkan Materi Workshop CTF Fundamental
Kategori: Jeopardy CTF (Web, Crypto, Forensics, PCAP/Network, Steganography,
           OSINT, Pwn/RE, Log Analysis) & SOC Triage
"""

# ================================================================
# TOOL REGISTRY — Pemetaan Tool per Kategori CTF & SOC
# Setiap tool berisi: command, deskripsi, kategori, dan flag apa
# yang biasa ditemukan.
# ================================================================

TOOL_REGISTRY = {

    # ============================================================
    # KATEGORI: FORENSICS & STEGANOGRAPHY
    # ============================================================
    "forensics": {
        "file": {
            "cmd": ["file"],
            "args_append_target": True,
            "desc": "Identifikasi tipe file berdasarkan magic bytes. Langkah PERTAMA untuk setiap file CTF.",
            "output_limit": 1000,
            "when_to_use": "SELALU dijalankan pertama kali pada sembarang file yang dikirim.",
            "mitre_technique": "T1082"
        },
        "strings": {
            "cmd": ["strings", "-n", "6"],
            "args_append_target": True,
            "desc": "Ekstrak semua string printable dari binary/file. Sering langsung menemukan flag tersembunyi.",
            "output_limit": 3000,
            "when_to_use": "File binary ELF, PDF, DOCX, gambar.",
            "mitre_technique": "T1140"
        },
        "exiftool": {
            "cmd": ["exiftool"],
            "args_append_target": True,
            "desc": "Baca semua metadata EXIF dari file (gambar, PDF, DOCX). Flag sering tersembunyi di metadata.",
            "output_limit": 2000,
            "when_to_use": "Gambar JPEG/PNG, PDF, file Office.",
            "mitre_technique": "T1005"
        },
        "hexdump": {
            "cmd": ["hexdump", "-C"],
            "args_append_target": True,
            "desc": "Tampilkan isi file dalam format hex + ASCII. Berguna untuk menemukan header file palsu.",
            "output_limit": 3000,
            "when_to_use": "File rusak/korup, file dengan ekstensi salah, file unknown.",
            "mitre_technique": "T1140"
        },
        "xxd": {
            "cmd": ["xxd"],
            "args_append_target": True,
            "desc": "Alternatif hexdump dengan tampilan lebih rapi.",
            "output_limit": 3000,
            "when_to_use": "Analisis hex untuk menemukan flag atau magic bytes tersembunyi.",
            "mitre_technique": "T1140"
        },
        "binwalk": {
            "cmd": ["binwalk", "-e", "-M"],
            "args_append_target": True,
            "desc": "Scan dan ekstrak file tersembunyi di dalam file lain (file carving). Tool wajib forensics.",
            "output_limit": 2000,
            "when_to_use": "Gambar atau binary yang dicurigai menyembunyikan file di dalamnya.",
            "mitre_technique": "T1140"
        },
        "foremost": {
            "cmd": ["foremost", "-o", "/tmp/foremost_out"],
            "args_append_target": True,
            "desc": "File carving berdasarkan header & footer. Alternatif binwalk untuk recovery file.",
            "output_limit": 1500,
            "when_to_use": "Disk image, binary yang menyimpan banyak file tersembunyi.",
            "mitre_technique": "T1140"
        },
        "volatility3": {
            "cmd": ["vol3", "-f"],
            "args_append_target": True,
            "desc": "Analisis memory dump (RAM forensics). Digunakan untuk mencari proses, koneksi jaringan, dan kredensial di RAM.",
            "output_limit": 3000,
            "timeout": 60.0,
            "when_to_use": "File .mem, .dmp, .vmem — soal Memory Forensics.",
            "mitre_technique": "T1005"
        },
        "vol_pslist": {
            "cmd": ["vol3", "-f", None, "windows.pslist.PsList"],
            "args_target_index": 2,
            "desc": "Volatility3: Daftar semua proses yang sedang berjalan di memory dump Windows.",
            "output_limit": 3000,
            "timeout": 90.0,
            "when_to_use": "Memory dump Windows — mencari proses mencurigakan (malware, injected DLL).",
            "mitre_technique": "T1005"
        },
        "vol_netscan": {
            "cmd": ["vol3", "-f", None, "windows.netscan.NetScan"],
            "args_target_index": 2,
            "desc": "Volatility3: Scan koneksi jaringan aktif dan listening ports di memory dump Windows.",
            "output_limit": 3000,
            "timeout": 90.0,
            "when_to_use": "Memory dump Windows — menemukan koneksi C2, reverse shell, atau beaconing.",
            "mitre_technique": "T1040"
        },
        "pdf_parser": {
            "cmd": ["pdf-parser", "--stats"],
            "args_append_target": True,
            "desc": "Parse dan analisis struktur file PDF untuk menemukan payload embedded, JavaScript, atau objek tersembunyi.",
            "output_limit": 3000,
            "timeout": 20.0,
            "when_to_use": "File PDF — forensics dokumen CTF atau malware dropper berbasis PDF.",
            "mitre_technique": "T1027"
        },
    },

    "steganography": {
        "steghide": {
            "cmd": ["steghide", "info", "-p", ""],
            "args_append_target": True,
            "desc": "Cek dan ekstrak payload tersembunyi di JPEG/BMP menggunakan passphrase.",
            "output_limit": 1000,
            "timeout": 15.0,
            "when_to_use": "File JPEG atau BMP yang dicurigai menyimpan pesan tersembunyi.",
            "mitre_technique": "T1027.003"
        },
        "stegseek": {
            "cmd": ["stegseek", "--crack"],
            "args_append_target": True,
            "desc": "Fast steghide cracker menggunakan wordlist rockyou. Jauh lebih cepat dari steghide brute-force manual.",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "JPEG/BMP yang terpassword — crack passphrase secara otomatis.",
            "mitre_technique": "T1027.003"
        },
        "zsteg": {
            "cmd": ["zsteg", "-a"],
            "args_append_target": True,
            "desc": "Deteksi dan ekstrak payload tersembunyi di PNG/BMP menggunakan berbagai teknik LSB.",
            "output_limit": 2000,
            "timeout": 20.0,
            "when_to_use": "File PNG — tool utama untuk LSB steganography.",
            "mitre_technique": "T1027.003"
        },
        "stegsolve": {
            "cmd": ["stegsolve"],
            "args_append_target": True,
            "desc": "Analisis visual gambar dengan berbagai filter warna (plane analysis).",
            "output_limit": 500,
            "when_to_use": "Gambar CTF yang perlu dilihat bit-plane-nya (R/G/B channel).",
            "mitre_technique": "T1027.003"
        },
        "pngcheck": {
            "cmd": ["pngcheck", "-v"],
            "args_append_target": True,
            "desc": "Validasi integritas file PNG dan deteksi chunk tersembunyi.",
            "output_limit": 2000,
            "when_to_use": "File PNG — mencari custom chunk data yang tidak standar.",
            "mitre_technique": "T1027.003"
        },
        "outguess": {
            "cmd": ["outguess", "-r"],
            "args_append_target": True,
            "desc": "Ekstraksi pesan tersembunyi menggunakan algoritma outguess.",
            "output_limit": 1000,
            "when_to_use": "JPEG yang dicurigai menggunakan outguess untuk menyembunyikan data.",
            "mitre_technique": "T1027.003"
        },
    },

    "cryptography": {
        "hashid": {
            "cmd": ["hashid"],
            "args_append_target": True,
            "desc": "Identifikasi tipe hash (MD5, SHA1, SHA256, bcrypt, dll).",
            "output_limit": 500,
            "timeout": 10.0,
            "when_to_use": "Diberikan sebuah string hash, identifikasi jenisnya sebelum cracking.",
            "mitre_technique": "T1110"
        },
        "hash_identifier": {
            "cmd": ["hash-identifier"],
            "args_append_target": True,
            "desc": "Alternatif hashid untuk identifikasi format hash.",
            "output_limit": 500,
            "timeout": 10.0,
            "when_to_use": "Identifikasi hash yang tidak jelas formatnya.",
            "mitre_technique": "T1110"
        },
        "john": {
            "cmd": ["john", "--wordlist=/usr/share/wordlists/rockyou.txt"],
            "args_append_target": True,
            "desc": "Password/Hash cracker menggunakan wordlist. Gunakan rockyou.txt untuk CTF.",
            "output_limit": 1000,
            "timeout": 120.0,
            "when_to_use": "File hash, file ZIP terpassword, file SSH key terenkripsi.",
            "mitre_technique": "T1110.002"
        },
        "hashcat": {
            "cmd": ["hashcat", "-a", "0", "-m", "0"],
            "args_append_target": False,
            "desc": "GPU-accelerated hash cracker. Jauh lebih cepat dari john untuk hash yang kuat.",
            "output_limit": 1000,
            "timeout": 120.0,
            "when_to_use": "Hash MD5/SHA256 yang perlu di-crack dengan GPU.",
            "mitre_technique": "T1110.002"
        },
        "openssl": {
            "cmd": ["openssl", "enc", "-d", "-base64", "-in"],
            "args_append_target": True,
            "desc": "Enkripsi/Dekripsi OpenSSL (base64, AES, RSA). Swiss-army knife kriptografi.",
            "output_limit": 1000,
            "timeout": 15.0,
            "when_to_use": "Data terenkripsi dengan library OpenSSL standar, sertifikat, RSA key.",
            "mitre_technique": "T1140"
        },
        "rsactftool": {
            "cmd": ["RsaCtfTool.py", "--publickey"],
            "args_append_target": True,
            "desc": "Toolkit otomatis untuk mengeksploitasi kelemahan RSA CTF (small-e, wiener, dll).",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "Soal RSA CTF — diberikan public key dan ciphertext untuk didekripsi.",
            "mitre_technique": "T1140"
        },
        "jwt_tool": {
            "cmd": ["jwt_tool"],
            "args_append_target": True,
            "desc": "Analisis dan uji kerentanan JWT (none algorithm, weak secret, RS256->HS256 confusion).",
            "output_limit": 2000,
            "timeout": 20.0,
            "when_to_use": "JWT token — soal Web CTF atau SOC yang menemukan token mencurigakan.",
            "mitre_technique": "T1140"
        },
    },

    "network": {
        "tshark": {
            "cmd": ["tshark", "-r"],
            "args_append_target": True,
            "desc": "CLI version of Wireshark. Analisis PCAP dari command line. Tool utama untuk soal network.",
            "output_limit": 3000,
            "when_to_use": "Semua file .pcap atau .pcapng.",
            "mitre_technique": "T1040"
        },
        "tshark_http": {
            "cmd": ["tshark", "-r", None, "-Y", "http", "-T", "fields", "-e", "http.request.uri", "-e", "http.file_data"],
            "args_target_index": 2,
            "desc": "Filter dan ekstrak konten HTTP dari PCAP (URL, form data, payload).",
            "output_limit": 3000,
            "when_to_use": "PCAP dengan traffic HTTP — mencari credential, flag dalam HTTP request/response.",
            "mitre_technique": "T1040"
        },
        "tshark_follow": {
            "cmd": ["tshark", "-r", None, "-q", "-z", "follow,tcp,ascii,0"],
            "args_target_index": 2,
            "desc": "Ikuti TCP stream penuh untuk melihat percakapan lengkap dalam PCAP.",
            "output_limit": 3000,
            "when_to_use": "PCAP dengan data yang perlu dilihat sebagai satu sesi komunikasi utuh.",
            "mitre_technique": "T1040"
        },
        "tcpdump": {
            "cmd": ["tcpdump", "-r"],
            "args_append_target": True,
            "desc": "Analisis PCAP cepat dengan filter packet yang fleksibel.",
            "output_limit": 2000,
            "when_to_use": "Analisis ringkas PCAP untuk menemukan paket anomali.",
            "mitre_technique": "T1040"
        },
        "nmap": {
            "cmd": ["nmap", "-sV", "--script=default"],
            "args_append_target": True,
            "desc": "Port scanner & service fingerprinting. Gunakan HANYA untuk target yang diizinkan.",
            "output_limit": 2000,
            "when_to_use": "Soal network yang memberikan alamat IP target yang diizinkan.",
            "mitre_technique": "T1046"
        },
    },

    "log_analysis": {
        "grep_ip": {
            "cmd": ["grep", "-oE", r"\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"],
            "args_append_target": True,
            "desc": "Ekstrak semua alamat IP dari file log.",
            "output_limit": 2000,
            "when_to_use": "File log akses web (nginx/apache) untuk mencari IP sumber serangan.",
            "mitre_technique": "T1005"
        },
        "awk_top_ip": {
            "cmd": ["bash", "-c", "awk '{print $1}' %TARGET% | sort | uniq -c | sort -rn | head -20"],
            "args_template": True,
            "desc": "Temukan 20 IP dengan jumlah request terbanyak dari log NGINX/Apache. Cocok untuk soal DoS.",
            "output_limit": 1000,
            "when_to_use": "Log file nginx/apache — mencari IP penyerang (soal DoS/DDoS di slide).",
            "mitre_technique": "T1498"
        },
        "grep_useragent": {
            "cmd": ["bash", "-c", "grep -oP '\"([^\"]+)\"\\s+[0-9]+\\s+[0-9]+' %TARGET% | awk '{print $NF}' | sort | uniq -c | sort -rn | head -20"],
            "args_template": True,
            "desc": "Identifikasi User-Agent paling sering muncul di log. Bot/scanner biasanya sangat repetitif.",
            "output_limit": 1000,
            "when_to_use": "Log file web — mencari User-Agent mencurigakan (curl, python-requests, bot scanner).",
            "mitre_technique": "T1071.001"
        },
        "grep_sqli": {
            "cmd": ["grep", "-iE", r"(union|select|insert|drop|or\s+1=1|'--|benchmark|sleep\()", "--color=always"],
            "args_append_target": True,
            "desc": "Cari payload SQL Injection di log. Deteksi serangan SQLi seperti yang ada di slide.",
            "output_limit": 2000,
            "when_to_use": "Log web server — mencari payload SQLi (OR 1=1, UNION SELECT, dsb).",
            "mitre_technique": "T1190"
        },
        "grep_xss": {
            "cmd": ["grep", "-iE", r"(<script|onerror|onload|javascript:|alert\(|document\.cookie)", "--color=always"],
            "args_append_target": True,
            "desc": "Cari payload XSS di dalam log akses web.",
            "output_limit": 2000,
            "when_to_use": "Log web server — mencari upaya serangan Cross-Site Scripting.",
            "mitre_technique": "T1190"
        },
    },

    "web": {
        "curl": {
            "cmd": ["curl", "-v", "-L", "--max-time", "15"],
            "args_append_target": True,
            "desc": "HTTP client untuk menganalisis response header, cookie, dan konten web secara manual.",
            "output_limit": 3000,
            "timeout": 20.0,
            "when_to_use": "URL target web CTF — cek header, redirect, dan isi halaman.",
            "mitre_technique": "T1071.001"
        },
        "whatweb": {
            "cmd": ["whatweb", "--no-errors", "-a", "3"],
            "args_append_target": True,
            "desc": "Fingerprint teknologi web: CMS, framework, server, versi. Langkah awal wajib sebelum attack.",
            "output_limit": 2000,
            "timeout": 30.0,
            "when_to_use": "URL target web — identifikasi WordPress, PHP, Apache, Nginx, framework, dll.",
            "mitre_technique": "T1592.002"
        },
        "wafw00f": {
            "cmd": ["wafw00f"],
            "args_append_target": True,
            "desc": "Deteksi Web Application Firewall (WAF). Penting sebelum SQLi/XSS attack untuk tahu ada proteksi atau tidak.",
            "output_limit": 1500,
            "timeout": 30.0,
            "when_to_use": "URL target sebelum attack — cek apakah ada Cloudflare, ModSecurity, AWS WAF, dll.",
            "mitre_technique": "T1595.002"
        },
        "sqlmap": {
            "cmd": ["sqlmap", "-u", None, "--batch", "--level=3", "--risk=2", "--threads=4"],
            "args_target_index": 2,
            "desc": "Automated SQL Injection tool (level=3 untuk deteksi lebih komprehensif). HANYA untuk target yang diizinkan.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "URL dengan parameter GET/POST yang dicurigai vulnerable terhadap SQLi.",
            "mitre_technique": "T1190"
        },
        "sqlmap_full": {
            "cmd": ["sqlmap", "-u", None, "--batch", "--level=5", "--risk=3", "--threads=4",
                    "--dbs", "--dump-all", "--exclude-sysdbs", "--forms"],
            "args_target_index": 2,
            "desc": "SQLmap mode FULL: enumerate semua database, dump tabel users, cari username & password. HANYA untuk target yang diizinkan.",
            "output_limit": 3000,
            "timeout": 180.0,
            "when_to_use": "Soal CTF SQLi — dump semua data termasuk tabel users, kredensial, dan flag.",
            "mitre_technique": "T1190"
        },
        "nikto": {
            "cmd": ["nikto", "-h"],
            "args_append_target": True,
            "desc": "Web vulnerability scanner yang mencari misconfiguration dan celah umum.",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "URL target web CTF untuk menemukan direktori tersembunyi, celah default.",
            "mitre_technique": "T1595.002"
        },
        "gobuster": {
            "cmd": ["gobuster", "dir", "-u", None, "-w", "/usr/share/wordlists/dirb/common.txt", "-q", "-t", "50"],
            "args_target_index": 3,
            "desc": "Directory/endpoint brute-forcer cepat (50 threads) untuk menemukan halaman tersembunyi.",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "URL target web CTF — mencari direktori tersembunyi seperti /admin, /backup, /flag.",
            "mitre_technique": "T1595.003"
        },
        "dirb": {
            "cmd": ["dirb", None, "/usr/share/wordlists/dirb/common.txt", "-S", "-r"],
            "args_target_index": 1,
            "desc": "Directory brute-forcer klasik. Lebih lambat dari gobuster tapi output lebih verbose dengan detail kode HTTP.",
            "output_limit": 2000,
            "timeout": 90.0,
            "when_to_use": "Alternatif gobuster, terutama saat gobuster tidak tersedia atau perlu detail response.",
            "mitre_technique": "T1595.003"
        },
        "ffuf": {
            "cmd": ["ffuf", "-u", None, "-w", "/usr/share/wordlists/dirb/common.txt:FUZZ", "-mc", "200,301,302,403", "-c", "-s"],
            "args_target_index": 2,
            "desc": "Fast web fuzzer (alternatif gobuster yang lebih fleksibel). Support FUZZ placeholder di URL.",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "Web fuzzing untuk directory, parameter, atau virtual host enumeration.",
            "mitre_technique": "T1595.003"
        },
        "hydra_http_get": {
            "cmd": ["hydra", "-L", "/usr/share/wordlists/ctf_mini.txt", "-P",
                    "/usr/share/wordlists/ctf_mini.txt", "-t", "4", "-f"],
            "args_append_target": True,
            "desc": "Hydra: Login brute-force HTTP Basic Auth menggunakan CTF mini-wordlist. Temukan username & password.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "Target HTTP Basic Auth — coba kombinasi username & password umum CTF.",
            "mitre_technique": "T1110.001"
        },
        "hydra_ssh": {
            "cmd": ["hydra", "-L", "/usr/share/wordlists/ctf_mini.txt", "-P",
                    "/usr/share/wordlists/ctf_mini.txt", "-t", "4", "-f", "-s", "22"],
            "args_append_target": True,
            "desc": "Hydra: SSH login brute-force menggunakan CTF mini-wordlist.",
            "output_limit": 2000,
            "timeout": 120.0,
            "when_to_use": "Target SSH yang diizinkan — coba kombinasi username & password umum CTF.",
            "mitre_technique": "T1110.001"
        },
        "nmap_web": {
            "cmd": ["nmap", "-sV", "-p", "80,443,8080,8443,8888,3000,5000,9000",
                    "--script=http-title,http-headers,http-methods"],
            "args_append_target": True,
            "desc": "Nmap port scan khusus web: cek port HTTP/HTTPS, dapatkan HTTP title & headers.",
            "output_limit": 2000,
            "timeout": 60.0,
            "when_to_use": "Domain/IP target — temukan semua web service yang berjalan.",
            "mitre_technique": "T1046"
        },
        "jq": {
            "cmd": ["jq", "."],
            "args_append_target": True,
            "desc": "JSON query dan pretty-print. Berguna untuk menganalisis API response atau JSON yang berisi flag.",
            "output_limit": 3000,
            "timeout": 10.0,
            "when_to_use": "File JSON atau output API yang perlu di-parse untuk mencari data tersembunyi.",
            "mitre_technique": "T1005"
        },
    },

    "reverse_engineering": {
        "file": {
            "cmd": ["file"],
            "args_append_target": True,
            "desc": "Identifikasi arsitektur binary (ELF 32/64 bit, Windows PE, stripped/not stripped).",
            "output_limit": 500,
            "when_to_use": "Semua file binary.",
            "mitre_technique": "T1082"
        },
        "strings": {
            "cmd": ["strings", "-n", "6", "-t", "x"],
            "args_append_target": True,
            "desc": "Cari string di binary dengan offset. Sering menemukan flag hardcoded atau URL C2.",
            "output_limit": 3000,
            "when_to_use": "Binary ELF, PE — mencari string flag atau petunjuk lain.",
            "mitre_technique": "T1140"
        },
        "objdump": {
            "cmd": ["objdump", "-d", "-M", "intel"],
            "args_append_target": True,
            "desc": "Disassemble binary (Linux ELF) menjadi Assembly Intel. Analisis logika program.",
            "output_limit": 3000,
            "when_to_use": "Binary Linux ELF untuk memahami alur eksekusi dan mencari fungsi menarik.",
            "mitre_technique": "T1012"
        },
        "readelf": {
            "cmd": ["readelf", "-a"],
            "args_append_target": True,
            "desc": "Baca semua header ELF (section, symbol, dynamic links). Info penting untuk exploit.",
            "output_limit": 3000,
            "when_to_use": "Binary Linux ELF — melihat proteksi (NX, PIE, RELRO, Canary).",
            "mitre_technique": "T1012"
        },
        "checksec": {
            "cmd": ["checksec", "--file"],
            "args_append_target": True,
            "desc": "Cek proteksi binary: Stack Canary, NX, PIE, RELRO. Menentukan teknik exploit yang dipakai.",
            "output_limit": 500,
            "when_to_use": "Soal Pwn — langkah pertama sebelum mencari vulnerability.",
            "mitre_technique": "T1012"
        },
        "ltrace": {
            "cmd": ["ltrace"],
            "args_append_target": True,
            "desc": "Trace panggilan library C saat binary dieksekusi. Bisa melihat strcmp untuk bypass password.",
            "output_limit": 2000,
            "when_to_use": "Binary yang melakukan pengecekan password/input.",
            "mitre_technique": "T1012"
        },
        "strace": {
            "cmd": ["strace"],
            "args_append_target": True,
            "desc": "Trace system calls binary saat dieksekusi. Lihat file apa yang dibuka, network call, dsb.",
            "output_limit": 2000,
            "when_to_use": "Binary yang berinteraksi dengan sistem/file — lihat apa yang dilakukannya.",
            "mitre_technique": "T1012"
        },
    },

    "osint": {
        "whois": {
            "cmd": ["whois"],
            "args_append_target": True,
            "desc": "Cari informasi registrasi domain (owner, server, tanggal pendaftaran).",
            "output_limit": 2000,
            "when_to_use": "Diberikan nama domain — cari informasi pemiliknya.",
            "mitre_technique": "T1590.002"
        },
        "dig": {
            "cmd": ["dig", "ANY"],
            "args_append_target": True,
            "desc": "DNS lookup lengkap (A, MX, TXT, NS, CNAME). Rekaman DNS sering menyimpan flag.",
            "output_limit": 1500,
            "when_to_use": "Soal OSINT berbasis domain — cari TXT record yang sering dipakai menyembunyikan flag.",
            "mitre_technique": "T1590.002"
        },
        "nslookup": {
            "cmd": ["nslookup"],
            "args_append_target": True,
            "desc": "Query DNS server untuk domain atau IP tertentu.",
            "output_limit": 1000,
            "when_to_use": "Resolusi domain ke IP atau sebaliknya (reverse DNS).",
            "mitre_technique": "T1590.002"
        },
        "theHarvester": {
            "cmd": ["theHarvester", "-d", None, "-b", "all"],
            "args_target_index": 2,
            "desc": "Kumpulkan email, subdomain, IP, dan URL dari berbagai sumber publik.",
            "output_limit": 2000,
            "when_to_use": "Soal OSINT berbasis perusahaan atau domain — enumerasi aset publik.",
            "mitre_technique": "T1589"
        },
    },

    # ============================================================
    # KATEGORI BARU: OSINT GITHUB & SOC
    # ============================================================
    "osint_github": {
        "trufflehog": {
            "cmd": ["trufflehog", "git", None, "--only-verified"],
            "args_target_index": 2,
            "desc": "Mencari hardcoded credential, password, dan API keys di Git repository.",
            "output_limit": 3000,
            "when_to_use": "URL Git repository untuk mencari leaked credentials.",
            "mitre_technique": "T1592.004"
        },
        "gitleaks": {
            "cmd": ["gitleaks", "detect", "-v", "--repo-url"],
            "args_append_target": True,
            "desc": "Deteksi secrets dan hardcoded passwords menggunakan Gitleaks.",
            "output_limit": 3000,
            "when_to_use": "URL Git repository untuk mencari leaked credentials.",
            "mitre_technique": "T1592.004"
        },
        "git_log_all": {
            "cmd": ["git", "log", "-p", "--all"],
            "args_append_target": True,
            "desc": "Menampilkan seluruh riwayat commit dan perubahannya untuk mencari data terhapus.",
            "output_limit": 3000,
            "when_to_use": "Direktori lokal repository Git.",
            "mitre_technique": "T1592.004"
        },
    },

    "soc_triage": {
        "wazuh_agent_check": {
            "cmd": ["systemctl", "status", "wazuh-agent"],
            "args_append_target": False,
            "desc": "Memeriksa status Wazuh SIEM agent di server lokal.",
            "output_limit": 1000,
            "when_to_use": "Mengecek infrastruktur SOC/SIEM.",
            "mitre_technique": "T1082"
        },
        "alert_summary": {
            "cmd": ["cat", "/var/log/syslog"], # Dummy command for concept
            "args_append_target": True,
            "desc": "Meringkas log alert berdasarkan prioritas (CRITICAL, HIGH, MEDIUM, LOW).",
            "output_limit": 2000,
            "when_to_use": "Triage alert dari SIEM.",
            "mitre_technique": "T1005"
        },
    },

    "siem_integration": {
        "elk_health": {
            "cmd": ["curl", "-XGET", "http://localhost:9200/_cluster/health"],
            "args_append_target": False,
            "desc": "Memeriksa status Elasticsearch cluster (ELK Stack).",
            "output_limit": 1000,
            "when_to_use": "Troubleshooting SIEM ELK.",
            "mitre_technique": "T1082"
        },
        "splunk_status": {
            "cmd": ["/opt/splunk/bin/splunk", "status"],
            "args_append_target": False,
            "desc": "Memeriksa status layanan Splunk Enterprise.",
            "output_limit": 1000,
            "when_to_use": "Troubleshooting SIEM Splunk.",
            "mitre_technique": "T1082"
        },
    }
}

# ================================================================
# AI TOOL SELECTOR RULES — Panduan untuk AI Orchestrator
# Digunakan sebagai bagian dari system prompt AI.
# ================================================================

AI_TOOL_SELECTOR_PROMPT = """
Anda adalah KIIBOT — Senior CTF Solver & SOC Analyst (Blue Team).
Berdasarkan materi workshop "CTF as a Gateway to SOC", kategori Jeopardy CTF dan SOC Triage yang ada adalah:
1. Forensics — Analisis file, memory dump, disk image
2. Steganography — Data tersembunyi dalam media (gambar, audio)
3. Cryptography — Hash, cipher, RSA, enkripsi (Crypto -> Data Security)
4. Network/PCAP — Analisis traffic jaringan
5. Log Analysis — Analisis log web server (nginx/apache), SIEM alert
6. Web Exploitation — SQL Injection, XSS, SSRF (Web Exp -> WAF & SIEM)
7. Reverse Engineering & Pwn — Binary analysis, buffer overflow (RevEng -> Malware Analysis)
8. OSINT — Pengumpulan informasi dari sumber terbuka (OSINT -> Threat Intel / GitHub Credential Leaks)
9. SOC Triage — Prioritas penanganan insiden (CRITICAL, HIGH, MEDIUM, LOW) & SIEM

ATURAN PEMILIHAN TOOLS:
- Gambar (JPEG/PNG/BMP/GIF) → selalu mulai dengan: file, exiftool, strings, binwalk, zsteg/steghide
- File .pcap/.pcapng → selalu mulai dengan: tshark, tshark_http, tshark_follow
- File log (access.log, nginx.log) → mulai dengan: awk_top_ip, grep_sqli, grep_xss, grep_useragent, alert_summary
- File binary ELF/PE/Mach-O → mulai dengan: file, checksec, strings, objdump, readelf
- File .zip/.tar terpassword → mulai dengan: file, strings, john
- Teks hash/cipher → langsung: hashid, rsactftool (jika RSA), openssl
- URL web → curl, gobuster, nikto, sqlmap
- Git Repo URL → trufflehog, gitleaks

FLAG FORMAT yang dicari: KIIBOT{...}, CTF{...}, FLAG{...}, atau string yang terlihat seperti jawaban tantangan.

Selalu jalankan MINIMAL 5 tools dan MAKSIMAL 10 tools secara bersamaan untuk efisiensi.
Setelah semua tools selesai, buat Laporan Akhir berisi:
1. Ringkasan tipe soal & Mapping ke SOC Mindset (Misal: SQLi = Update WAF & Blokir IP)
2. Tool mana yang menemukan hint/flag
3. Jawaban/Flag (jika ditemukan)
4. Langkah mitigasi SOC selanjutnya (jika flag belum ditemukan / untuk menyelesaikan insiden)
"""

# ================================================================
# KATEGORI → TOOLS MAPPING (Untuk Fallback Tanpa AI)
# ================================================================

CATEGORY_TOOL_MAP = {
    "image":               ["file", "exiftool", "strings", "binwalk", "zsteg", "steghide", "stegseek", "pngcheck", "hexdump"],
    "pcap":                ["tshark", "tshark_http", "tshark_follow", "tcpdump"],
    "log":                 ["awk_top_ip", "grep_ip", "grep_sqli", "grep_xss", "grep_useragent", "alert_summary"],
    "binary_elf":          ["file", "checksec", "strings", "objdump", "readelf", "ltrace", "strace"],
    "archive":             ["file", "strings", "binwalk", "john"],
    "hash_text":           ["hashid", "hash_identifier", "john", "hashcat"],
    "web_url":             ["curl", "whatweb", "wafw00f", "gobuster", "ffuf", "nikto"],
    "web_attack":          ["curl", "whatweb", "wafw00f", "nmap_web", "gobuster", "nikto", "sqlmap"],
    "web_sqli":            ["sqlmap", "sqlmap_full", "curl", "whatweb"],
    "web_dir":             ["gobuster", "dirb", "ffuf", "nikto", "curl"],
    "web_bruteforce":      ["hydra_http_get", "hydra_ssh", "curl", "whatweb"],
    "web_full_battery":    ["curl", "whatweb", "wafw00f", "nmap_web", "gobuster", "ffuf", "nikto", "sqlmap"],
    "osint_domain":        ["whois", "dig", "nslookup", "theHarvester"],
    "osint_github":        ["trufflehog", "gitleaks"],
    "rsa_crypto":          ["openssl", "rsactftool"],
    "jwt_crypto":          ["jwt_tool"],
    "memory_dump":         ["file", "strings", "volatility3", "vol_pslist", "vol_netscan"],
    "pdf":                 ["file", "strings", "pdf_parser", "binwalk"],
    "json_data":           ["jq", "strings"],
    "soc_triage":          ["wazuh_agent_check", "alert_summary"],
    "siem_integration":    ["elk_health", "splunk_status"],
    "general":             ["file", "strings", "hexdump", "binwalk", "exiftool"],
}
