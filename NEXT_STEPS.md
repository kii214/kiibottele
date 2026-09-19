# 🚀 KIIBOT — NEXT STEPS & QUICK EXECUTION GUIDE

Panduan lengkap perintah siap pakai (*copy-paste & run*) untuk menjalankan KIIBOT, instalasi seluruh tools ke lokal, fitur analisis file, auto-solver, flag hunter, dan modul spesifik lomba CTF.

---

## ⚡ 1. Menjalankan KIIBOT Sekarang

### A. Di Windows (PowerShell)

```powershell
# 1. Jalankan Menu Interaktif Utama (ASCII Banner & Menu 01-26)
py -3.11 -m kiibot.cli.main

# 2. Cek Versi & Bantuan
py -3.11 -m kiibot.cli.main --version
py -3.11 -m kiibot.cli.main --help

# 3. Jalankan System Diagnostics (Doctor)
py -3.11 -m kiibot.cli.main doctor

# 4. Instalasi Tools Lokal (Dry-run & Eksekusi)
py -3.11 -m kiibot.cli.main tools install --all --dry-run
py -3.11 -m kiibot.cli.main tools install --category crypto
.\scripts\install_all_tools.ps1
```

### B. Di Linux / Kali Linux / WSL2

```bash
# 1. Instalasi Otomatis Lengkap Sekaligus Semua Tools
chmod +x install.sh
./install.sh --all-tools

# Atau jalankan script paket komprehensif:
chmod +x scripts/install_all_tools.sh
./scripts/install_all_tools.sh

# 2. Jalankan KIIBOT langsung lewat CLI global:
kiibot
kiibot doctor --verbose
```

---

## 🎯 2. Perintah Analisis & Solver Lomba CTF

### A. Deep File Analyzer (`kiibot analyze`)
Analisis otomatis mendeteksi magic bytes (50+ format), Shannon Entropy meter, cryptographic hashes, strings, dan Checksec biner.

```bash
# Analisis file challenge apapun (ELF, PE, PCAP, ZIP, PNG, PDF, dll.)
kiibot analyze challenge.bin
kiibot analyze image.png
```

### B. Universal Recursive Auto-Solver (`kiibot solve`)
Auto-unwrapping bertingkat (`Base64` ➔ `Hex` ➔ `ROT13` ➔ `XOR` ➔ `Flag`) dengan ranking skor kecerdasan buatan/frekuensi bahasa.

```bash
# Solve cipher / token otomatis
kiibot solve "ZmxhZ3tzb2x2ZWRfc3VjY2Vzc2Z1bGx5fQ=="
kiibot solve "666c61677b6865785f736f6c7665647d"
kiibot solve "uryyb_synt_vf_urer" --depth 6
```

### C. Flag Hunter & Database Manager (`kiibot flag`)
Cari, validasi, dan simpan flag yang berhasil Anda dapatkan ke dalam database SQLite lokal.

```bash
# Cari flag di dalam string, file dump, atau direktori secara rekursif:
kiibot flag find "some memory dump text CTF{found_flag} ..."
kiibot flag find ./challenges/forensics_01/

# Tambahkan flag yang berhasil di-capture ke database:
kiibot flag add "flag{pwn_remote_leak_success}" --points 500 --challenge pwn-01

# Tampilkan daftar semua flag yang berhasil didapatkan:
kiibot flag list

# Verifikasi format flag:
kiibot flag verify "flag{sample_flag}"
```

### D. Modul Kriptografi (`kiibot crypto`)

```bash
# Auto-decode segala jenis encoding
kiibot crypto decode "SGVsbG8gV29ybGQ="

# Brute-force 25 pergeseran Caesar / ROT
kiibot crypto caesar "uryyb_jbeyq"

# Single-byte XOR brute force (0-255)
kiibot crypto xor "\x15\x1e\x13\x15"

# Identifikasi jenis hash dan hitung digest
kiibot crypto hash "5d41402abc4b2a76b9719d911017c592"

# CTF RSA attack (Small e & Wiener's attack)
kiibot crypto rsa --n 109727 --e 46687 --c 1337
```

### E. Modul Binary Exploitation (`kiibot pwn`)

```bash
# Pengecekan mitigasi biner (NX, PIE, Canary, RELRO, ASLR, DEP)
kiibot pwn checksec ./vuln

# Generate De Bruijn cyclic pattern (panjang 100 bytes)
kiibot pwn cyclic 100

# Cari offset crash buffer overflow dari string / hex register
kiibot pwn cyclic -l baaa
kiibot pwn cyclic -l 0x61616162
```

### F. Modul Steganografi & Web (`kiibot steg` & `kiibot web`)

```bash
# Analisis chunk PNG & deteksi payload tersembunyi
kiibot steg analyze suspect.png

# Ekstraksi payload bytes setelah chunk IEND
kiibot steg extract suspect.png -o hidden_payload.bin

# Audit token JWT & kerentanan algoritma
kiibot web jwt "eyJhbGciOiJIUzI1Ni..."
```

### G. Modul Forensik & Jaringan (`kiibot forensics` & `kiibot pcap`)

```bash
# Triage forensik archive / memory dump & carving embedded files
kiibot forensics evidence.raw --carve

# Analisis packet capture PCAP (HTTP, DNS, Credentials, Flag hunt)
kiibot pcap capture.pcap
```

---

## 🧪 3. Menjalankan Pengujian Unit (Pytest)

Validasi 100% dari seluruh modul (Database, CLI, Workspaces, Registry, Doctor, Analyzer, Solvers, RSA, PWN, Forensics, PCAP, Installer):

```powershell
# Di Windows PowerShell:
py -3.11 -m pytest -v
```

```bash
# Di Linux / macOS / WSL:
pytest -v
```

Semua 38 unit test dipastikan lulus (**100% PASSED**).
