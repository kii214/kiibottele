# 🛡️ KIIBOT — Panduan Deploy di Ubuntu VPS

> Panduan lengkap instalasi KIIBOT di Ubuntu 22.04 LTS (VPS)

---

## Spesifikasi VPS yang Direkomendasikan

| Kebutuhan | Minimum | Direkomendasikan |
|---|---|---|
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| RAM | 2 GB | 4 GB |
| Storage | 20 GB | 40 GB |
| CPU | 1 vCPU | 2 vCPU |
| Python | 3.10+ | 3.11+ |

---

## Metode A: Deploy Native (Langsung di VPS) ✅ Direkomendasikan

### Step 1 — Login ke VPS dan Clone Repo

```bash
# Login SSH ke VPS
ssh root@IP_VPS_ANDA

# Clone repository
git clone https://github.com/kii214/kiibottele.git
cd kiibottele
```

### Step 2 — Install Semua Tools CTF

```bash
chmod +x scripts/install_all_tools.sh
sudo bash scripts/install_all_tools.sh
```

> **Catatan**: Script ini sudah dioptimalkan untuk Ubuntu 22.04.
> Package Kali-only akan di-skip secara otomatis.

### Step 3 — Setup Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -e .
pip install python-docx
```

### Step 4 — Konfigurasi Environment

```bash
# Copy dan edit file .env
nano .env
```

Isi nilai berikut di `.env`:
```env
TELEGRAM_BOT_TOKEN="TOKEN_DARI_BOTFATHER"
TELEGRAM_CHAT_ID="ID_CHAT_KAMU"
AI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
AI_MODEL="gemini-2.0-flash"
```

Untuk mendapatkan `TELEGRAM_CHAT_ID`:
- Buka Telegram → cari `@userinfobot` → ketik `/start`
- Salin angka ID yang diberikan

### Step 5 — Konfigurasi API Keys Gemini

File `configs/ai_keys.json` sudah berisi 3 API Key. Untuk menambah lebih banyak:

```bash
nano configs/ai_keys.json
```

```json
[
  "API_KEY_GEMINI_1",
  "API_KEY_GEMINI_2",
  "API_KEY_GEMINI_3"
]
```

### Step 6 — Test Jalankan Bot

```bash
source venv/bin/activate
python3 scripts/kiibot_telegram_bot.py
```

Jika berhasil, akan muncul:
```
[+] KIIBOT Bot aktif & siap mendengarkan (Polling mode)...
```

Buka Telegram dan kirim `/start` ke bot Anda.

### Step 7 — Setup Systemd Service (Auto-Start)

```bash
sudo nano /etc/systemd/system/kiibot.service
```

Isi dengan:
```ini
[Unit]
Description=KIIBOT Telegram CTF & SOC Bot
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/kiibottele
EnvironmentFile=/root/kiibottele/.env
ExecStart=/root/kiibottele/venv/bin/python3 scripts/kiibot_telegram_bot.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kiibot

[Install]
WantedBy=multi-user.target
```

> **Penting**: Sesuaikan `WorkingDirectory` dan `ExecStart` dengan lokasi folder Anda

```bash
# Aktifkan dan jalankan service
sudo systemctl daemon-reload
sudo systemctl enable kiibot
sudo systemctl start kiibot

# Cek status
sudo systemctl status kiibot

# Lihat log real-time
sudo journalctl -u kiibot -f
```

---

## Metode B: Deploy via Docker 🐳

### Step 1 — Install Docker di Ubuntu

```bash
# Install Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo apt-get install docker-compose-plugin -y
```

### Step 2 — Clone dan Konfigurasi

```bash
git clone https://github.com/kii214/kiibottele.git
cd kiibottele

# Edit .env
nano .env
```

### Step 3 — Build dan Jalankan

```bash
# Build Docker image (pertama kali, butuh waktu ~10-20 menit)
docker compose build

# Jalankan di background
docker compose up -d

# Lihat log
docker compose logs -f kiibot
```

### Step 4 — Perintah Docker Berguna

```bash
# Cek status container
docker compose ps

# Stop bot
docker compose down

# Restart bot
docker compose restart kiibot

# Update dan restart
git pull
docker compose build
docker compose up -d
```

---

## Troubleshooting Ubuntu

### ❌ tshark: Permission denied
```bash
sudo usermod -aG wireshark $USER
sudo dpkg-reconfigure wireshark-common
# Pilih "Yes" saat ditanya
newgrp wireshark
```

### ❌ wkhtmltopdf error (untuk fitur /report)
```bash
sudo apt-get install -y wkhtmltopdf
# Atau download versi lengkap:
wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.jammy_amd64.deb
sudo dpkg -i wkhtmltox_0.12.6.1-2.jammy_amd64.deb
sudo apt-get install -f -y
```

### ❌ Package tidak ditemukan di Ubuntu
```bash
# Aktifkan universe repo
sudo add-apt-repository universe -y
sudo apt-get update
```

### ❌ Bot tidak merespon
```bash
# Cek log
sudo journalctl -u kiibot -n 50
# atau
docker compose logs --tail=50 kiibot

# Cek apakah token terbaca
grep TELEGRAM_BOT_TOKEN .env
```

### ❌ openai module not found
```bash
source venv/bin/activate
pip install openai python-telegram-bot
```

### ❌ Git Clone Minta Password / Authentication Failed 403
```bash
# Gunakan Personal Access Token (PAT) langsung di URL clone:
git clone https://YOUR_TOKEN@github.com/kii214/kiibottele.git
# Atau ubah repository Anda dari Private menjadi Public di Settings GitHub
```

---

## Daftar Command Bot

| Command | Fungsi |
|---|---|
| `/start` | Menu utama & status sistem |
| `/help` | Referensi command lengkap |
| `/soc` | Panduan 4-tahap alur kerja SOC |
| `/triage` | Simulator prioritas alert insiden |
| `/tools` | Daftar 40+ tools CTF & SOC |
| `/doctor` | Diagnosa tools yang terinstall di VPS |
| `/aikeys` | Status pool 3 API Keys Gemini & failover |
| `/mitre T1190` | Detail teknik MITRE ATT&CK |
| `/decode <teks>` | Multi-stage auto-decode |
| `/analyze <payload>` | Deep AI analysis expert |
| `/reportsoc` | **Generator Laporan SOC Konsolidasi Multi-Tugas (Word .docx & PDF)** |
| Kirim `.pcap` | Expert Wireshark battery (8 tools paralel) |
| Kirim `.log` | Concurrent log battery (8 investigasi) |
| Kirim foto/screenshot | AI Vision: bedah soal CTF + tools + solusi |
| Kirim `.elf`/`.bin` | AI assess + concurrent reversing tools |

---

## Checklist Sebelum Go-Live

- [ ] `TELEGRAM_BOT_TOKEN` sudah diisi di `.env`
- [ ] `TELEGRAM_CHAT_ID` sudah diisi di `.env`
- [ ] `configs/ai_keys.json` berisi API Key Gemini
- [ ] `sudo bash scripts/install_all_tools.sh` berhasil dijalankan
- [ ] Test `/start` berhasil direspon bot
- [ ] Test `/doctor` untuk cek tools yang terinstall
- [ ] Test `/aikeys` untuk cek status API Key
- [ ] Systemd service sudah aktif (`sudo systemctl status kiibot`)
