# 🛡️ KIIBOT — Panduan Deploy Lengkap ke VPS Linux

> Bot CTF Jeopardy & SOC Assistant dengan Expert-Level Concurrent Analysis

---

## Prasyarat VPS

| Kebutuhan | Minimum |
|---|---|
| OS | Ubuntu 22.04 / Debian 12 / Kali Linux |
| RAM | 2 GB (disarankan 4 GB) |
| Storage | 20 GB |
| Python | 3.10+ |

---

## Step 1 — Install Tools CTF & SOC Expert

```bash
chmod +x scripts/install_all_tools.sh
sudo bash scripts/install_all_tools.sh
```

Tools yang diinstall: tshark, tcpdump, tcpflow, zeek, binwalk, zsteg, steghide, ghidra, sqlmap, volatility3, john, hashcat, pwntools, angr, z3-solver, openai, dan 40+ lainnya.

---

## Step 2 — Setup Python Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -e .
pip install python-telegram-bot openai
```

---

## Step 3 — Konfigurasi API Keys AI

Edit `configs/ai_keys.json`:

```json
[
  "sk-key1-disini",
  "sk-key2-disini",
  "sk-key3-disini",
  "sk-key4-disini",
  "sk-key5-disini",
  "sk-key6-disini",
  "sk-key7-disini",
  "sk-key8-disini",
  "sk-key9-disini",
  "sk-key10-disini"
]
```

Provider yang disarankan: OpenAI, OpenRouter.ai, Groq (cepat & murah).

---

## Step 4 — Set Environment Variables

```bash
export TELEGRAM_BOT_TOKEN="7xxx:AAHxxx"
export TELEGRAM_CHAT_ID="-100xxx"
export AI_BASE_URL="https://api.openai.com/v1"
export AI_MODEL="gpt-4o"
```

---

## Step 5 — Jalankan Bot (Manual / Testing)

```bash
source venv/bin/activate
python scripts/kiibot_telegram_bot.py
```

---

## Step 6 — Systemd Service (Auto-Start di VPS)

Buat `/etc/systemd/system/kiibot.service`:

```ini
[Unit]
Description=KIIBOT Telegram Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/user/KIIBOTTOOLSCTF
Environment=TELEGRAM_BOT_TOKEN=7xxx:AAHxxx
Environment=TELEGRAM_CHAT_ID=-100xxx
Environment=AI_BASE_URL=https://api.openai.com/v1
Environment=AI_MODEL=gpt-4o
ExecStart=/home/user/KIIBOTTOOLSCTF/venv/bin/python scripts/kiibot_telegram_bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable kiibot
sudo systemctl start kiibot
sudo journalctl -u kiibot -f
```

---

## Daftar Command Bot

| Command | Fungsi |
|---|---|
| `/start` | Menu utama & status sistem |
| `/help` | Referensi command lengkap |
| `/soc` | Panduan 4-tahap alur kerja SOC Analyst |
| `/triage` | Simulator prioritas alert insiden |
| `/tools` | Daftar 40+ tools CTF & SOC |
| `/aikeys` | Status pool 10 API keys & failover |
| `/mitre T1190` | Detail teknik MITRE ATT&CK |
| `/decode <teks>` | Multi-stage auto-decode |
| `/analyze <payload>` | Deep AI analysis expert bertubi-tubi |
| Kirim `.pcap` | Expert Wireshark battery (8 tools paralel) |
| Kirim `.log` | Concurrent log battery (8 investigasi) |
| Kirim foto/screenshot | AI Vision: bedah soal CTF + tools + solusi |
| Kirim `.elf`/`.bin` | AI assess + concurrent reversing tools |

---

## AI Failover Cascade

```
Key 1 -> quota habis -> Key 2 -> error -> Key 3 -> ... -> Key 10
```

Jika semua key habis, bot tetap jalan mode offline (decoder lokal + tools VPS).

---

## Guardrail & Keamanan

| Tipe Konten | Aksi Bot |
|---|---|
| CTF soal, PCAP, log, binary, screenshot siber | DIPROSES PENUH |
| Teks cybersecurity / hash / payload / CVE | DIPROSES PENUH |
| Selfie, meme, obrolan umum, makanan | SILENT DROP (tidak dibalas) |
| Voice note, sticker, lokasi, video note | SILENT DROP |
| Unauthorized Chat ID | DITOLAK |

---

## Troubleshooting

**tshark permission denied:**
```bash
sudo usermod -aG wireshark $USER
sudo dpkg-reconfigure wireshark-common
```

**openai module not found:**
```bash
pip install openai
```

**Bot tidak respond:**
```bash
sudo journalctl -u kiibot -n 50
echo $TELEGRAM_BOT_TOKEN
```
