"""
KIIBOT AI Orchestrator — Cascading Multi-API Key Failover Pool
Mendukung hingga 10+ API Keys dengan auto-failover:
Jika Key 1 kuota habis / rate limit (429/401/insufficient_quota),
otomatis beralih ke Key 2, jika Key 2 habis ke Key 3, dan seterusnya.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

try:
    from openai import AsyncOpenAI
    HAS_OPENAI = True
except ImportError:
    AsyncOpenAI = None
    HAS_OPENAI = False

logger = logging.getLogger(__name__)


class AIOrchestrator:
    # Class-level state agar index aktif dipertahankan antar request (Singleton State)
    _active_key_index: int = 0
    _exhausted_keys: set = set()

    def __init__(self):
        self.base_url = os.getenv("AI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")
        self.model = os.getenv("AI_MODEL", "gemini-2.0-flash")
        self.api_keys: list[str] = self._load_api_keys()
        # Reset state agar key yang sebelumnya gagal karena bug auth dicoba ulang
        AIOrchestrator._active_key_index = 0
        AIOrchestrator._exhausted_keys.clear()

    def _load_api_keys(self) -> list[str]:
        """
        Memuat daftar API Keys dari berbagai sumber prioritas:
        1. configs/ai_keys.json (array string json)
        2. configs/ai_keys.txt (satu baris satu key)
        3. Environment variable AI_API_KEYS (dipisah koma)
        4. Environment variables AI_API_KEY_1 sampai AI_API_KEY_10
        5. Environment variable tunggal AI_API_KEY
        """
        keys: list[str] = []

        def is_placeholder(k: str) -> bool:
            k_lower = k.lower()
            return "masukkan" in k_lower or "ganti" in k_lower or "dummy" in k_lower or "example" in k_lower

        # 1. Cek configs/ai_keys.json
        possible_json_paths = [
            Path("configs/ai_keys.json"),
            Path(__file__).resolve().parent.parent.parent.parent / "configs" / "ai_keys.json"
        ]
        for path in possible_json_paths:
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for k in data:
                                if isinstance(k, str) and k.strip() and not is_placeholder(k.strip()):
                                    keys.append(k.strip())
                            if keys:
                                logger.info(f"[AI POOL] Berhasil memuat {len(keys)} API keys dari {path}")
                                return keys
                except Exception as e:
                    logger.warning(f"Gagal membaca {path}: {e}")

        # 2. Cek configs/ai_keys.txt
        possible_txt_paths = [
            Path("configs/ai_keys.txt"),
            Path(__file__).resolve().parent.parent.parent.parent / "configs" / "ai_keys.txt"
        ]
        for path in possible_txt_paths:
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        for line in f:
                            cleaned = line.strip()
                            if cleaned and not cleaned.startswith("#") and not is_placeholder(cleaned):
                                keys.append(cleaned)
                    if keys:
                        logger.info(f"[AI POOL] Berhasil memuat {len(keys)} API keys dari {path}")
                        return keys
                except Exception as e:
                    logger.warning(f"Gagal membaca {path}: {e}")

        # 3. Cek environment variable AI_API_KEYS (comma-separated)
        env_multi = os.getenv("AI_API_KEYS")
        if env_multi:
            for k in env_multi.split(","):
                cleaned = k.strip()
                if cleaned:
                    keys.append(cleaned)
            if keys:
                logger.info(f"[AI POOL] Berhasil memuat {len(keys)} API keys dari env AI_API_KEYS")
                return keys

        # 4. Cek AI_API_KEY_1 sampai AI_API_KEY_10
        for i in range(1, 11):
            k = os.getenv(f"AI_API_KEY_{i}")
            if k and k.strip():
                keys.append(k.strip())
        if keys:
            logger.info(f"[AI POOL] Berhasil memuat {len(keys)} API keys dari AI_API_KEY_1..10")
            return keys

        # 5. Cek single AI_API_KEY
        single_key = os.getenv("AI_API_KEY")
        if single_key and single_key.strip():
            keys.append(single_key.strip())
            logger.info("[AI POOL] Menggunakan 1 API key dari env AI_API_KEY")

        return keys

    def is_available(self) -> bool:
        """Cek apakah ada API key yang valid dan belum habis kuotanya."""
        if not HAS_OPENAI or not self.api_keys:
            return False
        # Cek apakah masih ada key yang belum exhausted
        for idx in range(len(self.api_keys)):
            if idx not in AIOrchestrator._exhausted_keys:
                return True
        return False

    def get_status_info(self) -> dict:
        """Mengembalikan informasi status pool API keys saat ini."""
        total = len(self.api_keys)
        exhausted_count = len(AIOrchestrator._exhausted_keys)
        current_idx = AIOrchestrator._active_key_index
        return {
            "total_keys": total,
            "active_key_index": current_idx + 1 if total > 0 else 0,
            "exhausted_keys_count": exhausted_count,
            "remaining_keys": max(0, total - exhausted_count),
            "model": self.model,
            "available": self.is_available()
        }

    def _get_client_for_key(self, api_key: str) -> Any | None:
        """Inisialisasi AsyncOpenAI client untuk key tertentu."""
        if not HAS_OPENAI or not AsyncOpenAI:
            return None

        is_gemini = "generativelanguage.googleapis.com" in self.base_url

        if is_gemini:
            # Key format AQ.Ab8... (GCP Service Account bound key) membutuhkan
            # x-goog-api-key header TANPA Authorization Bearer agar tidak konflik.
            # Key format AIzaSy... (standard API key) bisa pakai keduanya.
            is_new_format = api_key.startswith("AQ.")
            headers = {"x-goog-api-key": api_key}

            if is_new_format:
                # Gunakan dummy api_key agar SDK tidak kirim "Authorization: Bearer AQ..."
                # yang akan ditolak Google sebagai ACCESS_TOKEN_TYPE_UNSUPPORTED
                return AsyncOpenAI(
                    api_key="GEMINI",
                    base_url=self.base_url,
                    default_headers=headers
                )
            else:
                return AsyncOpenAI(
                    api_key=api_key,
                    base_url=self.base_url,
                    default_headers=headers
                )

        return AsyncOpenAI(api_key=api_key, base_url=self.base_url)

    def _is_quota_or_auth_error(self, error: Exception) -> bool:
        """Mendeteksi apakah error disebabkan oleh kuota habis, rate limit, atau token invalid."""
        err_str = str(error).lower()
        quota_indicators = [
            "rate_limit", "ratelimit", "429", "insufficient_quota", "quota_exceeded",
            "exceeded your current quota", "billing", "credit", "credits",
            "authenticationerror", "invalid_api_key", "401", "unauthorized"
        ]
        return any(ind in err_str for ind in quota_indicators)

    async def call_chat_completion(
        self,
        messages: list[dict[str, str]],
        response_format: dict[str, str] | None = None,
        temperature: float = 0.7
    ) -> str:
        """
        Eksekusi chat completion dengan failover cascade multi-key (1 sampai 10+).
        Jika key saat ini error (kuota habis/429/401), langsung lanjut ke key berikutnya.
        """
        if not HAS_OPENAI or not self.api_keys:
            raise RuntimeError("OpenAI module atau API keys tidak tersedia.")

        total_keys = len(self.api_keys)
        attempts = 0

        while attempts < total_keys:
            curr_idx = AIOrchestrator._active_key_index
            if curr_idx >= total_keys:
                # Loop kembali ke 0 jika mencapai ujung (untuk mengecek apakah ada key yang reset)
                curr_idx = 0
                AIOrchestrator._active_key_index = 0

            # Lewati jika key ini sudah ditandai exhausted
            if curr_idx in AIOrchestrator._exhausted_keys and len(AIOrchestrator._exhausted_keys) < total_keys:
                AIOrchestrator._active_key_index = (curr_idx + 1) % total_keys
                attempts += 1
                continue

            current_key = self.api_keys[curr_idx]
            masked_key = f"{current_key[:6]}...{current_key[-4:]}" if len(current_key) > 10 else "***"
            client = self._get_client_for_key(current_key)

            if not client:
                raise RuntimeError("AsyncOpenAI client gagal diinisialisasi.")

            logger.info(f"[AI POOL] Mengirim request dengan API Key #{curr_idx + 1} ({masked_key})")

            try:
                kwargs: dict[str, Any] = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": temperature,
                }
                if response_format:
                    kwargs["response_format"] = response_format

                response = await client.chat.completions.create(**kwargs)
                return response.choices[0].message.content or ""

            except Exception as e:
                logger.error(f"[AI POOL] Error pada API Key #{curr_idx + 1}: {e}")

                if self._is_quota_or_auth_error(e):
                    # Tandai key ini habis kuotanya
                    AIOrchestrator._exhausted_keys.add(curr_idx)
                    next_idx = (curr_idx + 1) % total_keys
                    logger.warning(
                        f"[AI POOL FAILOVER] ⚠️ API Key #{curr_idx + 1} kuota habis / rate-limited! "
                        f"Otomatis beralih ke API Key #{next_idx + 1}..."
                    )
                    AIOrchestrator._active_key_index = next_idx
                    attempts += 1
                else:
                    # Error lain (misal syntax prompt atau server 500), coba key berikutnya juga jika ada
                    logger.warning(f"[AI POOL] Percobaan gagal dengan key #{curr_idx + 1}. Mencoba key cadangan...")
                    AIOrchestrator._active_key_index = (curr_idx + 1) % total_keys
                    attempts += 1

        raise RuntimeError(f"Semua {total_keys} API Key telah dicoba dan kuotanya habis atau tidak valid!")

    async def ask_ai(self, user_question: str, system_prompt: str = "") -> str:
        """Helper praktis untuk menanyakan pertanyaan umum ke AI dengan failover aktif."""
        messages = []
        
        # GLOBAL GUARDRAIL: Strict accuracy and no hallucination rule
        global_guardrail = (
            "\n\n[GLOBAL RULE - WAJIB DIPATUHI SECARA MUTLAK]: "
            "Anda bertindak di dalam lingkungan operasional Cybersecurity tingkat lanjut. "
            "Jawablah dengan FAKTA TEKNIS YANG 100% AKURAT. DILARANG KERAS MENGARANG (HALLUCINATION), "
            "BERASUMSI, ATAU MEMBERIKAN SOLUSI YANG TIDAK MASUK AKAL. Jika informasi spesifik tidak "
            "tersedia di log/dokumen/soal, nyatakan secara eksplisit bahwa Anda tidak tahu. "
            "Konsisten dengan standar Cybersecurity dan metodologi best practice yang nyata."
        )
        
        final_sys_prompt = system_prompt + global_guardrail if system_prompt else global_guardrail
        messages.append({"role": "system", "content": final_sys_prompt})
        messages.append({"role": "user", "content": user_question})
        return await self.call_chat_completion(messages=messages)

    async def assess_challenge(self, text_context: str, file_name: str) -> dict:
        """
        Menganalisis berkas atau tantangan dan memilih daftar tools menggunakan AI (dengan failover).
        """
        from kiibot.core.tool_registry import AI_TOOL_SELECTOR_PROMPT, CATEGORY_TOOL_MAP

        if not self.is_available():
            logger.warning("[AI POOL] AI tidak tersedia/habis kuota. Menggunakan deteksi statis.")
            ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
            fallback_map = {
                "png": "image", "jpg": "image", "jpeg": "image", "bmp": "image", "gif": "image",
                "pcap": "pcap", "pcapng": "pcap",
                "log": "log", "txt": "log",
                "elf": "binary_elf", "exe": "binary_elf", "bin": "binary_elf",
                "zip": "archive", "tar": "archive", "gz": "archive",
                "mem": "memory_dump", "vmem": "memory_dump", "dmp": "memory_dump",
            }
            cat = fallback_map.get(ext, "general")
            return {"category": cat, "tools": CATEGORY_TOOL_MAP.get(cat, CATEGORY_TOOL_MAP["general"])}

        prompt = f"""
{AI_TOOL_SELECTOR_PROMPT}

---
INPUT YANG DITERIMA:
Nama File : {file_name}
Deskripsi : {text_context}

Berikan HANYA JSON valid:
{{
    "category": "nama_kategori",
    "tools": ["tool1", "tool2", "tool3", ...]
}}
        """

        try:
            content = await self.call_chat_completion(
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"}
            )
            return json.loads(content)
        except Exception as e:
            logger.error(f"Gagal memanggil AI untuk assess_challenge: {e}")
            return {"category": "error", "tools": ["file", "strings"]}

    async def analyze_results(self, tool_outputs: dict, previous_context: str) -> str:
        """
        Menganalisis hasil tools secara simultan (dengan failover cascading multi-key).
        Membatasi budget karakter per tool secara cerdas agar semua tools terwakili.
        """
        if not self.is_available():
            return "AI tidak aktif atau kuota semua key telah habis. Periksa log output tools secara manual."

        # Budget karakter per tool ditingkatkan agar capture output lengkap di laporan
        CHARS_PER_TOOL = 3000
        TOTAL_BUDGET = 14000
        formatted_outputs = {}
        for tool_name, output in tool_outputs.items():
            if isinstance(output, str):
                if len(output) > CHARS_PER_TOOL:
                    formatted_outputs[tool_name] = output[:CHARS_PER_TOOL] + f"\n... [TRUNCATED — {len(output)} chars total]"
                else:
                    formatted_outputs[tool_name] = output
            elif isinstance(output, (dict, list)):
                dumped = json.dumps(output, indent=2, ensure_ascii=False)
                if len(dumped) > CHARS_PER_TOOL:
                    formatted_outputs[tool_name] = dumped[:CHARS_PER_TOOL] + "\n... [TRUNCATED]"
                else:
                    formatted_outputs[tool_name] = output
            else:
                formatted_outputs[tool_name] = str(output)

        outputs_str = json.dumps(formatted_outputs, indent=2, ensure_ascii=False)[:TOTAL_BUDGET]

        system_prompt = (
            "You are a Tier-3 SOC Incident Responder, Threat Hunter, and DFIR Specialist with expertise in CTF challenges.\n"
            "Your role is to produce a professional, executive-grade Security Incident Analysis Report.\n\n"
            "STRICT INTEGRITY RULES:\n"
            "1. Report ONLY findings that are explicitly present in the tool outputs below. Do NOT fabricate flags, credentials, or IPs.\n"
            "2. Write in professional Bahasa Indonesia. Avoid excessive emoji — use only where structurally meaningful.\n"
            "3. Be analytical and narrative, not just a list. Explain what each finding means operationally.\n"
            "4. Every tool's key output must appear verbatim in the Capture/Evidence section.\n"
            "5. The report must be immediately usable by a SOC analyst for decision-making."
        )

        user_prompt = f"""Konteks Target / Kasus:
{previous_context}

Output Eksekusi Tools (Verbatim):
{outputs_str}

---

Susun laporan dalam format Markdown profesional berikut. Gunakan bahasa yang lugas, naratif, dan taktis.
Jangan kaku — laporan harus enak dibaca namun tetap teknis dan presisi.

---

# SECURITY INCIDENT & THREAT ANALYSIS REPORT
**Disusun oleh:** KIIBOT SOC Engine  
**Klasifikasi:** CONFIDENTIAL — Internal Use Only

---

## I. Executive Summary

Tulis narasi 3–5 kalimat yang menjelaskan secara ringkas: apa yang diselidiki, apa yang ditemukan,
dan seberapa kritis temuan tersebut. Hindari poin-poin di bagian ini — tulis seperti laporan eksekutif.

**Severity Level:** [CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL]  
**Attack Category:** [Web Exploitation / Network Forensics / Binary Reversing / Steganography / Recon / Malware]

---

## II. Temuan Per-Tool (Evidence Capture)

Untuk setiap tool yang dieksekusi, buat sub-bagian berisi:
- Narasi singkat apa yang tool lakukan
- Output kunci yang relevan ditampilkan dalam code block
- Interpretasi teknis temuan tersebut

Contoh format:

### [Nama Tool]
[Narasi singkat tujuan tool]

```
[Output verbatim tool yang paling relevan — jangan potong temuan penting]
```

**Interpretasi:** [Apa arti temuan ini? Apa implikasinya?]

Lakukan untuk SEMUA tool yang menghasilkan output bermakna.

---

## III. Korelasi & Attack Chain Analysis

Hubungkan temuan antar-tool secara naratif. Jelaskan bagaimana temuan dari tool A berkaitan
dengan tool B, dan bagaimana ini membentuk gambaran serangan yang lebih besar atau vektor
eksploitasi yang dapat digunakan.

---

## IV. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Keterangan |
|--------|-------------|----------------|------------|
| [Tactic] | [T-ID] | [Nama Teknik] | [Korelasi ke temuan] |

---

## V. Indicators of Compromise (IOCs)

| Tipe | Nilai | Keterangan |
|------|-------|------------|
| IP Address | — | — |
| Domain/URL | — | — |
| Hash (MD5/SHA) | — | — |
| Flag / Credential | — | — |

Isi dengan data nyata dari tool output. Jika tidak ada, tulis "Tidak ditemukan pada analisis ini."

---

## VI. SOC Containment & Mitigation Playbook

Tulis langkah-langkah penanganan yang konkret dan dapat langsung dieksekusi:

**Immediate Containment:**
[Tindakan blokir, isolasi, atau shutdown yang perlu dilakukan segera]

**Detection Rules (SIEM/IDS):**
```
[Contoh rule Suricata / Sigma / SPL query yang relevan jika ada]
```

**Remediation & Hardening:**
[Langkah perbaikan sistem jangka panjang]

---

## VII. Next Steps — Advanced Investigation Commands

Berikan perintah Linux CLI nyata dan presisi untuk investigasi lanjutan di VPS:

```bash
# [Deskripsi tujuan command]
[command]
```

---

Sajikan laporan ini secara lengkap, menyeluruh, dan tajam. Semua temuan dari tools harus masuk."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        try:
            return await self.call_chat_completion(messages=messages, temperature=0.25)
        except Exception as e:
            logger.error(f"Gagal memanggil AI analyze_results: {e}")
            return f"[ERROR] Terjadi kesalahan saat AI menganalisis hasil: {e!s}"

    async def assess_soc_severity(self, alert_context: str) -> str:
        """
        Menilai severity alert SOC (CRITICAL, HIGH, MEDIUM, LOW) dengan failover multi-key.
        """
        if not self.is_available():
            return "AI tidak aktif atau kuota semua key telah habis. Triage manual diperlukan."

        prompt = f"""
Anda adalah SOC Analyst L2. Triage alert berikut berdasarkan keparahan (severity).

Alert Context: {alert_context}

Berikan klasifikasi severity:
- CRITICAL: Data exfiltration, malware aktif di sistem penting, dsb.
- HIGH: Serangan aktif terdeteksi (SQLi, XSS berhasil).
- MEDIUM: Upaya pemindaian (scanning), payload SQLi gagal.
- LOW: Multiple failed logins pada akun non-admin, anomali kecil.

Jelaskan alasan penetapan severity tersebut secara singkat.
        """
        try:
            return await self.call_chat_completion(
                messages=[{"role": "user", "content": prompt}]
            )
        except Exception as e:
            logger.error(f"Gagal memanggil AI assess_soc_severity: {e}")
            return "Terjadi kesalahan saat AI melakukan triage."

    async def analyze_challenge_image(self, image_path: str, caption: str = "") -> str:
        """
        Menganalisis gambar soal / screenshot tantangan menggunakan AI Vision (GPT-4o dsb.).
        Mengembalikan laporan detail konsep soal, kategori, tools yang tepat di VPS,
        ekstraksi teks, langkah penyelesaian, dan translasi SOC.
        Jika gambar BUKAN topik CTF/SOC/Cyber, mengembalikan '[OUT_OF_CONTEXT]'.
        """
        if not self.is_available():
            return "AI Vision tidak aktif (API Key belum diset atau habis kuotanya). Lakukan analisis manual menggunakan tools stego."

        import base64
        try:
            with open(image_path, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode("utf-8")
        except Exception as e:
            logger.error(f"Gagal membaca gambar {image_path}: {e}")
            return f"Gagal membaca berkas gambar: {e}"

        ext = image_path.rsplit(".", 1)[-1].lower() if "." in image_path else "jpg"
        mime = "image/png" if ext == "png" else "image/jpeg"

        system_prompt = """Anda adalah Principal Security Researcher, Grandmaster CTF Solver, dan Senior SOC L3 / DFIR Lead.
Tugas Anda adalah menganalisis screenshot soal Jeopardy CTF / challenge cyber / alert SOC secara menyeluruh dan mendalam.

ATURAN STRICT GUARDRAIL (SANGAT PENTING):
1. Evaluasi apakah gambar ini terkait dengan topik: Cybersecurity, CTF, Soal Lomba Cyber, Alert SOC, Log Server, Kode Program, Network Packet/Wireshark, Kriptografi, Steganografi, Reverse Engineering, Forensic Disk/Memori, atau Linux Terminal.
2. JIKA GAMBAR INI JELAS DI LUAR KONTEKS (selfie, foto manusia/wajah, makanan, anime/meme non-cyber, pemandangan, dokumen pribadi), JAWABLAH HANYA 1 KATA:
[OUT_OF_CONTEXT]

ATURAN VALIDITAS & ANTI-HALUSINASI (DILARANG KERAS MENGARANG):
- DILARANG KERAS MENGARANG ATAU MENGHALUSINASIKAN FLAG, NILAI HASH, ATAU DATA YANG TIDAK TERLIHAT DI GAMBAR!
- Jika flag tidak langsung terbaca di gambar, katakan dengan jujur dan berikan perintah exact untuk mengekstraknya menggunakan tools di VPS.
- JANGAN PERNAH MENYERAH: Selalu sediakan rute penyelesaian alternatif (fallback) jika rute utama buntu."""

        user_text = f"""Keterangan Tambahan Pengguna: "{caption if caption else 'Analisis gambar soal ini secara mendalam'}"

Buat Laporan Investigasi Expert dengan format Markdown berikut (Harap sediakan penjelasan yang sangat mendetail, teknis, dan komprehensif, HINDARI penggunaan emoji):
1. KLASIFIKASI SOAL & KONSEP KERENTANAN:
   - Kategori spesifik (contoh: *Network Forensics (Wireshark PCAP)*, *Web Exploitation (Blind SQLi / SSRF)*, *Reverse Engineering (Anti-Debugging / VM)*, *Crypto (Coppersmith RSA / CBC Bitflipping)*).
   - Analisis skenario ancaman / mekanisme tantangan.
2. BEDAH DETAIL & EKSTRAKSI TEKS/KODE/LOG:
   - Transkrip presisi dari apa yang tertulis di gambar (URL, payload, register biner, IP sumber/tujuan, cuplikan kode, atau petunjuk teks).
3. TOOLS TINGKAT EXPERT DI VPS & BARIS PERINTAH PRESISI:
   - Daftar tools profesional yang terpasang di VPS (contoh: tshark, tcpflow, zeek, ghidra, pwntools, z3, volatility3, sqlmap, hashcat, stegseek, ffuf).
   - Berikan syntax perintah exact & akurat siap salin-tempel (copy-paste) untuk dijalankan di terminal Linux VPS.
4. METODOLOGI SOLUSI MENDALAM (JIKA BUNTU -> JALUR ALTERNATIF):
   - Langkah teknis bertahap untuk memecahkan soal hingga tuntas secara detail.
   - Skenario fallback jika cara pertama tidak menghasilkan flag.
5. SOC BLUE TEAM PERSPECTIVE (SIEM, YARA & MITIGASI):
   - Tactic & Technique MITRE ATT&CK terkait.
   - Deteksi SIEM / Suricata / Snort rule dan rekomendasi pencegahan taktis."""

        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": user_text},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{mime};base64,{encoded_string}"
                        }
                    }
                ]
            }
        ]

        try:
            return await self.call_chat_completion(messages=messages, temperature=0.2)
        except Exception as e:
            logger.error(f"Gagal memanggil AI Vision: {e}")
            return f"[ERROR] Terjadi kesalahan saat AI Vision menganalisis gambar: {e!s}"


