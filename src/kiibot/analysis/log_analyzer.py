"""
KIIBOT Deep Concurrent Log Analyzer — Optimized
Menjalankan serangkaian alat investigasi log secara bertubi-tubi dan serentak (paralel)
untuk menemukan penyerang, payload (SQLi, XSS, RCE, LFI, Auth Bypass), status HTTP,
anomali scanner, beaconing, dan mengekstrak flag atau IoC secara akurat.
"""

import asyncio
import html as html_module
import logging
import os
import re
from collections import Counter
from typing import Any
from urllib.parse import unquote

from kiibot.analysis.decoders import decode_all

logger = logging.getLogger(__name__)


class DeepLogAnalyzer:
    """Mesin investigasi log serentak (Multi-Tool Concurrent Battery)."""

    def __init__(self, log_content: str = "", file_path: str | None = None):
        self.file_path = file_path
        self.raw_content = log_content

        if file_path and os.path.exists(file_path) and not log_content:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.raw_content = f.read()
            except Exception as e:
                logger.error(f"Gagal membaca file log {file_path}: {e}")
                self.raw_content = ""

        self.lines = [l.strip() for l in self.raw_content.splitlines() if l.strip()]

    @staticmethod
    def _triple_decode(line: str) -> str:
        """Triple URL decode + HTML unescape — menangkap payload yang di-encode berlapis."""
        try:
            d1 = unquote(line)
            d2 = unquote(d1)
            d3 = unquote(d2)
            return html_module.unescape(d3)
        except Exception:
            return line

    async def analyze_top_ips(self) -> dict[str, Any]:
        """Tool 1: Ekstraksi dan ranking frekuensi alamat IP (Top Attackers)."""
        await asyncio.sleep(0.01)
        ip_regex = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        ips = []
        for line in self.lines:
            match = ip_regex.search(line)
            if match:
                ips.append(match.group(0))

        counter = Counter(ips)
        top_20 = counter.most_common(20)
        return {
            "total_ips": len(counter),
            "top_ips": top_20,
            "suspect_attacker_ip": top_20[0][0] if top_20 else None
        }

    async def analyze_sqli(self) -> list[str]:
        """Tool 2: Deteksi payload SQL Injection bertubi-tubi (Union, Boolean, Time-based, Error-based, Auth Bypass)."""
        await asyncio.sleep(0.01)
        sqli_patterns = re.compile(
            r"(union\s+(?:all\s+)?select|select\s+.+\s+from|order\s+by\s+\d+"
            r"|or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|or\s+\"1\"\s*=\s*\"1\""  # classic auth bypass
            r"|and\s+1\s*=\s*1|and\s+1\s*=\s*2"  # boolean-based
            r"|waitfor\s+delay|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|pg_sleep"  # time-based
            r"|load_file|into\s+(?:out|dump)file"  # file read/write
            r"|information_schema|group_concat|extractvalue|updatexml"  # error-based
            r"|--\s|/\*.*?\*/|#\s*$"  # comment-based termination
            r"|version\(\)|database\(\)|schema_name|current_user\(\)"  # info extraction
            r"|admin'\s*--|'\s*or\s*''='|'\s*or\s*'x'='x)",  # auth bypass variants
            re.IGNORECASE
        )
        findings = []
        for line in self.lines:
            decoded_line = self._triple_decode(line)
            if sqli_patterns.search(decoded_line):
                findings.append(line[:300])
        return findings[:30]

    async def analyze_xss(self) -> list[str]:
        """Tool 3: Deteksi payload Cross-Site Scripting (XSS) — termasuk encoded dan DOM-based."""
        await asyncio.sleep(0.01)
        xss_patterns = re.compile(
            r"(<script[\s>]|</script>|javascript:|vbscript:"
            r"|onerror\s*=|onload\s*=|onfocus\s*=|onmouseover\s*=|onclick\s*="
            r"|alert\s*\(|document\.cookie|document\.write|window\.location"
            r"|<img\s+[^>]*src\s*=|<svg\s+[^>]*onload=|<iframe[\s>]"
            r"|prompt\s*\(|confirm\s*\(|eval\s*\("
            r"|&#x[0-9a-f]+;|\\u003c|%3cscript)",  # hex/unicode encoded
            re.IGNORECASE
        )
        findings = []
        for line in self.lines:
            decoded_line = self._triple_decode(line)
            if xss_patterns.search(decoded_line):
                findings.append(line[:300])
        return findings[:30]

    async def analyze_rce_cmd(self) -> list[str]:
        """Tool 4: Deteksi Command Injection & RCE — termasuk SSRF dan Out-of-Band."""
        await asyncio.sleep(0.01)
        cmd_patterns = re.compile(
            r"(;|\||&&|`|\$\()\s*"
            r"(cat\s+/etc/(passwd|shadow|hosts)|whoami|id\b|uname\s+-a"
            r"|nc\s+-[el]|ncat\s+-[el]|bash\s+-i|/bin/(sh|bash)"
            r"|curl\s+http|wget\s+http|python[23]?\s+-c|perl\s+-e|ruby\s+-e"
            r"|powershell|cmd\.exe|mshta"
            r"|/proc/self/exe|/proc/\d+/maps)"
            r"|\$\{IFS\}|\${PATH}",  # IFS/env bypass
            re.IGNORECASE
        )
        findings = []
        for line in self.lines:
            decoded_line = self._triple_decode(line)
            if cmd_patterns.search(decoded_line):
                findings.append(line[:300])
        return findings[:30]

    async def analyze_lfi_traversal(self) -> list[str]:
        """Tool 5: Deteksi LFI / Path Traversal termasuk PHP Wrappers dan Server-Side Includes."""
        await asyncio.sleep(0.01)
        lfi_patterns = re.compile(
            r"(\.\./|\.\.\\"
            r"|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./"  # encoded traversal
            r"|/etc/(passwd|shadow|hosts|group|crontab|sudoers)"
            r"|/proc/(self/environ|version|net/tcp)"
            r"|/var/log/(apache2?|nginx|syslog|auth)"
            r"|win\.ini|boot\.ini|\\windows\\system32"
            r"|php://filter|php://input|php://fd"  # PHP wrappers
            r"|phar://|zip://|data://text"  # other PHP wrappers
            r"|expect://|/\.\./\.\./\.\./)",  # deep traversal
            re.IGNORECASE
        )
        findings = []
        for line in self.lines:
            decoded_line = self._triple_decode(line)
            if lfi_patterns.search(decoded_line):
                findings.append(line[:300])
        return findings[:30]

    async def analyze_user_agents(self) -> dict[str, Any]:
        """Tool 6: Deteksi Automated Attack Scanners & User-Agent Anomali (list diperluas)."""
        await asyncio.sleep(0.01)
        # Scanner signatures yang diperluas
        scanner_signatures = [
            # Web scanners
            "sqlmap", "nikto", "gobuster", "dirbuster", "wfuzz", "ffuf", "feroxbuster",
            # Brute force
            "hydra", "medusa", "patator",
            # Network scanners
            "nmap", "masscan", "zgrab", "zmap",
            # Vuln scanners
            "nuclei", "metasploit", "burpcollaborator", "acunetix", "nessus",
            "appscan", "w3af", "openvas",
            # Exploit frameworks
            "havij", "pangolin",
            # OSINT/recon
            "shodan", "censys", "binaryedge",
            # Generic suspicious clients
            "python-requests", "python-urllib", "go-http-client",
            "curl/", "libwww-perl", "lwp-", "wget/",
            "scrapy", "mechanize", "java/",
        ]
        scanners_detected = []
        ua_list = []

        ua_regex = re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE)[^"]*"\s+\d+\s+\d+\s+"[^"]*"\s+"([^"]+)"')
        for line in self.lines:
            match = ua_regex.search(line)
            ua = match.group(1) if match else line
            ua_list.append(ua)
            for sig in scanner_signatures:
                if sig in ua.lower():
                    scanners_detected.append((sig, line[:250]))

        counter = Counter(ua_list)
        return {
            "scanners_found": list({s[0] for s in scanners_detected}),
            "scanner_hits_sample": [s[1] for s in scanners_detected[:10]],
            "top_user_agents": counter.most_common(10)
        }

    async def search_flags_and_secrets(self) -> list[str]:
        """Tool 7: Pencarian otomatis Flag CTF (prefix diperluas) & Kredensial tersembunyi di log."""
        await asyncio.sleep(0.01)
        # Prefix flag yang diperluas — mencakup berbagai kompetisi CTF populer
        flag_regex = re.compile(
            r"((?:CTF|FLAG|KIIBOT|WORKSHOP|SOC|HTB|picoCTF|DUCTF|DEAD|CCC|RTCP|BCACTF|CSAW|RCTF|TFCCTF)\{[a-zA-Z0-9_\-+=/!@#$%^&*]{4,100}\}"
            r"|[a-zA-Z0-9_\-]{3,12}\{[a-zA-Z0-9_\-+=/!@#$%]{8,100}\})",  # generic format
            re.IGNORECASE
        )
        flags_found = set()
        for line in self.lines:
            # 1. Plain
            for m in flag_regex.findall(line):
                flags_found.add(m)
            # 2. Triple URL decoded
            decoded = self._triple_decode(line)
            for m in flag_regex.findall(decoded):
                flags_found.add(m)
            # 3. Base64 & Hex decoders on potential tokens
            tokens = re.findall(r"[A-Za-z0-9+/=]{16,}|[a-fA-F0-9]{32,}", line)
            for tok in tokens[:5]:
                try:
                    dec_res = decode_all(tok)
                    for d in dec_res:
                        res_str = str(d.get("result", ""))
                        for m in flag_regex.findall(res_str):
                            flags_found.add(m)
                except Exception:
                    pass

        return list(flags_found)

    async def analyze_status_codes(self) -> dict[str, int]:
        """Tool 8: Distribusi Response Code (200 Success, 403 Forbidden, 404 Probing, 500 Error)."""
        await asyncio.sleep(0.01)
        status_regex = re.compile(r'"\s+(\d{3})\s+\d+')
        codes = []
        for line in self.lines:
            m = status_regex.search(line)
            if m:
                codes.append(m.group(1))
        return dict(Counter(codes).most_common(10))

    async def detect_beaconing(self) -> dict[str, Any]:
        """Tool 9: Deteksi Beaconing — Request interval reguler ke IP/host yang sama (indikasi C2)."""
        await asyncio.sleep(0.01)
        # Parse timestamp + IP dari Common Log Format: [dd/Mon/yyyy:HH:MM:SS +zone]
        time_ip_regex = re.compile(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[(\d{2}/[A-Za-z]{3}/\d{4}):(\d{2}):(\d{2}):(\d{2})"
        )
        ip_timestamps: dict[str, list[int]] = {}

        for line in self.lines:
            m = time_ip_regex.search(line)
            if m:
                ip = m.group(1)
                h, mi, s = int(m.group(3)), int(m.group(4)), int(m.group(5))
                ts = h * 3600 + mi * 60 + s
                if ip not in ip_timestamps:
                    ip_timestamps[ip] = []
                ip_timestamps[ip].append(ts)

        beaconing_suspects = []
        for ip, timestamps in ip_timestamps.items():
            if len(timestamps) < 4:
                continue
            timestamps.sort()
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            if not intervals:
                continue
            avg = sum(intervals) / len(intervals)
            # Deteksi beaconing: interval sangat konsisten (stddev rendah) & ada pola reguler
            variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
            stddev = variance ** 0.5
            # Kriteria: > 5 requests, interval reguler (stddev < 30% dari avg), interval 10-3600s
            if len(timestamps) >= 5 and stddev < (avg * 0.3) and 10 <= avg <= 3600:
                beaconing_suspects.append({
                    "ip": ip,
                    "request_count": len(timestamps),
                    "avg_interval_sec": round(avg, 1),
                    "stddev_sec": round(stddev, 1),
                    "regularity_score": round(1 - (stddev / (avg + 1)), 3)
                })

        # Urutkan berdasarkan skor regularitas (tertinggi = paling mencurigakan)
        beaconing_suspects.sort(key=lambda x: x["regularity_score"], reverse=True)
        return {
            "beaconing_suspects": beaconing_suspects[:10],
            "total_ips_analyzed": len(ip_timestamps)
        }

    async def run_concurrent_battery(self) -> dict[str, Any]:
        """
        Mengeksekusi SEMUA alat analisis log secara bersamaan (bertubi-tubi serentak).
        Sekarang 9 sub-tools termasuk beaconing detection.
        """
        logger.info(f"[LOG BATTERY] Menjalankan 9 sub-tools investigasi paralel pada {len(self.lines)} baris log...")
        tasks = [
            self.analyze_top_ips(),
            self.analyze_sqli(),
            self.analyze_xss(),
            self.analyze_rce_cmd(),
            self.analyze_lfi_traversal(),
            self.analyze_user_agents(),
            self.search_flags_and_secrets(),
            self.analyze_status_codes(),
            self.detect_beaconing(),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            "top_ips": results[0] if not isinstance(results[0], Exception) else {},
            "sqli_findings": results[1] if not isinstance(results[1], Exception) else [],
            "xss_findings": results[2] if not isinstance(results[2], Exception) else [],
            "rce_findings": results[3] if not isinstance(results[3], Exception) else [],
            "lfi_findings": results[4] if not isinstance(results[4], Exception) else [],
            "user_agents": results[5] if not isinstance(results[5], Exception) else {},
            "flags_found": results[6] if not isinstance(results[6], Exception) else [],
            "status_codes": results[7] if not isinstance(results[7], Exception) else {},
            "beaconing": results[8] if not isinstance(results[8], Exception) else {},
        }
