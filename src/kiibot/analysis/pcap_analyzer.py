"""
KIIBOT Professional PCAP & Network Forensic Analyzer — Optimized
Menganalisis file PCAP/PCAPNG secara bertubi-tubi pada level Senior Security Analyst / WireShark Expert.
Ekstraksi: TCP streams, HTTP payloads, DNS queries, TLS SNI, SSH Banner,
ICMP tunneling, UDP flow, credentials, serta flag/secret secara nyata dan valid.
"""

import asyncio
import logging
import os
import re
import shutil
from typing import Any
from urllib.parse import unquote

logger = logging.getLogger(__name__)


class ProfessionalPCAPAnalyzer:
    """Mesin investigasi PCAP tingkat expert (Senior Wireshark & Network Forensic)."""

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.has_tshark = shutil.which("tshark") is not None
        self.has_tcpdump = shutil.which("tcpdump") is not None

    async def _run_command(self, cmd: list[str], timeout: float = 25.0) -> str:
        """Menjalankan perintah tshark/tcpdump secara aman dan mengembalikan output teks."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode("utf-8", errors="ignore")
            return out.strip()
        except TimeoutError:
            return "[TIMEOUT]: Command tshark melebihi batas waktu."
        except Exception as e:
            return f"[ERROR]: {e!s}"

    async def analyze_protocol_hierarchy(self) -> str:
        """Wireshark Expert 1: Protocol Hierarchy Statistics (-z io,phs)."""
        if not self.has_tshark:
            # Fallback: tcpdump summary
            if self.has_tcpdump:
                return await self._run_command(["tcpdump", "-r", self.pcap_path, "-q", "-c", "100"])
            return "tshark dan tcpdump tidak terpasang di VPS."
        cmd = ["tshark", "-r", self.pcap_path, "-q", "-z", "io,phs"]
        return await self._run_command(cmd)

    async def analyze_conversations_and_endpoints(self) -> str:
        """Wireshark Expert 2: IP Conversations & Top Endpoints (-z conv,ip)."""
        if not self.has_tshark:
            return "tshark tidak terpasang di VPS."
        cmd = ["tshark", "-r", self.pcap_path, "-q", "-z", "conv,ip"]
        return await self._run_command(cmd)

    async def extract_dns_queries(self) -> list[str]:
        """Wireshark Expert 3: DNS Exfiltration & Suspicious Domain Queries."""
        if not self.has_tshark:
            from kiibot.analysis.native_pcap import extract_dns_native
            return extract_dns_native(self.pcap_path)
        cmd = ["tshark", "-r", self.pcap_path, "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name"]
        out = await self._run_command(cmd)
        queries = [q.strip() for q in out.splitlines() if q.strip()]
        # Unik & urutkan
        seen = set()
        unique_queries = []
        for q in queries:
            if q not in seen:
                seen.add(q)
                unique_queries.append(q)
        return unique_queries[:50]

    async def extract_http_requests_and_payloads(self) -> list[dict[str, str]]:
        """Wireshark Expert 4: HTTP Request URI, Methods, User-Agent, File Data."""
        if not self.has_tshark:
            from kiibot.analysis.native_pcap import extract_http_native
            return extract_http_native(self.pcap_path)
        cmd = [
            "tshark", "-r", self.pcap_path,
            "-Y", "http.request or http.response",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "http.response.code",
            "-e", "http.file_data"
        ]
        out = await self._run_command(cmd)
        results = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 4:
                src = parts[0] if len(parts) > 0 else ""
                dst = parts[1] if len(parts) > 1 else ""
                method = parts[2] if len(parts) > 2 else ""
                uri = parts[3] if len(parts) > 3 else ""
                code = parts[4] if len(parts) > 4 else ""
                data = parts[5] if len(parts) > 5 else ""
                if method or uri or data:
                    results.append({
                        "src": src, "dst": dst, "method": method, "uri": uri, "code": code, "data": data[:300]
                    })
        return results[:40]

    async def extract_credentials_and_auth(self) -> list[str]:
        """Wireshark Expert 5: Cleartext Credentials (HTTP Auth, FTP, Telnet, SMTP)."""
        if not self.has_tshark:
            return []
        cmd = [
            "tshark", "-r", self.pcap_path,
            "-Y", "http.authorization or ftp.request.command or smtp.req.parameter",
            "-T", "fields",
            "-e", "http.authorization",
            "-e", "ftp.request.arg",
            "-e", "smtp.req.parameter"
        ]
        out = await self._run_command(cmd)
        creds = [c.strip() for c in out.splitlines() if c.strip()]
        return creds[:20]

    async def extract_icmp_and_custom_data(self) -> list[str]:
        """Wireshark Expert 6: ICMP Tunneling / Data Exfiltration."""
        if not self.has_tshark:
            return []
        cmd = [
            "tshark", "-r", self.pcap_path,
            "-Y", "icmp",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "data.text",
            "-e", "data.data"
        ]
        out = await self._run_command(cmd)
        datas = [d.strip() for d in out.splitlines() if d.strip()]
        return datas[:30]

    async def extract_tls_sni(self) -> list[str]:
        """Wireshark Expert 7b: TLS SNI (Server Name Indication) — deteksi domain C2 di traffic HTTPS."""
        if not self.has_tshark:
            return []
        cmd = [
            "tshark", "-r", self.pcap_path,
            "-Y", "tls.handshake.extensions_server_name",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tls.handshake.extensions_server_name"
        ]
        out = await self._run_command(cmd)
        sni_entries = []
        seen = set()
        for line in out.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 3 and parts[2] and parts[2] not in seen:
                seen.add(parts[2])
                sni_entries.append(f"{parts[0]} -> {parts[1]}: {parts[2]}")
        return sni_entries[:30]

    async def extract_ssh_banner(self) -> list[str]:
        """Wireshark Expert 7c: SSH Banner / Protocol Version — deteksi versi SSH dan banner."""
        if not self.has_tshark:
            return []
        cmd = [
            "tshark", "-r", self.pcap_path,
            "-Y", "ssh.protocol",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ssh.protocol"
        ]
        out = await self._run_command(cmd)
        banners = []
        seen = set()
        for line in out.splitlines():
            line = line.strip()
            if line and line not in seen:
                seen.add(line)
                banners.append(line)
        return banners[:20]

    async def analyze_udp_flows(self) -> str:
        """Wireshark Expert 7d: UDP Flow Analysis — DNS amplification, UDP flood detection."""
        if not self.has_tshark:
            return ""
        cmd = ["tshark", "-r", self.pcap_path, "-q", "-z", "conv,udp"]
        return await self._run_command(cmd, timeout=20.0)

    async def follow_top_tcp_streams(self, max_streams: int = 10) -> list[dict[str, Any]]:
        """Wireshark Expert 7: Deep Follow TCP Streams (Rekonstruksi Sesi Lengkap) — hingga 10 stream."""
        if not self.has_tshark:
            return []
        streams_data = []
        for stream_id in range(max_streams):
            cmd = ["tshark", "-r", self.pcap_path, "-q", "-z", f"follow,tcp,ascii,{stream_id}"]
            stream_out = await self._run_command(cmd, timeout=10.0)
            if stream_out and "Node 0" in stream_out and len(stream_out) > 50:
                lines = stream_out.splitlines()
                content = "\n".join(lines[6:]) if len(lines) > 6 else stream_out
                streams_data.append({
                    "stream_id": stream_id,
                    "preview": content[:1500]
                })
        return streams_data

    async def search_flags_in_pcap(self) -> list[str]:
        """Wireshark Expert 8: Rigorous Regex Flag Extraction (Valid, No Hallucination)."""
        flags = set()
        flag_regex = re.compile(r"([a-zA-Z0-9_\-]{3,15}\{[a-zA-Z0-9_\-\+\=\@\!]{4,100}\})")

        # Jalankan strings pada file PCAP
        try:
            cmd = ["strings", "-n", "6", self.pcap_path]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            text = stdout.decode("utf-8", errors="ignore")
            for m in flag_regex.findall(text):
                flags.add(m)
            # URL decode strings
            decoded_text = unquote(text)
            for m in flag_regex.findall(decoded_text):
                flags.add(m)
        except Exception:
            pass

        # Fallback manual baca file jika strings gagal
        if not flags and os.path.exists(self.pcap_path):
            try:
                with open(self.pcap_path, "rb") as f:
                    raw = f.read(5 * 1024 * 1024)
                    text = raw.decode("latin-1", errors="ignore")
                    for m in flag_regex.findall(text):
                        flags.add(m)
            except Exception:
                pass

        return list(flags)

    async def run_expert_pcap_battery(self) -> dict[str, Any]:
        """Menjalankan seluruh baterai analisis Wireshark tingkat expert secara simultan (12 tools)."""
        logger.info(f"[EXPERT PCAP] Menjalankan baterai Wireshark tingkat lanjut pada: {self.pcap_path}")

        tasks = [
            self.analyze_protocol_hierarchy(),       # 0
            self.analyze_conversations_and_endpoints(),  # 1
            self.extract_dns_queries(),              # 2
            self.extract_http_requests_and_payloads(),   # 3
            self.extract_credentials_and_auth(),    # 4
            self.extract_icmp_and_custom_data(),    # 5
            self.follow_top_tcp_streams(max_streams=10),  # 6
            self.search_flags_in_pcap(),            # 7
            self.extract_tls_sni(),                 # 8
            self.extract_ssh_banner(),              # 9
            self.analyze_udp_flows(),               # 10
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            "protocol_hierarchy": results[0] if not isinstance(results[0], Exception) else "",
            "conversations": results[1] if not isinstance(results[1], Exception) else "",
            "dns_queries": results[2] if not isinstance(results[2], Exception) else [],
            "http_traffic": results[3] if not isinstance(results[3], Exception) else [],
            "credentials": results[4] if not isinstance(results[4], Exception) else [],
            "icmp_data": results[5] if not isinstance(results[5], Exception) else [],
            "tcp_streams": results[6] if not isinstance(results[6], Exception) else [],
            "flags_found": results[7] if not isinstance(results[7], Exception) else [],
            "tls_sni": results[8] if not isinstance(results[8], Exception) else [],
            "ssh_banners": results[9] if not isinstance(results[9], Exception) else [],
            "udp_flows": results[10] if not isinstance(results[10], Exception) else "",
        }

class PCAPSummary:
    def __init__(self, total_packets: int, flags_found: list[str]):
        self.total_packets = total_packets
        self.flags_found = flags_found

def parse_pcap(file_path) -> PCAPSummary:
    path_str = str(file_path)
    analyzer = ProfessionalPCAPAnalyzer(path_str)
    
    # We use asyncio to run the async search flags
    try:
        loop = asyncio.get_event_loop()
        flags = loop.run_until_complete(analyzer.search_flags_in_pcap())
    except Exception:
        flags = asyncio.run(analyzer.search_flags_in_pcap())
    
    # Fallback basic packet counter for valid PCAP
    packets = 0
    try:
        with open(path_str, "rb") as f:
            header = f.read(24) # global header
            if len(header) == 24:
                while True:
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break
                    packets += 1
                    import struct
                    # simple parse incl_len (offset 8)
                    incl_len = struct.unpack_from("<I" if header[:4] == b"\xd4\xc3\xb2\xa1" else ">I", pkt_header, 8)[0]
                    f.seek(incl_len, 1)
    except Exception:
        packets = 1
        
    return PCAPSummary(total_packets=packets, flags_found=flags)
