"""
KIIBOT Native PCAP Fallback
Menggunakan Scapy (jika tersedia) untuk melakukan parsing PCAP secara native
ketika tshark tidak ter-install di sistem.
"""

def extract_dns_native(pcap_path: str) -> list[str]:
    try:
        from scapy.all import DNSQR, rdpcap
        packets = rdpcap(pcap_path, count=5000)
        queries = set()
        for pkt in packets:
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname
                if qname:
                    queries.add(qname.decode("utf-8", errors="ignore"))
        return list(queries)[:50]
    except ImportError:
        return ["[Fallback Native] Scapy tidak terinstall. Gagal ekstrak DNS."]
    except Exception as e:
        return [f"[Fallback Native] Error: {e}"]

def extract_http_native(pcap_path: str) -> list[dict[str, str]]:
    try:
        from scapy.all import IP, TCP, Raw, rdpcap
        packets = rdpcap(pcap_path, count=5000)
        results = []
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
                payload = pkt[Raw].load.decode("utf-8", errors="ignore")
                if payload.startswith(("GET ", "POST ", "HTTP/")):
                    lines = payload.split("\r\n")
                    req_line = lines[0]
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    results.append({
                        "src": src, "dst": dst, 
                        "method": req_line.split(" ")[0] if " " in req_line else "", 
                        "uri": req_line, 
                        "code": "", 
                        "data": payload[:300]
                    })
        return results[:40]
    except ImportError:
        return [{"src": "Error", "dst": "", "method": "", "uri": "Scapy tidak terinstall.", "code": "", "data": ""}]
    except Exception as e:
        return [{"src": "Error", "dst": "", "method": "", "uri": str(e), "code": "", "data": ""}]
