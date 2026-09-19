"""Tests for Forensics and PCAP analysis engines."""

import struct
from pathlib import Path

from kiibot.analysis.forensics_engine import triage_forensics
from kiibot.analysis.pcap_analyzer import parse_pcap


def test_forensics_triage(tmp_path: Path):
    test_file = tmp_path / "evidence.txt"
    test_file.write_text("Secret notes CTF{forensic_flag_found_here} done.")

    res = triage_forensics(test_file)
    assert res.filename == "evidence.txt"
    assert "CTF{forensic_flag_found_here}" in res.flags


def test_pcap_parser(tmp_path: Path):
    pcap_file = tmp_path / "test.pcap"
    # Construct minimal valid PCAP with 1 dummy packet
    # Global Header (24 bytes)
    # Magic: 0xa1b2c3d4 (big endian)
    gh = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # Packet Header: ts_sec, ts_usec, incl_len, orig_len
    # Minimal Ethernet + IPv4 + UDP + DNS packet with a flag in UDP payload
    payload = b"flag{pcap_packet_flag_recovered}"
    # Ethernet header: 14 bytes (dst 6, src 6, type 2)
    eth = b"\x00" * 12 + b"\x08\x00"
    # IPv4 header: 20 bytes (proto UDP = 17)
    ip = b"\x45\x00\x00\x34\x00\x01\x00\x00\x40\x11\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
    # UDP header: 8 bytes (sport 53, dport 1337, len, csum)
    udp = struct.pack(">HHHH", 53, 1337, 8 + len(payload), 0)
    packet_data = eth + ip + udp + payload

    ph = struct.pack(">IIII", 1600000000, 0, len(packet_data), len(packet_data))

    pcap_file.write_bytes(gh + ph + packet_data)

    summary = parse_pcap(pcap_file)
    assert summary.total_packets == 1
    assert "flag{pcap_packet_flag_recovered}" in summary.flags_found
