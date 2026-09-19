"""Tests for KIIBOT File Analyzer."""

from pathlib import Path

from kiibot.analysis.file_analyzer import (
    analyze_file,
    calculate_entropy,
    detect_embedded_files,
    extract_strings,
    find_flags,
)


def test_entropy_calculation():
    # Zero entropy
    assert calculate_entropy(b"") == 0.0
    assert calculate_entropy(b"AAAAAAA") == 0.0
    # High entropy (random-like)
    data = bytes(range(256))
    assert calculate_entropy(data) == 8.0


def test_flag_detection():
    data = b"Some prefix text ... CTF{congratulations_winner_1337} ... some suffix"
    flags = find_flags(data)
    assert len(flags) == 1
    assert flags[0] == "CTF{congratulations_winner_1337}"


def test_extract_strings():
    data = b"\x00\x00Hello CTF player!\x00\x01\x02\x03KIIBOT_RULES\x00"
    strings = extract_strings(data, min_len=4)
    assert "Hello CTF player!" in strings
    assert "KIIBOT_RULES" in strings


def test_embedded_files_detection():
    # PNG with embedded ZIP
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20 + b"PK\x03\x04" + b"\x00" * 10
    embedded = detect_embedded_files(data)
    assert len(embedded) >= 1
    assert "ZIP" in embedded[0]


def test_analyze_file(tmp_path: Path):
    test_file = tmp_path / "chall.bin"
    # Create fake ELF header with a flag
    content = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20 + b"flag{test_elf_flag_inside}"
    test_file.write_bytes(content)

    report = analyze_file(test_file)
    assert report.filename == "chall.bin"
    assert "ELF" in report.description
    assert report.category == "pwn"
    assert "flag{test_elf_flag_inside}" in report.flags_found
    assert report.checksec is not None
    assert report.checksec.bits == 64
