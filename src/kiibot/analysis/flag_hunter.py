"""KIIBOT CTF Flag Hunter.

Recursively searches files, directories, text, and memory dumps for CTF flags.
Supports custom regexes, base64-encoded flags, and rot13-encoded flags.
"""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path

from kiibot.analysis.decoders import caesar_cipher

FLAG_REGEX = re.compile(rb"[A-Za-z0-9_]{2,25}\{[A-Za-z0-9_\-+=!?@#$%^&*.,:;~]{3,128}\}")


def hunt_in_bytes(data: bytes, custom_pattern: str | None = None) -> list[tuple[str, str]]:
    """Search for flags in raw bytes (plain, rot13, base64).

    Returns list of (flag, method_found).
    """
    found: list[tuple[str, str]] = []
    pattern = re.compile(custom_pattern.encode()) if custom_pattern else FLAG_REGEX

    # 1. Direct search
    for m in pattern.findall(data):
        try:
            val = m.decode("utf-8", errors="ignore").strip()
            found.append((val, "Plaintext"))
        except Exception:
            pass

    # 2. ROT13 search
    try:
        text_sample = data.decode("latin-1", errors="ignore")
        rot13_text = caesar_cipher(text_sample, 13).encode("latin-1")
        for m in pattern.findall(rot13_text):
            val = m.decode("utf-8", errors="ignore").strip()
            found.append((val, "ROT-13 Obfuscation"))
    except Exception:
        pass

    # 3. Base64 block search
    b64_pattern = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")
    for b64_match in b64_pattern.findall(data):
        try:
            raw = base64.b64decode(b64_match, validate=False)
            for m in pattern.findall(raw):
                val = m.decode("utf-8", errors="ignore").strip()
                found.append((val, "Base64 Encoded Block"))
        except Exception:
            pass

    # Remove duplicates
    unique: dict[str, str] = {}
    for f, m in found:
        if f not in unique:
            unique[f] = m
    return list(unique.items())


def hunt_in_file(file_path: Path, custom_pattern: str | None = None) -> list[tuple[str, str, str]]:
    """Hunt for flags inside a single file.

    Returns list of (file_path, flag, method).
    """
    if not file_path.is_file():
        return []

    try:
        size = file_path.stat().st_size
        if size > 50 * 1024 * 1024:  # Skip files > 50MB
            return []
        with open(file_path, "rb") as f:
            data = f.read()
        matches = hunt_in_bytes(data, custom_pattern)
        return [(str(file_path), flag, method) for flag, method in matches]
    except Exception:
        return []


def hunt_in_path(path: str | Path, custom_pattern: str | None = None) -> list[tuple[str, str, str]]:
    """Hunt flags in file or recursively throughout a directory."""
    p = Path(path)
    if not p.exists():
        return []

    results: list[tuple[str, str, str]] = []
    if p.is_file():
        return hunt_in_file(p, custom_pattern)

    # Walk directory
    for root, _, files in os.walk(p):
        for file in files:
            full_path = Path(root) / file
            matches = hunt_in_file(full_path, custom_pattern)
            results.extend(matches)

    return results
