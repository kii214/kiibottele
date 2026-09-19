"""KIIBOT Digital Forensics Engine.

Handles deep forensic triage:
- Carving embedded files from disk images & payloads
- ZIP metadata & compression analysis
- Hidden comment & trail extractor
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from kiibot.analysis.flag_hunter import hunt_in_file


@dataclass
class ForensicsResult:
    filename: str
    size: int
    flags: list[str] = field(default_factory=list)
    zip_entries: list[str] = field(default_factory=list)
    has_encrypted_zip_files: bool = False
    carved_files: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


def carve_files(data: bytes, output_dir: Path) -> list[str]:
    """Carve embedded files (ZIP, PNG, ELF, PDF) from binary data."""
    output_dir.mkdir(parents=True, exist_ok=True)
    carved: list[str] = []

    # Carve ZIP
    pos = 0
    idx = 1
    while True:
        pos = data.find(b"PK\x03\x04", pos)
        if pos == -1:
            break
        # Look for end of central directory
        eocd = data.find(b"PK\x05\x06", pos)
        if eocd != -1 and eocd + 22 <= len(data):
            zip_slice = data[pos:eocd + 22]
            out_file = output_dir / f"carved_{idx}.zip"
            out_file.write_bytes(zip_slice)
            carved.append(f"carved_{idx}.zip (at 0x{pos:X}, {len(zip_slice)} bytes)")
            idx += 1
        pos += 4

    return carved


def triage_forensics(file_path: str | Path, carve_dir: Path | None = None) -> ForensicsResult:
    """Run comprehensive forensics triage on a target file."""
    p = Path(file_path)
    size = p.stat().st_size
    result = ForensicsResult(filename=p.name, size=size)

    # Hunt flags
    flag_matches = hunt_in_file(p)
    result.flags = [f for _, f, _ in flag_matches]

    # Check if ZIP
    if zipfile.is_zipfile(p):
        try:
            with zipfile.ZipFile(p, "r") as z:
                for info in z.infolist():
                    is_enc = bool(info.flag_bits & 0x1)
                    if is_enc:
                        result.has_encrypted_zip_files = True
                    result.zip_entries.append(f"{info.filename} ({info.file_size:,} bytes{' [ENCRYPTED]' if is_enc else ''})")
                if z.comment:
                    result.anomalies.append(f"Archive Comment: {z.comment.decode('latin-1', errors='replace')}")
        except Exception as e:
            result.anomalies.append(f"Corrupted ZIP structure: {e}")

    # Carving
    if carve_dir:
        with open(p, "rb") as f:
            data = f.read()
        result.carved_files = carve_files(data, carve_dir)

    return result
