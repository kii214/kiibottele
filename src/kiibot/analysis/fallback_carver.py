"""
KIIBOT Native Fallback Carver
Sebuah modul pure-Python pengganti 'binwalk' untuk melakukan ekstraksi file 
dari dalam binary data jika binwalk tidak tersedia di OS pengguna.
"""

from pathlib import Path

# Daftar signature: (Magic Bytes, Extension, Maksimal Ukuran Pencarian Lanjut)
CARVE_SIGNATURES = [
    (b"PK\x03\x04", ".zip", 0),          # ZIP Archive (end detected automatically or chunk extracted)
    (b"\x89PNG\r\n\x1a\n", ".png", 0),     # PNG Image
    (b"\xff\xd8\xff", ".jpg", 0),          # JPEG Image
    (b"%PDF-", ".pdf", 0),                 # PDF Document
    (b"\x7fELF", ".elf", 0),               # ELF Binary
]

def _find_all_occurrences(data: bytes, sub: bytes) -> list[int]:
    """Cari semua offset substring di dalam bytes data."""
    offsets = []
    idx = 0
    while True:
        idx = data.find(sub, idx)
        if idx == -1:
            break
        offsets.append(idx)
        idx += 1
    return offsets

def carve_file(file_path: str | Path, output_dir: str | Path | None = None) -> list[str]:
    """
    Membedah file dan mengekstrak file tersembunyi (Carving).
    Mengembalikan daftar file yang berhasil diekstrak.
    """
    path = Path(file_path)
    if not path.exists():
        return []
        
    out_dir = Path(output_dir) if output_dir else path.parent / f"_carved_{path.name}"
    
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return []
        
    extracted_files = []
    
    # Deteksi PNG chunk khusus
    for magic, ext, _ in CARVE_SIGNATURES:
        offsets = _find_all_occurrences(data, magic)
        
        # Hindari offset 0 jika ekstensinya sama dengan file aslinya (menghindari duplikasi)
        if len(offsets) == 1 and offsets[0] == 0:
            continue
            
        for i, offset in enumerate(offsets):
            # Skip offset 0 karena itu adalah file itu sendiri
            if offset == 0:
                continue
                
            out_dir.mkdir(parents=True, exist_ok=True)
            carved_path = out_dir / f"carved_{offset:X}{ext}"
            
            # Tentukan batas akhir (end) dari file yang diekstrak
            end_offset = len(data)
            if ext == ".png":
                # Cari IEND chunk
                iend = data.find(b"IEND\xaeB`\x82", offset)
                if iend != -1:
                    end_offset = iend + 8
            elif ext == ".jpg":
                # Cari EOI (End of Image) \xff\xd9
                eoi = data.find(b"\xff\xd9", offset)
                if eoi != -1:
                    end_offset = eoi + 2
            elif ext == ".zip":
                # Cari End of central directory record signature
                eocd = data.find(b"PK\x05\x06", offset)
                if eocd != -1:
                    end_offset = eocd + 22
            
            try:
                with open(carved_path, "wb") as out_f:
                    out_f.write(data[offset:end_offset])
                extracted_files.append(str(carved_path))
            except Exception:
                pass
                
    return extracted_files
