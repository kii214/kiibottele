"""KIIBOT Decoders & Crypto Utilities.

Implements multi-base decoders, ciphers (Caesar, XOR, Atbash, Affine, Bacon, Morse, Brainfuck),
and hash identification algorithms.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse

# Common English character frequencies for heuristic scoring
ENGLISH_FREQ = {
    'e': 12.7, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75,
    's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
    'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97,
    'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07, ' ': 15.0,
}

MORSE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
    '-..-.': '/', '-....-': '-', '-...-': '=', '.-.-.': '+', '---...': ':',
    '-.-.-.': ';', '-.--.': '(', '-.--.-': ')', '..--.-': '_', '...-..-': '$',
    '.--.-.': '@', '.-...': '&',
}


def score_english(text: str) -> float:
    """Calculate an English readability score for a string."""
    if not text:
        return 0.0
    text_lower = text.lower()
    score = 0.0
    printable_count = 0

    for ch in text_lower:
        if 32 <= ord(ch) <= 126 or ch in "\r\n\t":
            printable_count += 1
            score += ENGLISH_FREQ.get(ch, 0.1)
        else:
            score -= 10.0  # Heavy penalty for non-printable

    ratio = printable_count / len(text)
    if ratio < 0.8:
        return 0.0

    # Boost score if flag pattern is detected
    if re.search(r"[A-Za-z0-9_]{2,20}\{[^}]+\}", text):
        score += 500.0

    return score


# ── Base Encodings ─────────────────────────────────────────────────────────────

def try_base64_decode(data: str | bytes) -> tuple[bool, str]:
    """Attempt to decode Base64 string."""
    text = data if isinstance(data, str) else data.decode("latin-1", errors="ignore")
    text = text.strip()
    if len(text) < 4 or len(text) % 4 not in (0, 2, 3):
        # Fix padding if needed
        missing_padding = len(text) % 4
        if missing_padding:
            text += "=" * (4 - missing_padding)

    try:
        raw = base64.b64decode(text, validate=False)
        decoded = raw.decode("utf-8")
        # Validate printable
        if len(decoded) > 0 and sum(1 for c in decoded if 32 <= ord(c) <= 126) / len(decoded) > 0.85:
            return True, decoded
    except Exception:
        pass
    return False, ""


def try_hex_decode(data: str | bytes) -> tuple[bool, str]:
    """Attempt to decode Hexadecimal string."""
    text = data if isinstance(data, str) else data.decode("latin-1", errors="ignore")
    text = text.strip().replace(" ", "").replace("0x", "").replace("0X", "").replace("\\x", "")
    if len(text) < 2 or len(text) % 2 != 0:
        return False, ""
    try:
        raw = binascii.unhexlify(text)
        decoded = raw.decode("utf-8")
        if len(decoded) > 0 and sum(1 for c in decoded if 32 <= ord(c) <= 126) / len(decoded) > 0.85:
            return True, decoded
    except Exception:
        pass
    return False, ""


def try_base32_decode(data: str | bytes) -> tuple[bool, str]:
    """Attempt to decode Base32 string."""
    text = data if isinstance(data, str) else data.decode("latin-1", errors="ignore")
    text = text.strip().upper()
    if len(text) < 4:
        return False, ""
    try:
        missing = len(text) % 8
        if missing:
            text += "=" * (8 - missing)
        raw = base64.b32decode(text)
        decoded = raw.decode("utf-8")
        if len(decoded) > 0 and sum(1 for c in decoded if 32 <= ord(c) <= 126) / len(decoded) > 0.85:
            return True, decoded
    except Exception:
        pass
    return False, ""


def try_base85_decode(data: str | bytes) -> tuple[bool, str]:
    """Attempt to decode Base85 string."""
    text = data if isinstance(data, str) else data.decode("latin-1", errors="ignore")
    text = text.strip()
    try:
        raw = base64.b85decode(text)
        decoded = raw.decode("utf-8")
        if len(decoded) > 0 and sum(1 for c in decoded if 32 <= ord(c) <= 126) / len(decoded) > 0.85:
            return True, decoded
    except Exception:
        pass
    return False, ""


def try_binary_decode(data: str | bytes) -> tuple[bool, str]:
    """Attempt to decode space-separated or continuous binary 8-bit strings."""
    text = data if isinstance(data, str) else data.decode("latin-1", errors="ignore")
    text = text.strip().replace(" ", "")
    if len(text) < 8 or len(text) % 8 != 0 or not set(text).issubset({"0", "1"}):
        return False, ""
    try:
        chars = [chr(int(text[i:i + 8], 2)) for i in range(0, len(text), 8)]
        decoded = "".join(chars)
        if len(decoded) > 0 and sum(1 for c in decoded if 32 <= ord(c) <= 126) / len(decoded) > 0.85:
            return True, decoded
    except Exception:
        pass
    return False, ""


def try_url_decode(data: str | bytes) -> tuple[bool, str]:
    """Attempt to URL-decode a percent-encoded string."""
    text = data if isinstance(data, str) else data.decode("latin-1", errors="ignore")
    text = text.strip()
    if "%" not in text and "+" not in text:
        return False, ""
    try:
        decoded = urllib.parse.unquote_plus(text)
        if decoded != text and len(decoded) > 0:
            printable = sum(1 for c in decoded if 32 <= ord(c) <= 126)
            if printable / len(decoded) > 0.85:
                return True, decoded
    except Exception:
        pass
    return False, ""


def try_jwt_decode(data: str | bytes) -> tuple[bool, str]:
    """Decode JWT token (header + payload) without signature verification."""
    text = data if isinstance(data, str) else data.decode("latin-1", errors="ignore")
    text = text.strip()
    parts = text.split(".")
    if len(parts) != 3:
        return False, ""
    try:
        def pad(s: str) -> str:
            return s + "=" * (-len(s) % 4)

        header_raw = base64.urlsafe_b64decode(pad(parts[0])).decode("utf-8")
        payload_raw = base64.urlsafe_b64decode(pad(parts[1])).decode("utf-8")
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
        result = (
            f"Header: {json.dumps(header, indent=2)}\n"
            f"Payload: {json.dumps(payload, indent=2)}\n"
            f"Signature: {parts[2][:32]}... (not verified)"
        )
        return True, result
    except Exception:
        return False, ""


# ── Classic Ciphers ───────────────────────────────────────────────────────────

def rot47(text: str) -> str:
    """ROT47 cipher: rotates all printable ASCII characters (! to ~) by 47 positions."""
    result = []
    for ch in text:
        o = ord(ch)
        if 33 <= o <= 126:
            result.append(chr(33 + (o - 33 + 47) % 94))
        else:
            result.append(ch)
    return "".join(result)


def caesar_cipher(text: str, shift: int) -> str:
    """Shift letters by `shift` places."""
    res = []
    for ch in text:
        if "a" <= ch <= "z":
            res.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            res.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            res.append(ch)
    return "".join(res)


def brute_force_caesar(text: str) -> list[tuple[int, str, float]]:
    """Brute-force all 25 Caesar shifts and sort by English score."""
    results = []
    for shift in range(1, 26):
        decoded = caesar_cipher(text, shift)
        score = score_english(decoded)
        results.append((shift, decoded, score))
    return sorted(results, key=lambda x: x[2], reverse=True)


def atbash_cipher(text: str) -> str:
    """Atbash substitution cipher (A <-> Z, B <-> Y)."""
    res = []
    for ch in text:
        if "a" <= ch <= "z":
            res.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z":
            res.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else:
            res.append(ch)
    return "".join(res)


def xor_single_byte(data: bytes, key: int) -> bytes:
    """XOR all bytes with a single byte key."""
    return bytes([b ^ key for b in data])


def brute_force_xor(data: bytes | str) -> list[tuple[int, str, float]]:
    """Brute force all 256 single-byte XOR keys."""
    raw = data.encode("latin-1") if isinstance(data, str) else data
    results = []
    for key in range(256):
        xored = xor_single_byte(raw, key)
        try:
            decoded = xored.decode("utf-8")
            score = score_english(decoded)
            if score > 15.0:
                results.append((key, decoded, score))
        except UnicodeDecodeError:
            continue
    return sorted(results, key=lambda x: x[2], reverse=True)


# ── Esoteric & Decoders ───────────────────────────────────────────────────────

def decode_morse(morse_code: str) -> str:
    """Decode Morse code string (separated by spaces, words separated by / or double space)."""
    words = morse_code.strip().replace("   ", " / ").split(" / ")
    decoded_words = []
    for word in words:
        chars = word.split()
        decoded_word = "".join(MORSE_DICT.get(c, "?") for c in chars)
        decoded_words.append(decoded_word)
    return " ".join(decoded_words)


def run_brainfuck(code: str, max_steps: int = 100000) -> str:
    """Execute Brainfuck code and return its stdout string."""
    cleaned = [c for c in code if c in "><+-.,[]"]
    tape = [0] * 30000
    ptr = 0
    pc = 0
    output = []
    steps = 0

    # Build bracket map
    bracket_map = {}
    stack = []
    for i, c in enumerate(cleaned):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return ""
            start = stack.pop()
            bracket_map[start] = i
            bracket_map[i] = start

    while pc < len(cleaned) and steps < max_steps:
        steps += 1
        cmd = cleaned[pc]
        if cmd == ">":
            ptr = (ptr + 1) % 30000
        elif cmd == "<":
            ptr = (ptr - 1) % 30000
        elif cmd == "+":
            tape[ptr] = (tape[ptr] + 1) % 256
        elif cmd == "-":
            tape[ptr] = (tape[ptr] - 1) % 256
        elif cmd == ".":
            output.append(chr(tape[ptr]))
        elif cmd == "[":
            if tape[ptr] == 0:
                pc = bracket_map[pc]
        elif cmd == "]" and tape[ptr] != 0:
            pc = bracket_map[pc]
        pc += 1

    return "".join(output)


def decode_bacon(text: str) -> str:
    """Decode standard Bacon cipher (A/B or 0/1 representation)."""
    cleaned = text.upper().replace(" ", "")
    # Normalize to A and B
    trans = str.maketrans("01", "AB")
    cleaned = cleaned.translate(trans)
    cleaned = re.sub(r"[^AB]", "", cleaned)

    bacon_dict = {
        'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
        'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'K',
        'ABABA': 'L', 'ABABB': 'M', 'ABBAA': 'N', 'ABBAB': 'O', 'ABBBA': 'P',
        'ABBBB': 'Q', 'BAAAA': 'R', 'BAAAB': 'S', 'BAABA': 'T', 'BAABB': 'U',
        'BABAA': 'W', 'BABAB': 'X', 'BABBA': 'Y', 'BABBB': 'Z',
    }
    chunks = [cleaned[i:i + 5] for i in range(0, len(cleaned), 5) if len(cleaned[i:i + 5]) == 5]
    return "".join(bacon_dict.get(c, "?") for c in chunks)


def identify_hash(hash_str: str) -> list[str]:
    """Identify possible cryptographic hash types from string representation."""
    h = hash_str.strip().lower()
    if re.match(r"^[0-9a-f]{32}$", h):
        return ["MD5", "NTLM", "MD4", "MD2"]
    elif re.match(r"^[0-9a-f]{40}$", h):
        return ["SHA-1", "RIPEMD-160"]
    elif re.match(r"^[0-9a-f]{56}$", h):
        return ["SHA-224", "SHA3-224"]
    elif re.match(r"^[0-9a-f]{64}$", h):
        return ["SHA-256", "SHA3-256", "BLAKE2s"]
    elif re.match(r"^[0-9a-f]{96}$", h):
        return ["SHA-384", "SHA3-384"]
    elif re.match(r"^[0-9a-f]{128}$", h):
        return ["SHA-512", "SHA3-512", "Whirlpool", "BLAKE2b"]
    elif h.startswith(("$2a$", "$2b$", "$2y$")):
        return ["bcrypt"]
    elif h.startswith("$6$"):
        return ["SHA-512 Crypt (Linux)"]
    elif h.startswith("$1$"):
        return ["MD5 Crypt (Linux)"]
    return ["Unknown Hash Format"]


def decode_all(text: str) -> list[dict[str, str]]:
    """Attempt all decoders and return any successful results.
    Includes multi-stage chain detection for nested encodings.
    """
    results = []
    seen_results = set()  # Deduplicate identical results

    def add_if_new(dtype: str, result: str):
        key = result.strip()[:200]
        if key not in seen_results and result.strip():
            seen_results.add(key)
            results.append({"type": dtype, "result": result})

    # Base64
    ok, b64 = try_base64_decode(text)
    if ok and b64 != text:
        add_if_new("Base64", b64)
        # Chain: Base64-in-Base64
        ok2, b64b = try_base64_decode(b64)
        if ok2 and b64b != b64:
            add_if_new("Base64 (double)", b64b)

    # Hex
    ok, hexd = try_hex_decode(text)
    if ok and hexd != text:
        add_if_new("Hex", hexd)
        # Chain: Hex -> Base64
        ok2, hb64 = try_base64_decode(hexd)
        if ok2 and hb64 != hexd:
            add_if_new("Hex → Base64", hb64)

    # Base32
    ok, b32 = try_base32_decode(text)
    if ok and b32 != text:
        add_if_new("Base32", b32)

    # Base85
    ok, b85 = try_base85_decode(text)
    if ok and b85 != text:
        add_if_new("Base85", b85)

    # Binary
    ok, bin_d = try_binary_decode(text)
    if ok and bin_d != text:
        add_if_new("Binary", bin_d)

    # URL Decode
    ok, urld = try_url_decode(text)
    if ok and urld != text:
        add_if_new("URL Decode", urld)
        # Chain: URL -> Base64
        ok2, ub64 = try_base64_decode(urld)
        if ok2 and ub64 != urld:
            add_if_new("URL → Base64", ub64)

    # JWT
    ok, jwtd = try_jwt_decode(text)
    if ok:
        add_if_new("JWT Token", jwtd)

    # Caesar
    caesar_res = brute_force_caesar(text)
    if caesar_res:
        top_shift, top_text, top_score = caesar_res[0]
        if top_score > 10.0:
            add_if_new(f"Caesar (Shift {top_shift})", top_text)

    # ROT13 shortcut
    rot13 = caesar_cipher(text, 13)
    if rot13 != text:
        add_if_new("ROT-13", rot13)

    # ROT47
    rot47_result = rot47(text)
    if rot47_result != text:
        sc = score_english(rot47_result)
        if sc > 15.0:
            add_if_new("ROT-47", rot47_result)

    # XOR
    xor_res = brute_force_xor(text)
    if xor_res:
        top_key, top_text, top_score = xor_res[0]
        if top_score > 10.0:
            add_if_new(f"XOR (Key 0x{top_key:02x})", top_text)

    # Hash Identification
    hashes = identify_hash(text)
    if hashes and "Unknown Hash Format" not in hashes:
        add_if_new("Hash Identity", ", ".join(hashes))

    return results
