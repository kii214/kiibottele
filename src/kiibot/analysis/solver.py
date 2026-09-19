"""KIIBOT Overpowered Recursive Auto-Solver.

Tries multi-stage decoding (Base64, Hex, ROT/Caesar, XOR, Atbash, Base32, Binary, URL decode)
to recursively unwrap nested ciphers until a valid CTF flag is discovered.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from kiibot.analysis.decoders import (
    atbash_cipher,
    brute_force_xor,
    caesar_cipher,
    decode_morse,
    run_brainfuck,
    score_english,
    try_base32_decode,
    try_base64_decode,
    try_base85_decode,
    try_binary_decode,
    try_hex_decode,
)

PREFERRED_FLAG_REGEX = re.compile(
    r"(?:flag|ctf|kiibot|htb|picoctf|sec|cyber|chall|root|workshop|soc|blue)[A-Za-z0-9_]*\{[A-Za-z0-9_\-+=!?@#$%^&*.,:;~]{3,128}\}",
    re.IGNORECASE,
)
GENERIC_FLAG_REGEX = re.compile(r"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_\-+=!?@#$%^&*.,:;~]{3,128}\}")


@dataclass
class SolveResult:
    """Result of an auto-solver run."""
    original_input: str
    flag_found: str | None = None
    best_candidate: str = ""
    transformations: list[str] = field(default_factory=list)
    confidence: float = 0.0
    all_candidates: list[tuple[str, list[str], float]] = field(default_factory=list)


class AutoSolver:
    """Recursive Multi-layer Solver Engine."""

    def __init__(self, max_depth: int = 5, custom_flag_prefix: str | None = None) -> None:
        self.max_depth = max_depth
        self.custom_flag_prefix = custom_flag_prefix
        if custom_flag_prefix:
            self.flag_regex = re.compile(
                rf"{re.escape(custom_flag_prefix)}\{{[A-Za-z0-9_\-+=!?@#$%^&*.,:;~]{{3,128}}\}}",
                re.IGNORECASE,
            )
            self.generic_allowed = False
        else:
            self.flag_regex = PREFERRED_FLAG_REGEX
            self.generic_allowed = True

    def solve(self, input_data: str) -> SolveResult:
        """Recursively attempt all decoding steps to discover the hidden flag or solution."""
        cleaned = input_data.strip()

        # If file path was passed, read file
        try:
            p = Path(cleaned)
            if p.is_file() and p.stat().st_size < 1000000:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    cleaned = f.read().strip()
        except Exception:
            pass

        result = SolveResult(original_input=cleaned)

        # 1. Immediate flag check
        match = self.flag_regex.search(cleaned)
        if match:
            result.flag_found = match.group(0)
            result.best_candidate = cleaned
            result.transformations = ["Direct Flag Match"]
            result.confidence = 100.0
            return result

        # 2. Check for Brainfuck
        if all(c in "><+-.,[] \n\r\t" for c in cleaned) and len(cleaned) > 10:
            bf_out = run_brainfuck(cleaned)
            if bf_out:
                bf_match = self.flag_regex.search(bf_out)
                if bf_match:
                    result.flag_found = bf_match.group(0)
                    result.best_candidate = bf_out
                    result.transformations = ["Brainfuck Interpreter"]
                    result.confidence = 100.0
                    return result

        # 3. Check for Morse
        if all(c in ".-/ \n\r\t" for c in cleaned) and len(cleaned) > 5:
            morse_out = decode_morse(cleaned)
            if morse_out:
                m_match = self.flag_regex.search(morse_out)
                if m_match:
                    result.flag_found = m_match.group(0)
                    result.best_candidate = morse_out
                    result.transformations = ["Morse Code Decode"]
                    result.confidence = 100.0
                    return result

        # 4. Recursive BFS search queue
        queue: list[tuple[str, list[str], int]] = [(cleaned, [], 0)]
        visited: set[str] = {cleaned}
        candidates: list[tuple[str, list[str], float]] = []
        generic_flag_match: tuple[str, str, list[str]] | None = None

        while queue:
            curr_text, steps, depth = queue.pop(0)

            # Check for preferred flag match
            preferred_match = self.flag_regex.search(curr_text)
            if preferred_match:
                result.flag_found = preferred_match.group(0)
                result.best_candidate = curr_text
                result.transformations = steps
                result.confidence = 100.0
                return result

            # Check for generic flag match if allowed and not already preferred
            if self.generic_allowed and generic_flag_match is None:
                gen_m = GENERIC_FLAG_REGEX.search(curr_text)
                if gen_m:
                    generic_flag_match = (gen_m.group(0), curr_text, steps)

            # Record candidate score
            sc = score_english(curr_text)
            if steps:
                candidates.append((curr_text, steps, sc))

            if depth >= self.max_depth:
                continue

            # Generate possible transformations:
            transforms: list[tuple[str, str]] = []

            # A. URL Decode
            if "%" in curr_text:
                try:
                    urld = urllib.parse.unquote(curr_text)
                    if urld != curr_text:
                        transforms.append(("URL Decode", urld))
                except Exception:
                    pass

            # B. Base64
            ok, b64_res = try_base64_decode(curr_text)
            if ok and b64_res != curr_text:
                transforms.append(("Base64 Decode", b64_res))

            # C. Hex
            ok, hex_res = try_hex_decode(curr_text)
            if ok and hex_res != curr_text:
                transforms.append(("Hex Decode", hex_res))

            # D. Binary
            ok, bin_res = try_binary_decode(curr_text)
            if ok and bin_res != curr_text:
                transforms.append(("Binary Decode", bin_res))

            # E. Base32
            ok, b32_res = try_base32_decode(curr_text)
            if ok and b32_res != curr_text:
                transforms.append(("Base32 Decode", b32_res))

            # F. Base85
            ok, b85_res = try_base85_decode(curr_text)
            if ok and b85_res != curr_text:
                transforms.append(("Base85 Decode", b85_res))

            # G. ROT-13
            rot13_res = caesar_cipher(curr_text, 13)
            if rot13_res != curr_text:
                transforms.append(("ROT-13", rot13_res))

            # H. Atbash
            atbash_res = atbash_cipher(curr_text)
            if atbash_res != curr_text:
                transforms.append(("Atbash Cipher", atbash_res))

            # I. Single-byte XOR brute-force (top result if score is high)
            xor_candidates = brute_force_xor(curr_text)
            if xor_candidates:
                best_k, best_xored, best_sc = xor_candidates[0]
                if best_sc > 30.0:
                    transforms.append((f"XOR (Key 0x{best_k:02X})", best_xored))

            # Push new states
            for name, new_val in transforms:
                if new_val not in visited:
                    visited.add(new_val)
                    queue.append((new_val, steps + [name], depth + 1))

        # If no preferred flag found, check if a generic flag candidate was found
        if generic_flag_match:
            g_flag, g_text, g_steps = generic_flag_match
            result.flag_found = g_flag
            result.best_candidate = g_text
            result.transformations = g_steps
            result.confidence = 90.0
            return result

        # If no explicit flag found, return best candidate by English readability score
        if candidates:
            candidates.sort(key=lambda x: x[2], reverse=True)
            result.all_candidates = candidates[:10]
            top_cand, top_steps, top_score = candidates[0]
            result.best_candidate = top_cand
            result.transformations = top_steps
            result.confidence = min(95.0, top_score / 2.0)

        return result
