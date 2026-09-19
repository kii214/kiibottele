"""Tests for KIIBOT Auto-Solver & Decoders."""


from kiibot.analysis.decoders import (
    brute_force_xor,
    caesar_cipher,
    decode_morse,
    identify_hash,
    run_brainfuck,
    try_base64_decode,
    try_hex_decode,
)
from kiibot.analysis.solver import AutoSolver


def test_base64_decode():
    ok, text = try_base64_decode("SGVsbG8gV29ybGQ=")
    assert ok is True
    assert text == "Hello World"


def test_hex_decode():
    ok, text = try_hex_decode("48656c6c6f20576f726c64")
    assert ok is True
    assert text == "Hello World"


def test_caesar_cipher():
    assert caesar_cipher("Hello", 13) == "Uryyb"
    assert caesar_cipher("Uryyb", 13) == "Hello"


def test_xor_single_byte():
    plain = "flag{single_byte_xor_works}"
    key = 0x42
    cipher = bytes([ord(c) ^ key for c in plain])
    results = brute_force_xor(cipher)
    assert len(results) > 0
    top_key, top_text, _ = results[0]
    assert top_key == key
    assert top_text == plain


def test_morse_and_brainfuck():
    # Morse: ... --- ...
    assert decode_morse("... --- ...") == "SOS"
    # Brainfuck: print 'A' (ASCII 65)
    bf = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++."
    assert run_brainfuck(bf) == "A"


def test_identify_hash():
    md5_hashes = identify_hash("5d41402abc4b2a76b9719d911017c592")
    assert "MD5" in md5_hashes
    sha256_hashes = identify_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert "SHA-256" in sha256_hashes


def test_auto_solver_multilayer():
    # Multi-layer test:
    # flag{nested_auto_solver_success}
    # -> ROT13 -> Base64
    flag = "flag{nested_auto_solver_success}"
    step1_rot13 = caesar_cipher(flag, 13)
    import base64
    step2_b64 = base64.b64encode(step1_rot13.encode()).decode()

    solver = AutoSolver(max_depth=4)
    res = solver.solve(step2_b64)
    assert res.flag_found == flag
    assert "Base64 Decode" in res.transformations
    assert "ROT-13" in res.transformations
