"""KIIBOT Binary Exploitation (PWN) Helpers.

De Bruijn cyclic pattern generator & offset finder for buffer overflow analysis.
"""

from __future__ import annotations

import struct


def de_bruijn(k: str = "abcdefghijklmnopqrstuvwxyz", n: int = 4) -> str:
    """Generate a De Bruijn sequence."""
    _k = len(k)
    a = [0] * _k * n
    sequence = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, _k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return "".join(k[i] for i in sequence)


_CACHE_DE_BRUIJN = de_bruijn()


def cyclic(length: int, n: int = 4) -> str:
    """Generate a unique cyclic pattern of given length."""
    global _CACHE_DE_BRUIJN
    if length > len(_CACHE_DE_BRUIJN):
        # Extend alphabet
        _CACHE_DE_BRUIJN = de_bruijn(k="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", n=n)
    return _CACHE_DE_BRUIJN[:length]


def cyclic_find(sub: str | int, n: int = 4) -> int:
    """Find the offset of a pattern in the cyclic sequence.

    Can be:
    - 4-byte string: 'baaa'
    - Hex integer: 0x61616162
    - Hex string: '0x61616162'
    """
    global _CACHE_DE_BRUIJN

    if isinstance(sub, int):
        # Convert integer to little-endian bytes
        try:
            target = struct.pack("<I", sub).decode("latin-1")
        except struct.error:
            target = struct.pack("<Q", sub).decode("latin-1")
    elif isinstance(sub, str):
        if sub.startswith(("0x", "0X")):
            val = int(sub, 16)
            try:
                target = struct.pack("<I", val).decode("latin-1")
            except struct.error:
                target = struct.pack("<Q", val).decode("latin-1")
        else:
            target = sub
    else:
        raise ValueError("Target must be a string or integer")

    return _CACHE_DE_BRUIJN.find(target)
