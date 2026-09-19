"""KIIBOT RSA CTF Attacks & Solver.

Solves common CTF RSA challenges:
- Small public exponent (e=3 root without mod wrap)
- Wiener's attack (small private exponent d < (1/3) * N^(1/4))
- Common modulus attack
- Hastad's broadcast attack helper
"""

from __future__ import annotations

import math
from collections.abc import Generator


def isqrt(n: int) -> int:
    """Integer square root."""
    return math.isqrt(n)


def integer_nth_root(val: int, n: int) -> tuple[bool, int]:
    """Find the exact n-th root of an integer if it exists."""
    if val < 0:
        raise ValueError("val must be positive")
    if val == 0:
        return True, 0

    # Newton's method
    high = 1
    while high ** n < val:
        high *= 2
    low = high // 2

    while low < high:
        mid = (low + high) // 2
        p = mid ** n
        if p == val:
            return True, mid
        elif p < val:
            low = mid + 1
        else:
            high = mid

    if low ** n == val:
        return True, low
    return False, low


def continued_fractions(n: int, d: int) -> Generator[int, None, None]:
    """Generate continued fraction expansions of n / d."""
    while d:
        q = n // d
        yield q
        n, d = d, n - d * q


def convergents(cf: list[int]) -> Generator[tuple[int, int], None, None]:
    """Calculate convergents (numerator, denominator) from continued fractions."""
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for q in cf:
        n = q * n1 + n0
        d = q * d1 + d0
        yield n, d
        n0, n1 = n1, n
        d0, d1 = d1, d


def wieners_attack(e: int, n: int) -> int | None:
    """Wiener's attack for small private exponent d.

    Returns d if found, or None.
    """
    cf = list(continued_fractions(e, n))
    for k, d in convergents(cf):
        if k == 0 or d % 2 == 0:
            continue
        # phi = (e * d - 1) // k
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Roots of x^2 - ((n - phi) + 1)x + n = 0
        s = n - phi + 1
        discr = s * s - 4 * n
        if discr >= 0:
            t = isqrt(discr)
            if t * t == discr and (s + t) % 2 == 0:
                return d
    return None


def small_e_attack(c: int, e: int) -> int | None:
    """Attack when message m was not padded and m^e < N."""
    ok, root = integer_nth_root(c, e)
    if ok:
        return root
    return None


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm: a*x + b*y = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int) -> int | None:
    """Common modulus attack when two messages are encrypted with same N and coprime e1, e2."""
    gcd, s1, s2 = extended_gcd(e1, e2)
    if gcd != 1:
        return None

    if s1 < 0:
        s1 = -s1
        c1 = pow(c1, -1, n)
    if s2 < 0:
        s2 = -s2
        c2 = pow(c2, -1, n)

    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return m
