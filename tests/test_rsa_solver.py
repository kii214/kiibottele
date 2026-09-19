"""Tests for KIIBOT RSA Attacks."""


from kiibot.analysis.rsa_solver import (
    integer_nth_root,
    small_e_attack,
    wieners_attack,
)


def test_integer_nth_root():
    ok, root = integer_nth_root(27, 3)
    assert ok is True
    assert root == 3

    ok, root = integer_nth_root(1000000, 6)
    assert ok is True
    assert root == 10


def test_small_e_attack():
    # m^3 < N
    m = 1337
    e = 3
    c = pow(m, e)
    recovered = small_e_attack(c, e)
    assert recovered == m


def test_wieners_attack():
    # Small private exponent test case
    # p = 179, q = 613, N = 109727
    # phi = 178 * 612 = 108936
    # d = 7, e = 46687 (e * d % phi == 1)
    n = 109727
    e = 46687
    expected_d = 7
    d = wieners_attack(e, n)
    assert d == expected_d
