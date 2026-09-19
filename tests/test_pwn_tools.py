"""Tests for KIIBOT PWN tools."""


from kiibot.analysis.pwn_tools import cyclic, cyclic_find


def test_cyclic_generation():
    seq = cyclic(100)
    assert len(seq) == 100
    # Every 4-byte substring should be unique
    chunks = [seq[i:i + 4] for i in range(len(seq) - 3)]
    assert len(chunks) == len(set(chunks))


def test_cyclic_lookup():
    seq = cyclic(100)
    # Target chunk at offset 16
    target = seq[16:20]
    offset = cyclic_find(target)
    assert offset == 16


def test_cyclic_lookup_hex():
    # 'baaa' in little endian is 0x61616162
    offset = cyclic_find(0x61616162)
    assert offset != -1
