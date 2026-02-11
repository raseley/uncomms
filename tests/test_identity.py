"""Tests for identity module."""

import tempfile
from pathlib import Path

from uncomms.identity import Identity


def test_generate():
    ident = Identity.generate("Alice")
    assert ident.display_name == "Alice"
    assert len(ident.public_key) == 32
    assert len(ident.private_key) == 32
    assert len(ident.fingerprint) == 8


def test_sign_verify():
    ident = Identity.generate("Bob")
    data = b"hello world"
    sig = ident.sign(data)
    assert len(sig) == 64
    assert Identity.verify(ident.public_key, data, sig)


def test_verify_rejects_bad_sig():
    ident = Identity.generate("Bob")
    data = b"hello world"
    sig = ident.sign(data)
    # Tamper with signature
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    assert not Identity.verify(ident.public_key, data, bad_sig)


def test_verify_rejects_wrong_data():
    ident = Identity.generate("Bob")
    sig = ident.sign(b"hello")
    assert not Identity.verify(ident.public_key, b"world", sig)


def test_save_load():
    ident = Identity.generate("Charlie")
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "identity.json"
        ident.save(path)
        loaded = Identity.load(path)
        assert loaded.display_name == "Charlie"
        assert loaded.public_key == ident.public_key
        assert loaded.private_key == ident.private_key


def test_two_identities_differ():
    a = Identity.generate("A")
    b = Identity.generate("B")
    assert a.public_key != b.public_key
