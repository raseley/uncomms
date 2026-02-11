"""Tests for message module."""

from uncomms.identity import Identity
from uncomms.message import Message, GENESIS_HASH


def test_create_message():
    ident = Identity.generate("Alice")
    msg = Message.create(
        identity=ident,
        server_id="srv1",
        channel="general",
        content="Hello!",
        prev_hash=GENESIS_HASH,
    )
    assert msg.id  # non-empty
    assert msg.server_id == "srv1"
    assert msg.channel == "general"
    assert msg.content == "Hello!"
    assert msg.prev_hash == GENESIS_HASH
    assert msg.author_name == "Alice"
    assert msg.author_pubkey == ident.public_key


def test_verify_id():
    ident = Identity.generate("Alice")
    msg = Message.create(ident, "s", "c", "test", GENESIS_HASH)
    assert msg.verify_id()
    # Tamper
    msg.content = "tampered"
    assert not msg.verify_id()


def test_verify_signature():
    ident = Identity.generate("Alice")
    msg = Message.create(ident, "s", "c", "test", GENESIS_HASH)
    assert msg.verify_signature()


def test_tampered_signature_fails():
    ident = Identity.generate("Alice")
    msg = Message.create(ident, "s", "c", "test", GENESIS_HASH)
    msg.content = "evil"
    assert not msg.verify_signature()


def test_hashchain_linking():
    ident = Identity.generate("Alice")
    msg1 = Message.create(ident, "s", "c", "first", GENESIS_HASH)
    msg2 = Message.create(ident, "s", "c", "second", msg1.id)
    assert msg2.prev_hash == msg1.id
    assert msg1.prev_hash == GENESIS_HASH


def test_serialization_roundtrip():
    ident = Identity.generate("Alice")
    msg = Message.create(ident, "s", "c", "test", GENESIS_HASH)
    d = msg.to_dict()
    restored = Message.from_dict(d)
    assert restored.id == msg.id
    assert restored.content == msg.content
    assert restored.author_pubkey == msg.author_pubkey
    assert restored.signature == msg.signature
    assert restored.verify_id()
    assert restored.verify_signature()


def test_different_content_different_hash():
    ident = Identity.generate("Alice")
    msg1 = Message.create(ident, "s", "c", "hello", GENESIS_HASH)
    msg2 = Message.create(ident, "s", "c", "world", GENESIS_HASH)
    assert msg1.id != msg2.id
