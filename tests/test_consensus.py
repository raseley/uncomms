"""Tests for consensus/validation."""

import asyncio
import tempfile
import time
from pathlib import Path

import pytest

from uncomms.consensus import ChainValidator
from uncomms.identity import Identity
from uncomms.message import Message, GENESIS_HASH
from uncomms.store import MessageStore


@pytest.fixture
def setup():
    with tempfile.TemporaryDirectory() as td:
        store = MessageStore(Path(td) / "test.db")
        store.open()
        validator = ChainValidator(store)
        ident = Identity.generate("Tester")
        yield store, validator, ident
        store.close()


def test_validate_good_message(setup):
    store, validator, ident = setup
    msg = Message.create(ident, "s", "c", "hello", GENESIS_HASH)

    loop = asyncio.get_event_loop()
    valid, err = loop.run_until_complete(validator.validate_message(msg))
    assert valid is True
    assert err == ""


def test_validate_bad_id(setup):
    store, validator, ident = setup
    msg = Message.create(ident, "s", "c", "hello", GENESIS_HASH)
    msg.id = "0" * 64  # wrong hash

    loop = asyncio.get_event_loop()
    valid, err = loop.run_until_complete(validator.validate_message(msg))
    assert valid is False
    assert "id mismatch" in err


def test_validate_bad_signature(setup):
    store, validator, ident = setup
    msg = Message.create(ident, "s", "c", "hello", GENESIS_HASH)
    # Tamper content but keep old signature
    original_sig = msg.signature
    original_id = msg.id
    msg.content = "tampered"
    msg.signature = original_sig
    msg.id = original_id

    loop = asyncio.get_event_loop()
    valid, err = loop.run_until_complete(validator.validate_message(msg))
    assert valid is False


def test_validate_future_timestamp(setup):
    store, validator, ident = setup
    msg = Message.create(
        ident, "s", "c", "hello", GENESIS_HASH,
        timestamp=time.time() + 600,  # 10 min in future
    )

    loop = asyncio.get_event_loop()
    valid, err = loop.run_until_complete(validator.validate_message(msg))
    assert valid is False
    assert "future" in err


def test_validate_chain(setup):
    store, validator, ident = setup
    loop = asyncio.get_event_loop()

    m1 = Message.create(ident, "s", "c", "first", GENESIS_HASH, timestamp=1.0)
    m2 = Message.create(ident, "s", "c", "second", m1.id, timestamp=2.0)
    loop.run_until_complete(store.add_message(m1))
    loop.run_until_complete(store.add_message(m2))

    errors = loop.run_until_complete(validator.validate_chain("s", "c"))
    assert errors == []


def test_resolve_fork():
    ident = Identity.generate("A")
    # Two messages with same prev_hash (a fork)
    m1 = Message.create(ident, "s", "c", "aaa", GENESIS_HASH, timestamp=2.0)
    m2 = Message.create(ident, "s", "c", "bbb", GENESIS_HASH, timestamp=1.0)
    ordered = ChainValidator.resolve_fork([m1, m2])
    assert ordered[0].timestamp <= ordered[1].timestamp


def test_detect_missing():
    our = {"a", "b", "c"}
    theirs = {"b", "c", "d", "e"}
    we_need, they_need = ChainValidator.detect_missing(our, theirs)
    assert we_need == {"d", "e"}
    assert they_need == {"a"}
