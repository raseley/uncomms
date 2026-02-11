"""Tests for SQLite store."""

import asyncio
import tempfile
from pathlib import Path

import pytest

from uncomms.identity import Identity
from uncomms.message import Message, GENESIS_HASH
from uncomms.store import MessageStore


@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as td:
        s = MessageStore(Path(td) / "test.db")
        s.open()
        yield s
        s.close()


@pytest.fixture
def ident():
    return Identity.generate("Tester")


def test_add_and_get(store, ident):
    msg = Message.create(ident, "srv1", "general", "hello", GENESIS_HASH)

    added = asyncio.get_event_loop().run_until_complete(store.add_message(msg))
    assert added is True

    # Duplicate
    added2 = asyncio.get_event_loop().run_until_complete(store.add_message(msg))
    assert added2 is False

    # Retrieve
    got = asyncio.get_event_loop().run_until_complete(store.get_message(msg.id))
    assert got is not None
    assert got.id == msg.id
    assert got.content == "hello"


def test_channel_messages(store, ident):
    m1 = Message.create(ident, "s", "general", "first", GENESIS_HASH, timestamp=1.0)
    m2 = Message.create(ident, "s", "general", "second", m1.id, timestamp=2.0)
    m3 = Message.create(ident, "s", "random", "other", GENESIS_HASH, timestamp=1.5)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(store.add_message(m1))
    loop.run_until_complete(store.add_message(m2))
    loop.run_until_complete(store.add_message(m3))

    msgs = loop.run_until_complete(store.get_channel_messages("s", "general"))
    assert len(msgs) == 2
    assert msgs[0].content == "first"
    assert msgs[1].content == "second"

    msgs2 = loop.run_until_complete(store.get_channel_messages("s", "random"))
    assert len(msgs2) == 1


def test_chain_head(store, ident):
    loop = asyncio.get_event_loop()

    head = loop.run_until_complete(store.get_chain_head("s", "c"))
    assert head == ""

    m1 = Message.create(ident, "s", "c", "first", GENESIS_HASH, timestamp=1.0)
    loop.run_until_complete(store.add_message(m1))
    head = loop.run_until_complete(store.get_chain_head("s", "c"))
    assert head == m1.id


def test_has_message(store, ident):
    loop = asyncio.get_event_loop()

    assert loop.run_until_complete(store.has_message("nonexistent")) is False
    msg = Message.create(ident, "s", "c", "test", GENESIS_HASH)
    loop.run_until_complete(store.add_message(msg))
    assert loop.run_until_complete(store.has_message(msg.id)) is True


def test_server_persistence(store):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(store.save_server("id1", "TestServer", 1000.0, "pk123"))
    servers = loop.run_until_complete(store.get_servers())
    assert len(servers) == 1
    assert servers[0]["name"] == "TestServer"


def test_channels(store, ident):
    loop = asyncio.get_event_loop()
    m1 = Message.create(ident, "s", "general", "hi", GENESIS_HASH)
    m2 = Message.create(ident, "s", "random", "yo", GENESIS_HASH)
    loop.run_until_complete(store.add_message(m1))
    loop.run_until_complete(store.add_message(m2))

    channels = loop.run_until_complete(store.get_channels("s"))
    assert set(channels) == {"general", "random"}
