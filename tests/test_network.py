"""Integration test: multi-node message exchange."""

import asyncio
import tempfile
from pathlib import Path

import pytest

from uncomms.identity import Identity
from uncomms.message import Message, GENESIS_HASH
from uncomms.network import PeerNetwork
from uncomms.store import MessageStore


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def _make_node(tmpdir: str, name: str, port: int = 0):
    ident = Identity.generate(name)
    store = MessageStore(Path(tmpdir) / f"{name}.db")
    store.open()
    received = []

    async def on_msg(msg):
        received.append(msg)

    net = PeerNetwork(
        identity=ident, host="127.0.0.1", port=port,
        store=store, on_message=on_msg,
    )
    return ident, store, net, received


def test_two_nodes_exchange(event_loop):
    """Two nodes connect and exchange a message."""

    async def _run():
        with tempfile.TemporaryDirectory() as td:
            id_a, store_a, net_a, recv_a = _make_node(td, "Alice")
            id_b, store_b, net_b, recv_b = _make_node(td, "Bob")

            net_a.server_ids = ["srv"]
            net_b.server_ids = ["srv"]

            await net_a.start()
            await net_b.start()

            # Bob connects to Alice
            ok = await net_b.connect_to_peer("127.0.0.1", net_a.actual_port)
            assert ok

            await asyncio.sleep(0.2)

            # Alice sends a message
            msg = Message.create(id_a, "srv", "general", "Hello Bob!", GENESIS_HASH)
            await store_a.add_message(msg)
            await net_a.gossip_message(msg)

            await asyncio.sleep(0.3)

            # Bob should have received it
            assert len(recv_b) == 1
            assert recv_b[0].content == "Hello Bob!"

            # And it should be in Bob's store
            stored = await store_b.get_message(msg.id)
            assert stored is not None

            await net_a.stop()
            await net_b.stop()
            store_a.close()
            store_b.close()

    event_loop.run_until_complete(_run())


def test_three_nodes_gossip(event_loop):
    """Message from Alice reaches Charlie via Bob (gossip)."""

    async def _run():
        with tempfile.TemporaryDirectory() as td:
            id_a, store_a, net_a, recv_a = _make_node(td, "Alice")
            id_b, store_b, net_b, recv_b = _make_node(td, "Bob")
            id_c, store_c, net_c, recv_c = _make_node(td, "Charlie")

            for n in (net_a, net_b, net_c):
                n.server_ids = ["srv"]

            await net_a.start()
            await net_b.start()
            await net_c.start()

            # Bob connects to Alice
            await net_b.connect_to_peer("127.0.0.1", net_a.actual_port)
            # Charlie connects to Bob
            await net_c.connect_to_peer("127.0.0.1", net_b.actual_port)

            await asyncio.sleep(0.3)

            # Alice sends a message
            msg = Message.create(id_a, "srv", "general", "Hello everyone!", GENESIS_HASH)
            await store_a.add_message(msg)
            await net_a.gossip_message(msg)

            await asyncio.sleep(0.5)

            # Both Bob and Charlie should receive it
            assert len(recv_b) >= 1
            assert any(m.content == "Hello everyone!" for m in recv_b)
            assert len(recv_c) >= 1
            assert any(m.content == "Hello everyone!" for m in recv_c)

            await net_a.stop()
            await net_b.stop()
            await net_c.stop()
            store_a.close()
            store_b.close()
            store_c.close()

    event_loop.run_until_complete(_run())


def test_sync_on_connect(event_loop):
    """Bob gets Alice's existing messages when he connects."""

    async def _run():
        with tempfile.TemporaryDirectory() as td:
            id_a, store_a, net_a, recv_a = _make_node(td, "Alice")
            id_b, store_b, net_b, recv_b = _make_node(td, "Bob")

            net_a.server_ids = ["srv"]
            net_b.server_ids = ["srv"]

            # Alice creates messages before Bob connects
            m1 = Message.create(id_a, "srv", "general", "Message 1", GENESIS_HASH, timestamp=1.0)
            m2 = Message.create(id_a, "srv", "general", "Message 2", m1.id, timestamp=2.0)
            await store_a.add_message(m1)
            await store_a.add_message(m2)
            net_a._seen_ids.add(m1.id)
            net_a._seen_ids.add(m2.id)

            await net_a.start()
            await net_b.start()

            # Bob connects — should trigger sync
            await net_b.connect_to_peer("127.0.0.1", net_a.actual_port)

            await asyncio.sleep(0.5)

            # Bob should have both messages
            msgs = await store_b.get_channel_messages("srv", "general")
            assert len(msgs) == 2
            assert msgs[0].content == "Message 1"
            assert msgs[1].content == "Message 2"

            await net_a.stop()
            await net_b.stop()
            store_a.close()
            store_b.close()

    event_loop.run_until_complete(_run())
