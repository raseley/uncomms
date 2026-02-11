"""Tests for transport and message encryption."""

import asyncio
import struct
import tempfile
from pathlib import Path

import pytest

from uncomms.identity import Identity, Keyring
from uncomms.message import Message, GENESIS_HASH
from uncomms.network import PeerNetwork
from uncomms.protocol import (
    EncryptedChannel,
    Envelope,
    MsgType,
    derive_transport_keys,
    read_encrypted_envelope,
    write_encrypted_envelope,
)
from uncomms.server import ServerManager
from uncomms.store import MessageStore

from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.utils import random


# -- Transport encryption tests ------------------------------------------------


def test_derive_transport_keys_deterministic():
    """Both peers derive the same shared keys."""
    eph_a = PrivateKey.generate()
    eph_b = PrivateKey.generate()
    static_a = Identity.generate("Alice")
    static_b = Identity.generate("Bob")

    send_a, recv_a = derive_transport_keys(
        eph_a, eph_b.public_key,
        static_a.public_key, static_b.public_key,
    )
    send_b, recv_b = derive_transport_keys(
        eph_b, eph_a.public_key,
        static_b.public_key, static_a.public_key,
    )

    # A's send key == B's recv key and vice versa
    assert send_a == recv_b
    assert recv_a == send_b
    # Send and recv keys are different
    assert send_a != recv_a


def test_derive_transport_keys_different_ephemerals():
    """Different ephemeral keys produce different shared secrets."""
    eph_a1 = PrivateKey.generate()
    eph_a2 = PrivateKey.generate()
    eph_b = PrivateKey.generate()
    static_a = Identity.generate("Alice")
    static_b = Identity.generate("Bob")

    send1, recv1 = derive_transport_keys(
        eph_a1, eph_b.public_key,
        static_a.public_key, static_b.public_key,
    )
    send2, recv2 = derive_transport_keys(
        eph_a2, eph_b.public_key,
        static_a.public_key, static_b.public_key,
    )

    assert send1 != send2
    assert recv1 != recv2


def test_encrypted_channel_roundtrip():
    """EncryptedChannel can send and receive data correctly."""
    async def _run():
        server_streams = {}

        async def handler(reader, writer):
            server_streams["reader"] = reader
            server_streams["writer"] = writer

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        reader_c, writer_c = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.05)

        key_send = random(32)
        key_recv = random(32)

        # Client: send=key_send, recv=key_recv
        # Server: send=key_recv, recv=key_send (swapped)
        ch_client = EncryptedChannel(reader_c, writer_c, key_send, key_recv)
        ch_server = EncryptedChannel(
            server_streams["reader"], server_streams["writer"],
            key_recv, key_send,
        )

        # Client sends, server receives
        await ch_client.send(b"hello from client")
        data = await ch_server.recv()
        assert data == b"hello from client"

        # Server sends, client receives
        await ch_server.send(b"hello from server")
        data = await ch_client.recv()
        assert data == b"hello from server"

        # Multiple messages maintain nonce sync
        for i in range(10):
            msg = f"message {i}".encode()
            await ch_client.send(msg)
            received = await ch_server.recv()
            assert received == msg

        writer_c.close()
        server_streams["writer"].close()
        server.close()
        await server.wait_closed()

    asyncio.new_event_loop().run_until_complete(_run())


def test_encrypted_envelope_roundtrip():
    """Envelopes can be sent through an encrypted channel."""
    async def _run():
        server_streams = {}

        async def handler(reader, writer):
            server_streams["reader"] = reader
            server_streams["writer"] = writer

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        reader_c, writer_c = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.05)

        key_send = random(32)
        key_recv = random(32)

        ch_client = EncryptedChannel(reader_c, writer_c, key_send, key_recv)
        ch_server = EncryptedChannel(
            server_streams["reader"], server_streams["writer"],
            key_recv, key_send,
        )

        # Send an envelope through the encrypted channel
        env = Envelope(
            msg_type=MsgType.NEW_MESSAGE,
            payload={"content": "secret message", "id": "abc123"},
            sender_pubkey="deadbeef",
        )
        await write_encrypted_envelope(ch_client, env)

        received = await read_encrypted_envelope(ch_server)
        assert received is not None
        assert received.msg_type == MsgType.NEW_MESSAGE
        assert received.payload["content"] == "secret message"
        assert received.sender_pubkey == "deadbeef"

        writer_c.close()
        server_streams["writer"].close()
        server.close()
        await server.wait_closed()

    asyncio.new_event_loop().run_until_complete(_run())


# -- Message encryption tests -------------------------------------------------


def test_message_create_encrypted():
    """Message.create with a server key encrypts the content."""
    ident = Identity.generate("Alice")
    server_key = random(32)

    msg = Message.create(
        identity=ident,
        server_id="test_server",
        channel="general",
        content="Hello, encrypted world!",
        prev_hash=GENESIS_HASH,
        server_key=server_key,
    )

    assert msg.encrypted is True
    # Content is hex-encoded ciphertext, not the plaintext
    assert msg.content != "Hello, encrypted world!"
    # Verify it's valid hex
    bytes.fromhex(msg.content)

    # ID and signature are valid (computed over ciphertext)
    assert msg.verify_id()
    assert msg.verify_signature()


def test_message_decrypt_content():
    """Encrypted message content can be decrypted with the server key."""
    ident = Identity.generate("Alice")
    server_key = random(32)

    msg = Message.create(
        identity=ident,
        server_id="test_server",
        channel="general",
        content="Hello, encrypted world!",
        prev_hash=GENESIS_HASH,
        server_key=server_key,
    )

    # Decrypt
    plaintext = msg.decrypt_content(server_key)
    assert plaintext == "Hello, encrypted world!"


def test_message_decrypt_wrong_key_fails():
    """Decryption with wrong key raises an exception."""
    ident = Identity.generate("Alice")
    server_key = random(32)
    wrong_key = random(32)

    msg = Message.create(
        identity=ident,
        server_id="test_server",
        channel="general",
        content="Secret stuff",
        prev_hash=GENESIS_HASH,
        server_key=server_key,
    )

    with pytest.raises(Exception):
        msg.decrypt_content(wrong_key)


def test_message_get_display_content():
    """get_display_content decrypts if key available, else returns raw."""
    ident = Identity.generate("Alice")
    server_key = random(32)

    msg = Message.create(
        identity=ident,
        server_id="test_server",
        channel="general",
        content="Hello!",
        prev_hash=GENESIS_HASH,
        server_key=server_key,
    )

    # With correct key
    assert msg.get_display_content(server_key) == "Hello!"
    # Without key
    assert msg.get_display_content(None) == msg.content
    # With wrong key
    assert msg.get_display_content(random(32)) == "[decryption failed]"


def test_message_unencrypted_unchanged():
    """Messages without server_key are not encrypted."""
    ident = Identity.generate("Alice")

    msg = Message.create(
        identity=ident,
        server_id="test_server",
        channel="general",
        content="Hello plaintext!",
        prev_hash=GENESIS_HASH,
    )

    assert msg.encrypted is False
    assert msg.content == "Hello plaintext!"
    assert msg.get_display_content(None) == "Hello plaintext!"
    assert msg.verify_id()
    assert msg.verify_signature()


def test_encrypted_message_serialization_roundtrip():
    """Encrypted messages survive to_dict/from_dict."""
    ident = Identity.generate("Alice")
    server_key = random(32)

    msg = Message.create(
        identity=ident,
        server_id="test_server",
        channel="general",
        content="Roundtrip test",
        prev_hash=GENESIS_HASH,
        server_key=server_key,
    )

    d = msg.to_dict()
    assert d["encrypted"] is True

    restored = Message.from_dict(d)
    assert restored.encrypted is True
    assert restored.content == msg.content
    assert restored.verify_id()
    assert restored.verify_signature()
    assert restored.decrypt_content(server_key) == "Roundtrip test"


def test_unencrypted_message_serialization_no_flag():
    """Unencrypted messages don't include 'encrypted' in dict."""
    ident = Identity.generate("Alice")

    msg = Message.create(
        identity=ident,
        server_id="test_server",
        channel="general",
        content="Plain",
        prev_hash=GENESIS_HASH,
    )

    d = msg.to_dict()
    assert "encrypted" not in d

    restored = Message.from_dict(d)
    assert restored.encrypted is False


def test_encrypted_flag_not_in_canonical_bytes():
    """The encrypted flag does not affect canonical bytes or hash."""
    ident = Identity.generate("Alice")
    server_key = random(32)

    msg = Message.create(
        identity=ident,
        server_id="test_server",
        channel="general",
        content="Test",
        prev_hash=GENESIS_HASH,
        server_key=server_key,
    )

    # Manually flip the flag — canonical bytes should be the same
    canonical_encrypted = msg.canonical_bytes()
    msg.encrypted = False
    canonical_unencrypted = msg.canonical_bytes()
    assert canonical_encrypted == canonical_unencrypted


# -- Keyring tests -------------------------------------------------------------


def test_keyring_set_get():
    """Keyring stores and retrieves keys."""
    ident = Identity.generate("Alice")
    kr = Keyring(ident)

    key = random(32)
    kr.set_key("server1", key)

    assert kr.get_key("server1") == key
    assert kr.get_key("nonexistent") is None


def test_keyring_save_load():
    """Keyring persists to disk and loads back."""
    ident = Identity.generate("Alice")
    kr = Keyring(ident)

    key1 = random(32)
    key2 = random(32)
    kr.set_key("server1", key1)
    kr.set_key("server2", key2)

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "keyring.enc"
        kr.save(path)

        # Load into new keyring with same identity
        kr2 = Keyring(ident)
        kr2.load(path)

        assert kr2.get_key("server1") == key1
        assert kr2.get_key("server2") == key2


def test_keyring_different_identity_cant_decrypt():
    """Keyring encrypted with one identity can't be read by another."""
    ident_a = Identity.generate("Alice")
    ident_b = Identity.generate("Bob")

    kr = Keyring(ident_a)
    kr.set_key("server1", random(32))

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "keyring.enc"
        kr.save(path)

        # Bob can't read Alice's keyring
        kr_b = Keyring(ident_b)
        kr_b.load(path)
        assert kr_b.get_key("server1") is None  # silently fails


def test_keyring_encrypt_decrypt_for_peer():
    """Server key can be encrypted for a peer and decrypted by them."""
    alice = Identity.generate("Alice")
    bob = Identity.generate("Bob")

    kr_alice = Keyring(alice)
    server_key = random(32)
    kr_alice.set_key("server1", server_key)

    # Alice encrypts the key for Bob
    sealed = kr_alice.encrypt_key_for_peer("server1", bob.public_key)
    assert sealed is not None

    # Bob decrypts it
    kr_bob = Keyring(bob)
    decrypted = kr_bob.decrypt_key_from_peer(sealed, alice.public_key)
    assert decrypted == server_key


def test_keyring_encrypt_nonexistent_key_returns_none():
    """Encrypting a key for a server not in the keyring returns None."""
    alice = Identity.generate("Alice")
    bob = Identity.generate("Bob")

    kr = Keyring(alice)
    result = kr.encrypt_key_for_peer("nonexistent", bob.public_key)
    assert result is None


# -- Store encryption flag tests -----------------------------------------------


def test_store_encrypted_message():
    """Store persists and retrieves the encrypted flag."""
    async def _run():
        with tempfile.TemporaryDirectory() as td:
            store = MessageStore(Path(td) / "test.db")
            store.open()

            ident = Identity.generate("Alice")
            server_key = random(32)

            msg = Message.create(
                identity=ident,
                server_id="srv",
                channel="general",
                content="Secret!",
                prev_hash=GENESIS_HASH,
                server_key=server_key,
            )

            await store.add_message(msg)

            # Retrieve
            stored = await store.get_message(msg.id)
            assert stored is not None
            assert stored.encrypted is True
            assert stored.content == msg.content  # stored as ciphertext

            # Can decrypt
            assert stored.decrypt_content(server_key) == "Secret!"

            store.close()

    asyncio.new_event_loop().run_until_complete(_run())


def test_store_unencrypted_message():
    """Store handles unencrypted messages correctly."""
    async def _run():
        with tempfile.TemporaryDirectory() as td:
            store = MessageStore(Path(td) / "test.db")
            store.open()

            ident = Identity.generate("Alice")

            msg = Message.create(
                identity=ident,
                server_id="srv",
                channel="general",
                content="Plain text",
                prev_hash=GENESIS_HASH,
            )

            await store.add_message(msg)

            stored = await store.get_message(msg.id)
            assert stored is not None
            assert stored.encrypted is False
            assert stored.content == "Plain text"

            store.close()

    asyncio.new_event_loop().run_until_complete(_run())


# -- Network encrypted transport tests -----------------------------------------


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


def test_encrypted_transport_two_nodes(event_loop):
    """Two nodes connect with encrypted transport and exchange messages."""

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

            # Verify both sides have encrypted channels
            for pk, peer in net_a.peers.items():
                assert peer.encrypted_channel is not None, "Alice's peer should have encrypted channel"
            for pk, peer in net_b.peers.items():
                assert peer.encrypted_channel is not None, "Bob's peer should have encrypted channel"

            # Alice sends a message through the encrypted channel
            msg = Message.create(id_a, "srv", "general", "Encrypted hello!", GENESIS_HASH)
            await store_a.add_message(msg)
            await net_a.gossip_message(msg)

            await asyncio.sleep(0.3)

            # Bob should have received it
            assert len(recv_b) == 1
            assert recv_b[0].content == "Encrypted hello!"

            await net_a.stop()
            await net_b.stop()
            store_a.close()
            store_b.close()

    event_loop.run_until_complete(_run())


def test_encrypted_transport_sync(event_loop):
    """Sync works over encrypted transport."""

    async def _run():
        with tempfile.TemporaryDirectory() as td:
            id_a, store_a, net_a, recv_a = _make_node(td, "Alice")
            id_b, store_b, net_b, recv_b = _make_node(td, "Bob")

            net_a.server_ids = ["srv"]
            net_b.server_ids = ["srv"]

            # Alice creates messages before Bob connects
            m1 = Message.create(id_a, "srv", "general", "Pre-existing 1", GENESIS_HASH, timestamp=1.0)
            m2 = Message.create(id_a, "srv", "general", "Pre-existing 2", m1.id, timestamp=2.0)
            await store_a.add_message(m1)
            await store_a.add_message(m2)
            net_a._seen_ids.add(m1.id)
            net_a._seen_ids.add(m2.id)

            await net_a.start()
            await net_b.start()

            # Bob connects — encrypted transport + sync
            await net_b.connect_to_peer("127.0.0.1", net_a.actual_port)

            await asyncio.sleep(0.5)

            # Bob should have synced both messages via encrypted channel
            msgs = await store_b.get_channel_messages("srv", "general")
            assert len(msgs) == 2
            assert msgs[0].content == "Pre-existing 1"
            assert msgs[1].content == "Pre-existing 2"

            await net_a.stop()
            await net_b.stop()
            store_a.close()
            store_b.close()

    event_loop.run_until_complete(_run())


def test_key_exchange_message_type():
    """KEY_EXCHANGE message type roundtrips correctly."""
    env = Envelope(
        msg_type=MsgType.KEY_EXCHANGE,
        payload={"server_id": "test_server", "sealed_key": "aabbccdd"},
        sender_pubkey="deadbeef",
    )
    raw = env.to_bytes()
    restored = Envelope.from_json(raw[4:])
    assert restored.msg_type == MsgType.KEY_EXCHANGE
    assert restored.payload["server_id"] == "test_server"
    assert restored.payload["sealed_key"] == "aabbccdd"


# -- Ed25519 to Curve25519 conversion tests -----------------------------------


def test_ed25519_to_curve25519_conversion():
    """Ed25519 keys can be converted to Curve25519 for key exchange."""
    alice = Identity.generate("Alice")
    bob = Identity.generate("Bob")

    # Convert and create a Box
    curve_sk = alice.to_curve25519_private_key()
    curve_pk = Identity.verify_key_to_curve25519(bob.public_key)

    from nacl.public import Box
    box = Box(curve_sk, curve_pk)

    # Encrypt something
    ct = box.encrypt(b"test message")

    # Bob decrypts
    curve_sk_bob = bob.to_curve25519_private_key()
    curve_pk_alice = Identity.verify_key_to_curve25519(alice.public_key)
    box_bob = Box(curve_sk_bob, curve_pk_alice)
    pt = box_bob.decrypt(ct)
    assert pt == b"test message"
