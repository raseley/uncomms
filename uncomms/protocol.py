"""Wire protocol: message types, envelope, and length-prefix framing."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.hash import blake2b
from nacl import encoding

MAX_PAYLOAD = 4 * 1024 * 1024  # 4 MiB safety limit


class MsgType(str, Enum):
    # Handshake
    HELLO = "hello"
    HELLO_ACK = "hello_ack"
    # Chat messages
    NEW_MESSAGE = "new_message"
    # Sync
    SYNC_REQUEST = "sync_req"
    SYNC_RESPONSE = "sync_resp"
    # Peer discovery
    PEER_LIST = "peer_list"
    # Bootstrap
    REGISTER = "register"
    DISCOVER = "discover"
    DISCOVER_RESPONSE = "discover_resp"
    # Server management
    SERVER_INFO = "server_info"
    # NAT traversal
    PUNCH_REQUEST = "punch_req"    # client → bootstrap: request hole punch
    PUNCH_NOTIFY = "punch_notify"  # bootstrap → client: punch notification
    RELAY = "relay"                # peer → peer: relay envelope to another peer
    # Encryption
    KEY_EXCHANGE = "key_exchange"   # server key distribution on join


@dataclass
class Envelope:
    msg_type: MsgType
    payload: dict[str, Any]
    sender_pubkey: str = ""  # hex-encoded

    def to_bytes(self) -> bytes:
        raw = json.dumps(
            {
                "type": self.msg_type.value,
                "payload": self.payload,
                "sender": self.sender_pubkey,
            },
            separators=(",", ":"),
        ).encode()
        return struct.pack(">I", len(raw)) + raw

    @classmethod
    def from_json(cls, data: bytes) -> Envelope:
        obj = json.loads(data)
        return cls(
            msg_type=MsgType(obj["type"]),
            payload=obj.get("payload", {}),
            sender_pubkey=obj.get("sender", ""),
        )


# -- async stream helpers ------------------------------------------------------


async def read_envelope(reader) -> Envelope | None:
    """Read one length-prefixed envelope from an asyncio StreamReader."""
    try:
        header = await reader.readexactly(4)
    except Exception:
        return None
    length = struct.unpack(">I", header)[0]
    if length > MAX_PAYLOAD:
        return None
    try:
        data = await reader.readexactly(length)
    except Exception:
        return None
    return Envelope.from_json(data)


async def write_envelope(writer, envelope: Envelope) -> None:
    """Write one length-prefixed envelope to an asyncio StreamWriter."""
    writer.write(envelope.to_bytes())
    await writer.drain()


# -- transport encryption ------------------------------------------------------


def derive_transport_keys(
    eph_sk: PrivateKey,
    peer_eph_pk: PublicKey,
    our_static_pk: bytes,
    peer_static_pk: bytes,
) -> tuple[bytes, bytes]:
    """Derive directional send/recv keys from ephemeral DH + static pubkeys.

    The two peers sort their static public keys lexicographically. The
    "lower" key holder uses key_a for sending and key_b for receiving;
    the "higher" key holder does the opposite.
    """
    box = Box(eph_sk, peer_eph_pk)
    shared = box.shared_key()  # 32 bytes

    keys_sorted = sorted([our_static_pk, peer_static_pk])
    material = shared + keys_sorted[0] + keys_sorted[1]
    tx_rx = blake2b(material, digest_size=64, encoder=encoding.RawEncoder)
    key_a, key_b = tx_rx[:32], tx_rx[32:]

    if our_static_pk == keys_sorted[0]:
        return key_a, key_b  # send_key, recv_key
    else:
        return key_b, key_a


class EncryptedChannel:
    """Wraps an asyncio (reader, writer) pair with XSalsa20-Poly1305 encryption.

    Each direction uses a separate SecretBox key and a monotonically
    incrementing 24-byte nonce (uint192, big-endian).
    """

    def __init__(
        self,
        reader,
        writer,
        send_key: bytes,
        recv_key: bytes,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self._send_box = SecretBox(send_key)
        self._recv_box = SecretBox(recv_key)
        self._send_nonce: int = 0
        self._recv_nonce: int = 0

    def _next_send_nonce(self) -> bytes:
        nonce = self._send_nonce.to_bytes(24, "big")
        self._send_nonce += 1
        return nonce

    def _next_recv_nonce(self) -> bytes:
        nonce = self._recv_nonce.to_bytes(24, "big")
        self._recv_nonce += 1
        return nonce

    async def send(self, plaintext: bytes) -> None:
        """Encrypt and write one length-prefixed frame."""
        nonce = self._next_send_nonce()
        ct = self._send_box.encrypt(plaintext, nonce)  # nonce + ciphertext + tag
        frame = struct.pack(">I", len(ct)) + ct
        self.writer.write(frame)
        await self.writer.drain()

    async def recv(self) -> bytes | None:
        """Read and decrypt one length-prefixed frame."""
        try:
            header = await self.reader.readexactly(4)
        except Exception:
            return None
        length = struct.unpack(">I", header)[0]
        if length > MAX_PAYLOAD:
            return None
        try:
            ct = await self.reader.readexactly(length)
        except Exception:
            return None
        nonce = self._next_recv_nonce()
        try:
            return self._recv_box.decrypt(ct, nonce=None)  # nonce is prepended in ct
        except Exception:
            return None


async def read_encrypted_envelope(channel: EncryptedChannel) -> Envelope | None:
    """Read one envelope through an encrypted channel."""
    data = await channel.recv()
    if data is None:
        return None
    try:
        return Envelope.from_json(data)
    except Exception:
        return None


async def write_encrypted_envelope(
    channel: EncryptedChannel, envelope: Envelope
) -> None:
    """Write one envelope through an encrypted channel."""
    raw = envelope.to_bytes()
    # Strip the length prefix — EncryptedChannel adds its own
    payload = raw[4:]
    await channel.send(payload)
