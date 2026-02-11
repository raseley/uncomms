"""Message model with hashchain linking."""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass

from .identity import Identity

GENESIS_HASH = "0" * 64


def _lp(b: bytes) -> bytes:
    """Length-prefix a byte string (4-byte big-endian length + payload)."""
    return struct.pack(">I", len(b)) + b


@dataclass
class Message:
    id: str  # SHA-256 of canonical_bytes
    server_id: str
    channel: str
    author_pubkey: bytes  # 32 bytes
    author_name: str
    content: str
    timestamp: float
    prev_hash: str  # hash of the previous message in this channel
    signature: bytes  # 64-byte Ed25519 signature

    # -- canonical form --------------------------------------------------------

    def canonical_bytes(self) -> bytes:
        """Deterministic byte representation used for hashing and signing.

        Fields are length-prefixed to prevent ambiguity.
        """
        return b"".join(
            [
                _lp(self.server_id.encode()),
                _lp(self.channel.encode()),
                _lp(self.author_pubkey),
                _lp(self.content.encode()),
                _lp(f"{self.timestamp:.6f}".encode()),
                _lp(self.prev_hash.encode()),
            ]
        )

    @staticmethod
    def compute_hash(canonical: bytes) -> str:
        return hashlib.sha256(canonical).hexdigest()

    def verify_id(self) -> bool:
        return self.id == self.compute_hash(self.canonical_bytes())

    def verify_signature(self) -> bool:
        return Identity.verify(self.author_pubkey, self.canonical_bytes(), self.signature)

    # -- construction helpers --------------------------------------------------

    @classmethod
    def create(
        cls,
        identity: Identity,
        server_id: str,
        channel: str,
        content: str,
        prev_hash: str,
        timestamp: float | None = None,
    ) -> Message:
        ts = timestamp if timestamp is not None else time.time()
        msg = cls(
            id="",  # computed below
            server_id=server_id,
            channel=channel,
            author_pubkey=identity.public_key,
            author_name=identity.display_name,
            content=content,
            timestamp=ts,
            prev_hash=prev_hash,
            signature=b"",  # computed below
        )
        canonical = msg.canonical_bytes()
        msg.signature = identity.sign(canonical)
        msg.id = cls.compute_hash(canonical)
        return msg

    # -- serialization ---------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "server_id": self.server_id,
            "channel": self.channel,
            "author_pubkey": self.author_pubkey.hex(),
            "author_name": self.author_name,
            "content": self.content,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> Message:
        return cls(
            id=d["id"],
            server_id=d["server_id"],
            channel=d["channel"],
            author_pubkey=bytes.fromhex(d["author_pubkey"]),
            author_name=d["author_name"],
            content=d["content"],
            timestamp=d["timestamp"],
            prev_hash=d["prev_hash"],
            signature=bytes.fromhex(d["signature"]),
        )
