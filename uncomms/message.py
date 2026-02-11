"""Message model with hashchain linking."""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass

from nacl.secret import SecretBox

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
    encrypted: bool = False  # metadata flag (not in canonical bytes or hash)

    # -- canonical form --------------------------------------------------------

    def canonical_bytes(self) -> bytes:
        """Deterministic byte representation used for hashing and signing.

        Fields are length-prefixed to prevent ambiguity.
        The `encrypted` flag is NOT included — it's metadata only.
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
        server_key: bytes | None = None,
    ) -> Message:
        """Create a new signed message.

        If *server_key* is provided, the content is encrypted before
        signing — the hashchain covers ciphertext.
        """
        ts = timestamp if timestamp is not None else time.time()

        encrypted = False
        final_content = content
        if server_key is not None:
            box = SecretBox(server_key)
            ct = box.encrypt(content.encode())
            final_content = ct.hex()
            encrypted = True

        msg = cls(
            id="",  # computed below
            server_id=server_id,
            channel=channel,
            author_pubkey=identity.public_key,
            author_name=identity.display_name,
            content=final_content,
            timestamp=ts,
            prev_hash=prev_hash,
            signature=b"",  # computed below
            encrypted=encrypted,
        )
        canonical = msg.canonical_bytes()
        msg.signature = identity.sign(canonical)
        msg.id = cls.compute_hash(canonical)
        return msg

    # -- encryption helpers ----------------------------------------------------

    def decrypt_content(self, server_key: bytes) -> str:
        """Decrypt the content field using the server key.

        Returns the plaintext string. Raises on failure.
        """
        ct = bytes.fromhex(self.content)
        box = SecretBox(server_key)
        return box.decrypt(ct).decode()

    def get_display_content(self, server_key: bytes | None = None) -> str:
        """Return content suitable for display.

        If encrypted and key is available, decrypt. Otherwise return
        the raw content (ciphertext hex for encrypted messages without key).
        """
        if self.encrypted and server_key is not None:
            try:
                return self.decrypt_content(server_key)
            except Exception:
                return "[decryption failed]"
        return self.content

    # -- serialization ---------------------------------------------------------

    def to_dict(self) -> dict:
        d = {
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
        if self.encrypted:
            d["encrypted"] = True
        return d

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
            encrypted=d.get("encrypted", False),
        )
