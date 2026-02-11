"""Cryptographic identity: Ed25519 key generation, signing, verification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


@dataclass
class Identity:
    _signing_key: SigningKey
    display_name: str

    # -- construction ----------------------------------------------------------

    @classmethod
    def generate(cls, display_name: str) -> Identity:
        return cls(_signing_key=SigningKey.generate(), display_name=display_name)

    @classmethod
    def load(cls, path: Path) -> Identity:
        data = json.loads(path.read_text())
        sk = SigningKey(bytes.fromhex(data["private_key"]))
        return cls(_signing_key=sk, display_name=data["display_name"])

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "private_key": self.private_key.hex(),
            "public_key": self.public_key.hex(),
            "display_name": self.display_name,
        }
        path.write_text(json.dumps(data, indent=2))

    # -- keys ------------------------------------------------------------------

    @property
    def private_key(self) -> bytes:
        return bytes(self._signing_key)

    @property
    def public_key(self) -> bytes:
        return bytes(self._signing_key.verify_key)

    @property
    def pubkey_hex(self) -> str:
        return self.public_key.hex()

    @property
    def fingerprint(self) -> str:
        """Short identifier derived from the public key (first 8 hex chars)."""
        return self.pubkey_hex[:8]

    # -- sign / verify ---------------------------------------------------------

    def sign(self, data: bytes) -> bytes:
        """Return the 64-byte Ed25519 signature over *data*."""
        return self._signing_key.sign(data).signature

    @staticmethod
    def verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
        try:
            VerifyKey(public_key).verify(data, signature)
            return True
        except (BadSignatureError, Exception):
            return False
