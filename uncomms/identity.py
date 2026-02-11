"""Cryptographic identity: Ed25519 key generation, signing, verification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey as CurvePrivateKey, PublicKey as CurvePublicKey, Box
from nacl.secret import SecretBox
from nacl.hash import blake2b
from nacl.exceptions import BadSignatureError
from nacl.utils import random
from nacl import encoding


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

    # -- Curve25519 conversion helpers -----------------------------------------

    def to_curve25519_private_key(self) -> CurvePrivateKey:
        """Convert Ed25519 signing key to Curve25519 for key exchange."""
        return self._signing_key.to_curve25519_private_key()

    @staticmethod
    def verify_key_to_curve25519(public_key: bytes) -> CurvePublicKey:
        """Convert an Ed25519 verify key (raw bytes) to Curve25519 public key."""
        vk = VerifyKey(public_key)
        return vk.to_curve25519_public_key()

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


# -- Keyring (server key storage) ---------------------------------------------

_KEYRING_SALT = b"uncomms-keyring"


class Keyring:
    """Encrypted local storage for server symmetric keys.

    The keyring is encrypted with a key derived from the Ed25519 private key
    via blake2b. If the identity is compromised, the keyring is too — this is
    intentional: the identity IS the access credential.
    """

    def __init__(self, identity: Identity) -> None:
        self._identity = identity
        self._keys: dict[str, bytes] = {}  # server_id -> 32-byte server key
        self._derive_key = blake2b(
            identity.private_key,
            digest_size=32,
            salt=_KEYRING_SALT[:16],  # blake2b salt is max 16 bytes
            encoder=encoding.RawEncoder,
        )

    @property
    def keys(self) -> dict[str, bytes]:
        return self._keys

    def set_key(self, server_id: str, server_key: bytes) -> None:
        self._keys[server_id] = server_key

    def get_key(self, server_id: str) -> bytes | None:
        return self._keys.get(server_id)

    def save(self, path: Path) -> None:
        """Encrypt and save the keyring to disk."""
        path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = json.dumps(
            {sid: key.hex() for sid, key in self._keys.items()}
        ).encode()
        box = SecretBox(self._derive_key)
        ct = box.encrypt(plaintext)
        path.write_bytes(ct)

    def load(self, path: Path) -> None:
        """Load and decrypt the keyring from disk."""
        if not path.exists():
            return
        ct = path.read_bytes()
        box = SecretBox(self._derive_key)
        try:
            plaintext = box.decrypt(ct)
            data = json.loads(plaintext)
            self._keys = {sid: bytes.fromhex(h) for sid, h in data.items()}
        except Exception:
            # Corrupted keyring — start fresh
            self._keys = {}

    def encrypt_key_for_peer(
        self, server_id: str, peer_pubkey: bytes
    ) -> bytes | None:
        """Encrypt a server key for a specific peer using NaCl Box.

        Uses Ed25519→Curve25519 conversion for authenticated encryption.
        """
        server_key = self._keys.get(server_id)
        if server_key is None:
            return None
        curve_sk = self._identity.to_curve25519_private_key()
        curve_pk = Identity.verify_key_to_curve25519(peer_pubkey)
        box = Box(curve_sk, curve_pk)
        return box.encrypt(server_key)

    def decrypt_key_from_peer(
        self, sealed_key: bytes, peer_pubkey: bytes
    ) -> bytes:
        """Decrypt a server key received from a peer."""
        curve_sk = self._identity.to_curve25519_private_key()
        curve_pk = Identity.verify_key_to_curve25519(peer_pubkey)
        box = Box(curve_sk, curve_pk)
        return box.decrypt(sealed_key)
