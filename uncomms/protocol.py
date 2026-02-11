"""Wire protocol: message types, envelope, and length-prefix framing."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

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
