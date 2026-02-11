"""Server (guild) and channel management."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field

from .identity import Identity
from .store import MessageStore


@dataclass
class Server:
    id: str
    name: str
    channels: list[str] = field(default_factory=lambda: ["general"])
    members: dict[str, str] = field(default_factory=dict)  # pubkey_hex -> display_name
    creator_pubkey: str = ""
    created_at: float = 0.0


class ServerManager:
    def __init__(self, store: MessageStore, identity: Identity) -> None:
        self.store = store
        self.identity = identity
        self.servers: dict[str, Server] = {}

    def create_server(self, name: str) -> Server:
        raw = f"{self.identity.pubkey_hex}:{name}:{time.time()}"
        server_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        srv = Server(
            id=server_id,
            name=name,
            channels=["general"],
            members={self.identity.pubkey_hex: self.identity.display_name},
            creator_pubkey=self.identity.pubkey_hex,
            created_at=time.time(),
        )
        self.servers[server_id] = srv
        return srv

    async def persist_server(self, srv: Server) -> None:
        await self.store.save_server(
            srv.id, srv.name, srv.created_at, srv.creator_pubkey
        )

    async def load_servers(self) -> None:
        rows = await self.store.get_servers()
        for r in rows:
            sid = r["id"]
            if sid not in self.servers:
                self.servers[sid] = Server(
                    id=sid,
                    name=r["name"],
                    created_at=r["created_at"],
                    creator_pubkey=r["creator_pubkey"],
                )
            # Load channels from existing messages
            channels = await self.store.get_channels(sid)
            if channels:
                self.servers[sid].channels = list(
                    set(self.servers[sid].channels) | set(channels)
                )
            if "general" not in self.servers[sid].channels:
                self.servers[sid].channels.insert(0, "general")

    def add_channel(self, server_id: str, channel_name: str) -> bool:
        srv = self.servers.get(server_id)
        if not srv:
            return False
        if channel_name not in srv.channels:
            srv.channels.append(channel_name)
        return True

    def add_member(self, server_id: str, pubkey: str, display_name: str) -> None:
        srv = self.servers.get(server_id)
        if srv:
            srv.members[pubkey] = display_name

    def get_server(self, server_id: str) -> Server | None:
        return self.servers.get(server_id)
