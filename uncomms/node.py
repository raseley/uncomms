"""Main node orchestrator — ties all components together."""

from __future__ import annotations

import asyncio
import logging
import queue

from .config import Config
from .consensus import ChainValidator
from .identity import Identity
from .message import Message, GENESIS_HASH
from .network import PeerNetwork
from .server import Server, ServerManager
from .store import MessageStore

log = logging.getLogger(__name__)


class Node:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.identity: Identity | None = None
        self.store: MessageStore | None = None
        self.network: PeerNetwork | None = None
        self.validator: ChainValidator | None = None
        self.server_mgr: ServerManager | None = None
        self.ui_queue: queue.Queue = queue.Queue()  # async -> UI updates
        self._loop: asyncio.AbstractEventLoop | None = None

    # -- lifecycle -------------------------------------------------------------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self.config.ensure_dirs()

        # Identity
        if self.config.identity_path.exists():
            self.identity = Identity.load(self.config.identity_path)
            log.info("Loaded identity: %s (%s)", self.identity.display_name, self.identity.fingerprint)
        else:
            name = self.config.display_name or "anon"
            self.identity = Identity.generate(name)
            self.identity.save(self.config.identity_path)
            log.info("Generated new identity: %s (%s)", self.identity.display_name, self.identity.fingerprint)

        # Store
        self.store = MessageStore(self.config.db_path)
        self.store.open()

        # Consensus
        self.validator = ChainValidator(self.store)

        # Server manager
        self.server_mgr = ServerManager(self.store, self.identity)
        await self.server_mgr.load_servers()

        # Network
        self.network = PeerNetwork(
            identity=self.identity,
            host=self.config.listen_host,
            port=self.config.listen_port,
            store=self.store,
            on_message=self._on_peer_message,
            on_peer_update=self._on_peer_update,
        )
        self.network.server_ids = list(self.server_mgr.servers.keys())
        await self.network.start()

        # Connect to initial peers
        for host, port in self.config.initial_peers:
            asyncio.ensure_future(self.network.connect_to_peer(host, port))

        # Bootstrap registration
        if self.config.bootstrap:
            asyncio.ensure_future(self._bootstrap_loop())

    async def shutdown(self) -> None:
        if self.network:
            await self.network.stop()
        if self.store:
            self.store.close()

    # -- sending messages ------------------------------------------------------

    async def send_message(self, server_id: str, channel: str, content: str) -> Message:
        head = await self.store.get_chain_head(server_id, channel)
        prev_hash = head if head else GENESIS_HASH

        msg = Message.create(
            identity=self.identity,
            server_id=server_id,
            channel=channel,
            content=content,
            prev_hash=prev_hash,
        )

        await self.store.add_message(msg)
        await self.network.gossip_message(msg)

        self.ui_queue.put(("new_message", msg))
        return msg

    # -- callbacks from network ------------------------------------------------

    async def _on_peer_message(self, msg: Message) -> None:
        # Track member
        srv = self.server_mgr.get_server(msg.server_id)
        if srv:
            self.server_mgr.add_member(
                msg.server_id, msg.author_pubkey.hex(), msg.author_name
            )
        self.ui_queue.put(("new_message", msg))

    async def _on_peer_update(self) -> None:
        self.ui_queue.put(("peer_update", None))

    # -- server management -----------------------------------------------------

    async def create_server(self, name: str) -> Server:
        srv = self.server_mgr.create_server(name)
        await self.server_mgr.persist_server(srv)
        self.network.server_ids = list(self.server_mgr.servers.keys())
        self.ui_queue.put(("server_update", srv))
        return srv

    async def join_server(self, server_id: str, peer_host: str, peer_port: int) -> bool:
        """Join a server by connecting to a peer that's in it."""
        if server_id not in self.server_mgr.servers:
            self.server_mgr.servers[server_id] = Server(
                id=server_id, name=f"server-{server_id[:8]}"
            )
        self.network.server_ids = list(self.server_mgr.servers.keys())
        ok = await self.network.connect_to_peer(peer_host, peer_port)
        if ok:
            self.ui_queue.put(("server_update", None))
        return ok

    def create_channel(self, server_id: str, channel_name: str) -> bool:
        ok = self.server_mgr.add_channel(server_id, channel_name)
        if ok:
            self.ui_queue.put(("server_update", None))
        return ok

    # -- bootstrap -------------------------------------------------------------

    async def _bootstrap_loop(self) -> None:
        from .protocol import Envelope, MsgType, read_envelope, write_envelope

        parts = self.config.bootstrap.rpartition(":")
        bs_host = parts[0] or "127.0.0.1"
        bs_port = int(parts[2])

        while True:
            try:
                for sid in list(self.server_mgr.servers.keys()):
                    # Register
                    reader, writer = await asyncio.open_connection(bs_host, bs_port)
                    reg = Envelope(
                        msg_type=MsgType.REGISTER,
                        payload={
                            "server_id": sid,
                            "host": self.config.listen_host,
                            "port": self.network.actual_port,
                        },
                        sender_pubkey=self.identity.pubkey_hex,
                    )
                    await write_envelope(writer, reg)
                    writer.close()

                    # Discover peers
                    reader, writer = await asyncio.open_connection(bs_host, bs_port)
                    disc = Envelope(
                        msg_type=MsgType.DISCOVER,
                        payload={"server_id": sid},
                        sender_pubkey=self.identity.pubkey_hex,
                    )
                    await write_envelope(writer, disc)
                    resp = await read_envelope(reader)
                    writer.close()

                    if resp and resp.msg_type == MsgType.DISCOVER_RESPONSE:
                        for p in resp.payload.get("peers", []):
                            h, pt = p["host"], p["port"]
                            if pt != self.network.actual_port:
                                await self.network.connect_to_peer(h, pt)
            except Exception as exc:
                log.debug("Bootstrap error: %s", exc)

            await asyncio.sleep(120)
