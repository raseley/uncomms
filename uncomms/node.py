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
                await self._bootstrap_session(bs_host, bs_port)
            except Exception as exc:
                log.debug("Bootstrap session error: %s", exc)
                # Clean up stale bootstrap connection
                self.network._bootstrap_reader = None
                self.network._bootstrap_writer = None

            # Reconnect after disconnect or error
            await asyncio.sleep(10)

    async def _bootstrap_session(self, bs_host: str, bs_port: int) -> None:
        """Maintain a persistent connection to the bootstrap server.

        Handles REGISTER, DISCOVER, and incoming PUNCH_NOTIFY/relay messages.
        """
        from .protocol import Envelope, MsgType, read_envelope, write_envelope

        reader, writer = await asyncio.open_connection(bs_host, bs_port)

        # First message must be REGISTER to establish persistent connection
        sids = list(self.server_mgr.servers.keys())
        first_sid = sids[0] if sids else ""
        reg = Envelope(
            msg_type=MsgType.REGISTER,
            payload={
                "server_id": first_sid,
                "host": self.config.listen_host,
                "port": self.network.actual_port,
            },
            sender_pubkey=self.identity.pubkey_hex,
        )
        await write_envelope(writer, reg)

        # Store the persistent connection on the network object
        self.network._bootstrap_reader = reader
        self.network._bootstrap_writer = writer

        # Register additional server_ids
        for sid in sids[1:]:
            extra_reg = Envelope(
                msg_type=MsgType.REGISTER,
                payload={
                    "server_id": sid,
                    "host": self.config.listen_host,
                    "port": self.network.actual_port,
                },
                sender_pubkey=self.identity.pubkey_hex,
            )
            await write_envelope(writer, extra_reg)

        # Start background reader for incoming bootstrap messages
        read_task = asyncio.ensure_future(
            self._bootstrap_read_loop(reader, bs_host, bs_port)
        )

        # Periodic discover + re-register loop
        try:
            while True:
                for sid in list(self.server_mgr.servers.keys()):
                    # Discover peers over the persistent connection
                    disc = Envelope(
                        msg_type=MsgType.DISCOVER,
                        payload={"server_id": sid},
                        sender_pubkey=self.identity.pubkey_hex,
                    )
                    await write_envelope(writer, disc)

                await asyncio.sleep(120)

                # Re-register (keepalive) for all servers
                for sid in list(self.server_mgr.servers.keys()):
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
        finally:
            read_task.cancel()
            try:
                writer.close()
            except Exception:
                pass
            self.network._bootstrap_reader = None
            self.network._bootstrap_writer = None

    async def _bootstrap_read_loop(
        self,
        reader: asyncio.StreamReader,
        bs_host: str,
        bs_port: int,
    ) -> None:
        """Read messages pushed by the bootstrap server (PUNCH_NOTIFY,
        DISCOVER_RESPONSE, relayed messages)."""
        from .protocol import Envelope, MsgType, read_envelope

        while True:
            env = await read_envelope(reader)
            if env is None:
                break

            if env.msg_type == MsgType.DISCOVER_RESPONSE:
                for p in env.payload.get("peers", []):
                    h, pt = p["host"], p["port"]
                    pk = p.get("pubkey", "")
                    if pt != self.network.actual_port:
                        if pk:
                            await self.network.ensure_reachability(
                                pk, h, pt, bs_host, bs_port
                            )
                        else:
                            await self.network.connect_to_peer(h, pt)

            elif env.msg_type == MsgType.PUNCH_NOTIFY:
                await self.network._handle_punch_notify(env)

            elif env.msg_type == MsgType.NEW_MESSAGE:
                # Relayed message from bootstrap — process like a peer message
                # Create a dummy sender for the handler
                from .network import PeerConnection
                import io
                dummy = PeerConnection(
                    reader=asyncio.StreamReader(),
                    writer=None,  # type: ignore[arg-type]
                    pubkey=env.sender_pubkey,
                )
                await self.network._handle_new_message(env, dummy)

            elif env.msg_type == MsgType.SYNC_RESPONSE:
                from .network import PeerConnection
                dummy = PeerConnection(
                    reader=asyncio.StreamReader(),
                    writer=None,  # type: ignore[arg-type]
                    pubkey=env.sender_pubkey,
                )
                await self.network._handle_sync_response(env, dummy)
