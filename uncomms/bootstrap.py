"""Lightweight bootstrap/rendezvous server for peer discovery.

Maintains persistent connections to registered nodes for NAT traversal:
- Peer discovery (REGISTER / DISCOVER)
- Hole-punch coordination (PUNCH_REQUEST → PUNCH_NOTIFY)
- Last-resort relay for nodes that cannot connect directly
"""

from __future__ import annotations

import asyncio
import logging
import time

from .protocol import Envelope, MsgType, read_envelope, write_envelope

log = logging.getLogger(__name__)

EXPIRY_SECONDS = 300  # 5 minutes


class _ConnectedNode:
    """A persistently connected node."""

    __slots__ = ("reader", "writer", "pubkey", "server_ids", "public_addr", "last_seen")

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        pubkey: str,
        public_addr: tuple[str, int],
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.pubkey = pubkey
        self.server_ids: list[str] = []
        self.public_addr = public_addr
        self.last_seen = time.time()


class BootstrapServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 9999) -> None:
        self.host = host
        self.port = port
        # Legacy registry for one-shot REGISTER/DISCOVER (backward compat)
        # server_id -> {(host, port): timestamp}
        self.registry: dict[str, dict[tuple[str, int], float]] = {}
        # Persistent connections keyed by pubkey
        self.connected_nodes: dict[str, _ConnectedNode] = {}

    async def start(self) -> None:
        server = await asyncio.start_server(self._handle, self.host, self.port)
        addr = server.sockets[0].getsockname()
        log.info("Bootstrap server listening on %s:%d", addr[0], addr[1])
        print(f"Bootstrap server listening on {addr[0]}:{addr[1]}")
        async with server:
            await server.serve_forever()

    # -- connection handler ----------------------------------------------------

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        node: _ConnectedNode | None = None
        try:
            env = await read_envelope(reader)
            if env is None:
                return

            if env.msg_type == MsgType.REGISTER:
                node = await self._handle_register(env, reader, writer)
                if node is None:
                    return
                # Stay connected — read further messages from this node
                await self._persistent_loop(node)
            elif env.msg_type == MsgType.DISCOVER:
                # One-shot discover (backward compatible)
                await self._discover(env, writer)
            else:
                return
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            log.debug("Bootstrap handler error: %s", exc)
        finally:
            if node and node.pubkey in self.connected_nodes:
                del self.connected_nodes[node.pubkey]
                log.debug("Node disconnected: %s", node.pubkey[:8])
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_register(
        self,
        env: Envelope,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> _ConnectedNode | None:
        """Process a REGISTER and set up a persistent connection."""
        sid = env.payload.get("server_id", "")
        host = env.payload.get("host", "")
        port = env.payload.get("port", 0)
        pubkey = env.sender_pubkey

        if not sid or not port or not pubkey:
            return None

        # Observe public address from the TCP connection
        peername = writer.get_extra_info("peername")
        public_ip = peername[0] if peername else host
        public_port = port  # reported listen port

        # Update legacy registry
        if sid not in self.registry:
            self.registry[sid] = {}
        self.registry[sid][(host, port)] = time.time()
        self._expire(sid)

        # Close previous connection from same pubkey if any
        old = self.connected_nodes.get(pubkey)
        if old is not None:
            try:
                old.writer.close()
            except Exception:
                pass

        node = _ConnectedNode(reader, writer, pubkey, (public_ip, public_port))
        node.server_ids = [sid]
        self.connected_nodes[pubkey] = node

        log.debug(
            "Registered %s (pubkey %s) for server %s, public %s:%d",
            host, pubkey[:8], sid[:8], public_ip, public_port,
        )
        return node

    async def _persistent_loop(self, node: _ConnectedNode) -> None:
        """Read messages from a persistently connected node."""
        while True:
            env = await read_envelope(node.reader)
            if env is None:
                break
            node.last_seen = time.time()

            if env.msg_type == MsgType.REGISTER:
                # Re-register (additional server_id or keepalive)
                sid = env.payload.get("server_id", "")
                host = env.payload.get("host", "")
                port = env.payload.get("port", 0)
                if sid:
                    if sid not in node.server_ids:
                        node.server_ids.append(sid)
                    if sid not in self.registry:
                        self.registry[sid] = {}
                    self.registry[sid][(host, port)] = time.time()
                    self._expire(sid)

            elif env.msg_type == MsgType.DISCOVER:
                await self._discover(env, node.writer)

            elif env.msg_type == MsgType.PUNCH_REQUEST:
                await self._handle_punch_request(env, node)

            elif env.msg_type in (
                MsgType.NEW_MESSAGE,
                MsgType.SYNC_REQUEST,
                MsgType.SYNC_RESPONSE,
            ):
                # Layer 3: bootstrap relay — forward to other connected
                # nodes in the same server(s)
                await self._relay_through_bootstrap(env, node)

    # -- punch coordination ----------------------------------------------------

    async def _handle_punch_request(
        self, env: Envelope, requester: _ConnectedNode
    ) -> None:
        target_pubkey = env.payload.get("target_pubkey", "")
        target = self.connected_nodes.get(target_pubkey)
        if target is None:
            log.debug("Punch target %s not connected", target_pubkey[:8])
            return

        # Send PUNCH_NOTIFY to the target with requester's public address
        notify = Envelope(
            msg_type=MsgType.PUNCH_NOTIFY,
            payload={
                "from_pubkey": requester.pubkey,
                "public_addr": {
                    "host": requester.public_addr[0],
                    "port": requester.public_addr[1],
                },
            },
        )
        try:
            await write_envelope(target.writer, notify)
        except Exception:
            log.debug("Failed to send punch notify to %s", target_pubkey[:8])

    # -- bootstrap relay (layer 3) --------------------------------------------

    async def _relay_through_bootstrap(
        self, env: Envelope, sender: _ConnectedNode
    ) -> None:
        """Forward a message to all other connected nodes sharing a server."""
        sender_servers = set(sender.server_ids)
        for pubkey, node in list(self.connected_nodes.items()):
            if pubkey == sender.pubkey:
                continue
            # Only forward if they share at least one server_id
            if sender_servers & set(node.server_ids):
                try:
                    await write_envelope(node.writer, env)
                except Exception:
                    pass

    # -- one-shot discover (backward compatible) -------------------------------

    async def _discover(self, env: Envelope, writer: asyncio.StreamWriter) -> None:
        sid = env.payload.get("server_id", "")
        self._expire(sid)

        entries = self.registry.get(sid, {})
        peers: list[dict] = []
        for (h, p) in entries.keys():
            # Include pubkey if we have a connected node at this address
            pk = ""
            for node in self.connected_nodes.values():
                if node.public_addr == (h, p) or (h, p) in [
                    (node.public_addr[0], node.public_addr[1])
                ]:
                    pk = node.pubkey
                    break
            entry: dict = {"host": h, "port": p}
            if pk:
                entry["pubkey"] = pk
            peers.append(entry)

        resp = Envelope(
            msg_type=MsgType.DISCOVER_RESPONSE,
            payload={"server_id": sid, "peers": peers},
        )
        await write_envelope(writer, resp)

    # -- expiry ----------------------------------------------------------------

    def _expire(self, sid: str) -> None:
        now = time.time()
        if sid in self.registry:
            self.registry[sid] = {
                k: v
                for k, v in self.registry[sid].items()
                if now - v < EXPIRY_SECONDS
            }
