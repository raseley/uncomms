"""Async TCP mesh networking with gossip, sync, and NAT traversal."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from .identity import Identity
from .message import Message
from .protocol import (
    Envelope,
    MsgType,
    read_envelope,
    write_envelope,
)
from .store import MessageStore

log = logging.getLogger(__name__)

# NAT traversal constants
PUNCH_ATTEMPTS = 4
PUNCH_INTERVAL = 0.5  # seconds between attempts
PUNCH_TIMEOUT = 3.0   # total timeout for hole-punch sequence


@dataclass
class PeerConnection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    pubkey: str = ""  # hex, set after handshake
    display_name: str = ""
    host: str = ""
    port: int = 0  # their listening port
    server_ids: list[str] = field(default_factory=list)
    connected: bool = True

    async def send(self, envelope: Envelope) -> bool:
        if not self.connected:
            return False
        try:
            await write_envelope(self.writer, envelope)
            return True
        except Exception:
            self.connected = False
            return False

    def close(self) -> None:
        self.connected = False
        try:
            self.writer.close()
        except Exception:
            pass


class PeerNetwork:
    def __init__(
        self,
        identity: Identity,
        host: str,
        port: int,
        store: MessageStore,
        on_message=None,
        on_peer_update=None,
    ) -> None:
        self.identity = identity
        self.host = host
        self.port = port
        self.store = store
        self.on_message = on_message  # async callback(Message)
        self.on_peer_update = on_peer_update  # async callback()
        self.peers: dict[str, PeerConnection] = {}  # pubkey_hex -> connection
        self._server: asyncio.Server | None = None
        self._seen_ids: set[str] = set()  # message IDs we've already processed
        self.actual_port: int = 0  # filled after start()
        self.server_ids: list[str] = []  # servers we participate in

        # NAT traversal state
        self._relay_only_peers: set[str] = set()  # pubkeys reachable only via relay
        self._bootstrap_reader: asyncio.StreamReader | None = None
        self._bootstrap_writer: asyncio.StreamWriter | None = None
        self._punch_events: dict[str, asyncio.Event] = {}  # pubkey -> event

    # -- lifecycle -------------------------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._on_inbound, self.host, self.port
        )
        addr = self._server.sockets[0].getsockname()
        self.actual_port = addr[1]
        log.info("Listening on %s:%d", addr[0], self.actual_port)

    async def stop(self) -> None:
        for peer in list(self.peers.values()):
            peer.close()
        self.peers.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        # Close bootstrap connection
        if self._bootstrap_writer:
            try:
                self._bootstrap_writer.close()
            except Exception:
                pass
            self._bootstrap_writer = None
            self._bootstrap_reader = None

    # -- outbound connections --------------------------------------------------

    async def connect_to_peer(self, host: str, port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0
            )
        except Exception as exc:
            log.debug("Failed to connect to %s:%d: %s", host, port, exc)
            return False

        # Send HELLO
        hello = Envelope(
            msg_type=MsgType.HELLO,
            payload={
                "display_name": self.identity.display_name,
                "listen_port": self.actual_port,
                "server_ids": self.server_ids,
            },
            sender_pubkey=self.identity.pubkey_hex,
        )
        try:
            await write_envelope(writer, hello)
        except Exception:
            writer.close()
            return False

        # Read HELLO_ACK
        ack = await read_envelope(reader)
        if ack is None or ack.msg_type != MsgType.HELLO_ACK:
            writer.close()
            return False

        peer = PeerConnection(
            reader=reader,
            writer=writer,
            pubkey=ack.sender_pubkey,
            display_name=ack.payload.get("display_name", ""),
            host=host,
            port=port,
            server_ids=ack.payload.get("server_ids", []),
        )

        if peer.pubkey == self.identity.pubkey_hex:
            peer.close()
            return False

        if peer.pubkey in self.peers:
            peer.close()
            return True  # already connected

        self.peers[peer.pubkey] = peer
        # No longer relay-only if we got a direct connection
        self._relay_only_peers.discard(peer.pubkey)
        log.info("Connected to %s (%s)", peer.display_name, peer.pubkey[:8])

        if self.on_peer_update:
            asyncio.ensure_future(self.on_peer_update())

        # Handle incoming peer list
        if "peers" in ack.payload:
            asyncio.ensure_future(self._connect_new_peers(ack.payload["peers"]))

        # Start reading from this peer
        asyncio.ensure_future(self._read_loop(peer))

        # Sync message history
        asyncio.ensure_future(self._sync_with_peer(peer))
        return True

    # -- inbound connections ---------------------------------------------------

    async def _on_inbound(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        env = await read_envelope(reader)
        if env is None or env.msg_type != MsgType.HELLO:
            writer.close()
            return

        peer_pubkey = env.sender_pubkey
        if peer_pubkey == self.identity.pubkey_hex:
            writer.close()
            return

        peer_addr = writer.get_extra_info("peername")
        peer = PeerConnection(
            reader=reader,
            writer=writer,
            pubkey=peer_pubkey,
            display_name=env.payload.get("display_name", ""),
            host=peer_addr[0] if peer_addr else "",
            port=env.payload.get("listen_port", 0),
            server_ids=env.payload.get("server_ids", []),
        )

        # Send HELLO_ACK with our peer list
        known = [
            {"host": p.host, "port": p.port, "pubkey": p.pubkey}
            for p in self.peers.values()
            if p.connected and p.pubkey != peer_pubkey
        ]
        ack = Envelope(
            msg_type=MsgType.HELLO_ACK,
            payload={
                "display_name": self.identity.display_name,
                "listen_port": self.actual_port,
                "server_ids": self.server_ids,
                "peers": known,
            },
            sender_pubkey=self.identity.pubkey_hex,
        )
        try:
            await write_envelope(writer, ack)
        except Exception:
            writer.close()
            return

        if peer.pubkey in self.peers:
            # Already connected — close duplicate
            writer.close()
            return

        self.peers[peer.pubkey] = peer
        self._relay_only_peers.discard(peer.pubkey)
        log.info("Inbound peer: %s (%s)", peer.display_name, peer.pubkey[:8])

        if self.on_peer_update:
            asyncio.ensure_future(self.on_peer_update())

        asyncio.ensure_future(self._read_loop(peer))
        asyncio.ensure_future(self._sync_with_peer(peer))

    # -- message reading loop --------------------------------------------------

    async def _read_loop(self, peer: PeerConnection) -> None:
        while peer.connected:
            env = await read_envelope(peer.reader)
            if env is None:
                break
            try:
                await self._handle_envelope(env, peer)
            except Exception as exc:
                log.debug("Error handling envelope from %s: %s", peer.pubkey[:8], exc)

        # Peer disconnected
        peer.connected = False
        self.peers.pop(peer.pubkey, None)
        log.info("Peer disconnected: %s (%s)", peer.display_name, peer.pubkey[:8])
        if self.on_peer_update:
            asyncio.ensure_future(self.on_peer_update())

    async def _handle_envelope(self, env: Envelope, sender: PeerConnection) -> None:
        if env.msg_type == MsgType.NEW_MESSAGE:
            await self._handle_new_message(env, sender)
        elif env.msg_type == MsgType.SYNC_REQUEST:
            await self._handle_sync_request(env, sender)
        elif env.msg_type == MsgType.SYNC_RESPONSE:
            await self._handle_sync_response(env, sender)
        elif env.msg_type == MsgType.PEER_LIST:
            asyncio.ensure_future(self._connect_new_peers(env.payload.get("peers", [])))
        elif env.msg_type == MsgType.SERVER_INFO:
            await self._handle_server_info(env, sender)
        elif env.msg_type == MsgType.RELAY:
            await self._handle_relay(env, sender)

    # -- gossip ----------------------------------------------------------------

    async def _handle_new_message(self, env: Envelope, sender: PeerConnection) -> None:
        msg = Message.from_dict(env.payload)

        if msg.id in self._seen_ids:
            return
        self._seen_ids.add(msg.id)

        # Validate
        if not msg.verify_id() or not msg.verify_signature():
            log.warning("Rejected invalid message %s", msg.id[:8])
            return

        # Store
        is_new = await self.store.add_message(msg)
        if not is_new:
            return

        # Notify UI
        if self.on_message:
            await self.on_message(msg)

        # Re-gossip to all peers except sender
        await self._broadcast(env, exclude=sender.pubkey)

    async def gossip_message(self, msg: Message) -> None:
        """Broadcast a locally-created message to all peers."""
        self._seen_ids.add(msg.id)
        env = Envelope(
            msg_type=MsgType.NEW_MESSAGE,
            payload=msg.to_dict(),
            sender_pubkey=self.identity.pubkey_hex,
        )
        await self._broadcast(env)

        # Also send through bootstrap relay for relay-only peers
        if self._relay_only_peers and self._bootstrap_writer:
            try:
                await write_envelope(self._bootstrap_writer, env)
            except Exception:
                log.debug("Failed to relay message through bootstrap")

    async def _broadcast(self, env: Envelope, exclude: str = "") -> None:
        for pk, peer in list(self.peers.items()):
            if pk == exclude or not peer.connected:
                continue
            await peer.send(env)

    # -- sync ------------------------------------------------------------------

    async def _sync_with_peer(self, peer: PeerConnection) -> None:
        """Request full history from a peer for all shared servers."""
        for sid in self.server_ids:
            if sid in peer.server_ids or not peer.server_ids:
                env = Envelope(
                    msg_type=MsgType.SYNC_REQUEST,
                    payload={"server_id": sid, "since_ts": 0},
                    sender_pubkey=self.identity.pubkey_hex,
                )
                await peer.send(env)

    async def _handle_sync_request(self, env: Envelope, sender: PeerConnection) -> None:
        server_id = env.payload.get("server_id", "")
        since_ts = env.payload.get("since_ts", 0)
        channels = await self.store.get_channels(server_id)

        all_msgs: list[dict] = []
        for ch in channels:
            msgs = await self.store.get_messages_after(server_id, ch, since_ts)
            all_msgs.extend(m.to_dict() for m in msgs)

        # Also include messages with since_ts=0 (full sync)
        if since_ts == 0 and not channels:
            # No messages yet — send empty response
            pass

        resp = Envelope(
            msg_type=MsgType.SYNC_RESPONSE,
            payload={"server_id": server_id, "messages": all_msgs},
            sender_pubkey=self.identity.pubkey_hex,
        )
        await sender.send(resp)

        # Also send server info
        servers = await self.store.get_servers()
        for s in servers:
            if s["id"] == server_id:
                info = Envelope(
                    msg_type=MsgType.SERVER_INFO,
                    payload=s,
                    sender_pubkey=self.identity.pubkey_hex,
                )
                await sender.send(info)

    async def _handle_sync_response(self, env: Envelope, sender: PeerConnection) -> None:
        messages = env.payload.get("messages", [])
        for md in messages:
            msg = Message.from_dict(md)
            if msg.id in self._seen_ids:
                continue
            self._seen_ids.add(msg.id)
            if not msg.verify_id() or not msg.verify_signature():
                continue
            is_new = await self.store.add_message(msg)
            if is_new and self.on_message:
                await self.on_message(msg)

    async def _handle_server_info(self, env: Envelope, sender: PeerConnection) -> None:
        p = env.payload
        await self.store.save_server(
            p["id"], p["name"], p["created_at"], p["creator_pubkey"]
        )
        sid = p["id"]
        if sid not in self.server_ids:
            self.server_ids.append(sid)

    # -- Layer 1: TCP hole punching --------------------------------------------

    async def _attempt_hole_punch(
        self, target_pubkey: str, bs_host: str, bs_port: int
    ) -> bool:
        """Request the bootstrap server to coordinate a hole punch."""
        if not self._bootstrap_writer:
            return False

        # Send PUNCH_REQUEST through persistent bootstrap connection
        req = Envelope(
            msg_type=MsgType.PUNCH_REQUEST,
            payload={"target_pubkey": target_pubkey},
            sender_pubkey=self.identity.pubkey_hex,
        )
        try:
            await write_envelope(self._bootstrap_writer, req)
        except Exception:
            return False

        # Wait for the PUNCH_NOTIFY to arrive (handled by bootstrap read loop)
        # and for the resulting connection attempt to succeed
        event = asyncio.Event()
        self._punch_events[target_pubkey] = event
        try:
            await asyncio.wait_for(event.wait(), timeout=PUNCH_TIMEOUT)
            return target_pubkey in self.peers
        except asyncio.TimeoutError:
            return False
        finally:
            self._punch_events.pop(target_pubkey, None)

    async def _handle_punch_notify(self, env: Envelope) -> None:
        """Handle PUNCH_NOTIFY from bootstrap: try to connect to the peer."""
        from_pubkey = env.payload.get("from_pubkey", "")
        addr = env.payload.get("public_addr", {})
        host = addr.get("host", "")
        port = addr.get("port", 0)

        if not host or not port or from_pubkey in self.peers:
            # Already connected or bad data — signal success
            event = self._punch_events.get(from_pubkey)
            if event:
                event.set()
            return

        log.debug("Punch notify: attempting %d connections to %s:%d", PUNCH_ATTEMPTS, host, port)

        # Make multiple rapid connection attempts (simultaneous open)
        tasks = []
        for i in range(PUNCH_ATTEMPTS):
            tasks.append(self._punch_connect(host, port, delay=i * PUNCH_INTERVAL))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        success = any(r is True for r in results)

        if success:
            log.info("Hole punch to %s succeeded", from_pubkey[:8])
        else:
            log.debug("Hole punch to %s:%d failed", host, port)

        # Signal any waiting _attempt_hole_punch call
        event = self._punch_events.get(from_pubkey)
        if event:
            event.set()

    async def _punch_connect(self, host: str, port: int, delay: float = 0) -> bool:
        """Single hole-punch connection attempt with optional delay."""
        if delay > 0:
            await asyncio.sleep(delay)
        return await self.connect_to_peer(host, port)

    # -- Layer 2: Relay through peers ------------------------------------------

    async def send_via_relay(self, target_pubkey: str, envelope: Envelope) -> bool:
        """Try to reach target through any connected peer that knows them."""
        relay_env = Envelope(
            msg_type=MsgType.RELAY,
            payload={
                "target": target_pubkey,
                "inner": {
                    "type": envelope.msg_type.value,
                    "payload": envelope.payload,
                    "sender": envelope.sender_pubkey,
                },
            },
            sender_pubkey=self.identity.pubkey_hex,
        )
        for peer in self.peers.values():
            if peer.connected:
                await peer.send(relay_env)
                return True
        return False

    async def _handle_relay(self, env: Envelope, sender: PeerConnection) -> None:
        """Forward a relayed envelope to its target if we're connected to them."""
        target_pubkey = env.payload.get("target", "")
        inner_data = env.payload.get("inner", {})

        if not target_pubkey or not inner_data:
            return

        # If we are the target, process the inner envelope directly
        if target_pubkey == self.identity.pubkey_hex:
            try:
                inner_env = Envelope(
                    msg_type=MsgType(inner_data["type"]),
                    payload=inner_data.get("payload", {}),
                    sender_pubkey=inner_data.get("sender", ""),
                )
                await self._handle_envelope(inner_env, sender)
            except (KeyError, ValueError):
                log.debug("Invalid inner envelope in relay")
            return

        # Otherwise forward to target if directly connected (single-hop only)
        target_peer = self.peers.get(target_pubkey)
        if target_peer and target_peer.connected:
            try:
                inner_env = Envelope(
                    msg_type=MsgType(inner_data["type"]),
                    payload=inner_data.get("payload", {}),
                    sender_pubkey=inner_data.get("sender", ""),
                )
                await target_peer.send(inner_env)
            except (KeyError, ValueError):
                log.debug("Invalid inner envelope in relay")
        else:
            log.debug("Relay target %s not directly connected, dropping", target_pubkey[:8])

    # -- Layer 3: Bootstrap relay helpers --------------------------------------

    async def send_via_bootstrap(self, envelope: Envelope) -> bool:
        """Send an envelope through the bootstrap server's relay."""
        if not self._bootstrap_writer:
            return False
        try:
            await write_envelope(self._bootstrap_writer, envelope)
            return True
        except Exception:
            log.debug("Failed to send via bootstrap relay")
            return False

    # -- Combined reachability -------------------------------------------------

    async def ensure_reachability(
        self,
        target_pubkey: str,
        hint_host: str,
        hint_port: int,
        bs_host: str = "",
        bs_port: int = 0,
    ) -> bool:
        """Try to reach a peer through the three-layer NAT traversal strategy.

        Layer 1: Direct TCP connect
        Layer 2: Hole punch via bootstrap
        Layer 3 & 4: Relay (implicit through gossip and bootstrap forwarding)
        """
        # Already connected?
        if target_pubkey in self.peers:
            return True

        # Layer 1: direct TCP connect
        if hint_host and hint_port:
            if await self.connect_to_peer(hint_host, hint_port):
                return True

        # Layer 2: hole punch via bootstrap
        if bs_host and bs_port and self._bootstrap_writer:
            if await self._attempt_hole_punch(target_pubkey, bs_host, bs_port):
                return True

        # Layer 3 & 4: relay is implicit — gossip and bootstrap forwarding
        # handle it. Mark this peer as "relay-only".
        self._relay_only_peers.add(target_pubkey)
        log.info(
            "Peer %s marked as relay-only (no direct connection)",
            target_pubkey[:8],
        )
        return True  # reachable, just not directly

    # -- peer discovery --------------------------------------------------------

    async def _connect_new_peers(self, peer_list: list[dict]) -> None:
        for info in peer_list:
            pk = info.get("pubkey", "")
            if pk == self.identity.pubkey_hex or pk in self.peers:
                continue
            host = info.get("host", "")
            port = info.get("port", 0)
            if host and port:
                await self.connect_to_peer(host, port)

    def get_peer_info(self) -> list[dict]:
        return [
            {
                "pubkey": p.pubkey,
                "display_name": p.display_name,
                "host": p.host,
                "port": p.port,
                "connected": p.connected,
                "relay_only": p.pubkey in self._relay_only_peers,
            }
            for p in self.peers.values()
        ]
