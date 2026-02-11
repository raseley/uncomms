"""Async TCP mesh networking with gossip and sync."""

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
            }
            for p in self.peers.values()
        ]
