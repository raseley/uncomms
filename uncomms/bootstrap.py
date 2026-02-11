"""Lightweight bootstrap/rendezvous server for peer discovery.

Stores nothing permanently — keeps an in-memory map of
server_id -> [(host, port, timestamp)] with automatic expiry.
"""

from __future__ import annotations

import asyncio
import logging
import time

from .protocol import Envelope, MsgType, read_envelope, write_envelope

log = logging.getLogger(__name__)

EXPIRY_SECONDS = 300  # 5 minutes


class BootstrapServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 9999) -> None:
        self.host = host
        self.port = port
        # server_id -> {(host, port): timestamp}
        self.registry: dict[str, dict[tuple[str, int], float]] = {}

    async def start(self) -> None:
        server = await asyncio.start_server(self._handle, self.host, self.port)
        addr = server.sockets[0].getsockname()
        log.info("Bootstrap server listening on %s:%d", addr[0], addr[1])
        print(f"Bootstrap server listening on {addr[0]}:{addr[1]}")
        async with server:
            await server.serve_forever()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            env = await read_envelope(reader)
            if env is None:
                return

            if env.msg_type == MsgType.REGISTER:
                self._register(env)
            elif env.msg_type == MsgType.DISCOVER:
                await self._discover(env, writer)
        except Exception as exc:
            log.debug("Bootstrap handler error: %s", exc)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _register(self, env: Envelope) -> None:
        sid = env.payload.get("server_id", "")
        host = env.payload.get("host", "")
        port = env.payload.get("port", 0)
        if not sid or not host or not port:
            return

        if sid not in self.registry:
            self.registry[sid] = {}
        self.registry[sid][(host, port)] = time.time()
        self._expire(sid)
        log.debug("Registered %s:%d for server %s", host, port, sid[:8])

    async def _discover(self, env: Envelope, writer: asyncio.StreamWriter) -> None:
        sid = env.payload.get("server_id", "")
        self._expire(sid)

        entries = self.registry.get(sid, {})
        peers = [{"host": h, "port": p} for (h, p) in entries.keys()]

        resp = Envelope(
            msg_type=MsgType.DISCOVER_RESPONSE,
            payload={"server_id": sid, "peers": peers},
        )
        await write_envelope(writer, resp)

    def _expire(self, sid: str) -> None:
        now = time.time()
        if sid in self.registry:
            self.registry[sid] = {
                k: v
                for k, v in self.registry[sid].items()
                if now - v < EXPIRY_SECONDS
            }
