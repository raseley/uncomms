"""SQLite persistence layer — append-only message store."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from functools import partial
from pathlib import Path

from .message import Message

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,
    server_id   TEXT NOT NULL,
    channel     TEXT NOT NULL,
    author_pubkey TEXT NOT NULL,
    author_name TEXT NOT NULL,
    content     TEXT NOT NULL,
    timestamp   REAL NOT NULL,
    prev_hash   TEXT NOT NULL,
    signature   TEXT NOT NULL,
    received_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_msg_chan
    ON messages(server_id, channel, timestamp);

CREATE INDEX IF NOT EXISTS idx_msg_prev
    ON messages(prev_hash);

CREATE TABLE IF NOT EXISTS servers (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    created_at    REAL NOT NULL,
    creator_pubkey TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS peers (
    server_id TEXT NOT NULL,
    host      TEXT NOT NULL,
    port      INTEGER NOT NULL,
    pubkey    TEXT,
    last_seen REAL,
    PRIMARY KEY (server_id, host, port)
);
"""


class MessageStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    # -- lifecycle -------------------------------------------------------------

    def open(self) -> None:
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # -- helpers ---------------------------------------------------------------

    async def _run(self, fn, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, partial(fn, *args))

    def _row_to_message(self, row: sqlite3.Row) -> Message:
        return Message(
            id=row["id"],
            server_id=row["server_id"],
            channel=row["channel"],
            author_pubkey=bytes.fromhex(row["author_pubkey"]),
            author_name=row["author_name"],
            content=row["content"],
            timestamp=row["timestamp"],
            prev_hash=row["prev_hash"],
            signature=bytes.fromhex(row["signature"]),
        )

    # -- messages --------------------------------------------------------------

    def _add_message_sync(self, msg: Message) -> bool:
        try:
            self._conn.execute(
                "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    msg.id,
                    msg.server_id,
                    msg.channel,
                    msg.author_pubkey.hex(),
                    msg.author_name,
                    msg.content,
                    msg.timestamp,
                    msg.prev_hash,
                    msg.signature.hex(),
                    time.time(),
                ),
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate

    async def add_message(self, msg: Message) -> bool:
        return await self._run(self._add_message_sync, msg)

    def _get_channel_messages_sync(
        self, server_id: str, channel: str, limit: int = 200
    ) -> list[Message]:
        cur = self._conn.execute(
            "SELECT * FROM messages WHERE server_id=? AND channel=? "
            "ORDER BY timestamp ASC, id ASC LIMIT ?",
            (server_id, channel, limit),
        )
        return [self._row_to_message(r) for r in cur.fetchall()]

    async def get_channel_messages(
        self, server_id: str, channel: str, limit: int = 200
    ) -> list[Message]:
        return await self._run(self._get_channel_messages_sync, server_id, channel, limit)

    def _get_chain_head_sync(self, server_id: str, channel: str) -> str:
        cur = self._conn.execute(
            "SELECT id FROM messages WHERE server_id=? AND channel=? "
            "ORDER BY timestamp DESC, id DESC LIMIT 1",
            (server_id, channel),
        )
        row = cur.fetchone()
        return row["id"] if row else ""

    async def get_chain_head(self, server_id: str, channel: str) -> str:
        return await self._run(self._get_chain_head_sync, server_id, channel)

    def _get_message_sync(self, msg_id: str) -> Message | None:
        cur = self._conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,))
        row = cur.fetchone()
        return self._row_to_message(row) if row else None

    async def get_message(self, msg_id: str) -> Message | None:
        return await self._run(self._get_message_sync, msg_id)

    def _has_message_sync(self, msg_id: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM messages WHERE id=? LIMIT 1", (msg_id,)
        )
        return cur.fetchone() is not None

    async def has_message(self, msg_id: str) -> bool:
        return await self._run(self._has_message_sync, msg_id)

    def _get_messages_after_sync(
        self, server_id: str, channel: str, after_ts: float
    ) -> list[Message]:
        cur = self._conn.execute(
            "SELECT * FROM messages WHERE server_id=? AND channel=? AND timestamp>? "
            "ORDER BY timestamp ASC, id ASC",
            (server_id, channel, after_ts),
        )
        return [self._row_to_message(r) for r in cur.fetchall()]

    async def get_messages_after(
        self, server_id: str, channel: str, after_ts: float
    ) -> list[Message]:
        return await self._run(self._get_messages_after_sync, server_id, channel, after_ts)

    def _get_all_messages_sync(self, server_id: str, channel: str) -> list[Message]:
        cur = self._conn.execute(
            "SELECT * FROM messages WHERE server_id=? AND channel=? "
            "ORDER BY timestamp ASC, id ASC",
            (server_id, channel),
        )
        return [self._row_to_message(r) for r in cur.fetchall()]

    async def get_all_messages(self, server_id: str, channel: str) -> list[Message]:
        return await self._run(self._get_all_messages_sync, server_id, channel)

    # -- servers ---------------------------------------------------------------

    def _save_server_sync(
        self, server_id: str, name: str, created_at: float, creator_pubkey: str
    ) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO servers VALUES (?,?,?,?)",
            (server_id, name, created_at, creator_pubkey),
        )
        self._conn.commit()

    async def save_server(
        self, server_id: str, name: str, created_at: float, creator_pubkey: str
    ) -> None:
        await self._run(self._save_server_sync, server_id, name, created_at, creator_pubkey)

    def _get_servers_sync(self) -> list[dict]:
        cur = self._conn.execute("SELECT * FROM servers")
        return [dict(r) for r in cur.fetchall()]

    async def get_servers(self) -> list[dict]:
        return await self._run(self._get_servers_sync)

    # -- peers -----------------------------------------------------------------

    def _save_peer_sync(
        self, server_id: str, host: str, port: int, pubkey: str | None
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO peers VALUES (?,?,?,?,?)",
            (server_id, host, port, pubkey, time.time()),
        )
        self._conn.commit()

    async def save_peer(
        self, server_id: str, host: str, port: int, pubkey: str | None = None
    ) -> None:
        await self._run(self._save_peer_sync, server_id, host, port, pubkey)

    def _get_peers_sync(self, server_id: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM peers WHERE server_id=?", (server_id,)
        )
        return [dict(r) for r in cur.fetchall()]

    async def get_peers(self, server_id: str) -> list[dict]:
        return await self._run(self._get_peers_sync, server_id)

    # -- channels (derived from messages) --------------------------------------

    def _get_channels_sync(self, server_id: str) -> list[str]:
        cur = self._conn.execute(
            "SELECT DISTINCT channel FROM messages WHERE server_id=? ORDER BY channel",
            (server_id,),
        )
        return [r["channel"] for r in cur.fetchall()]

    async def get_channels(self, server_id: str) -> list[str]:
        return await self._run(self._get_channels_sync, server_id)
