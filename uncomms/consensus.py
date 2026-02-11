"""Chain validation, fork resolution, and censorship detection."""

from __future__ import annotations

import time

from .message import Message, GENESIS_HASH
from .store import MessageStore

MAX_FUTURE_SECONDS = 300  # allow 5 min clock skew


class ChainValidator:
    def __init__(self, store: MessageStore) -> None:
        self.store = store

    async def validate_message(self, msg: Message) -> tuple[bool, str]:
        """Validate a single incoming message.

        Returns (is_valid, error_reason).
        """
        # 1. Message ID matches content hash
        if not msg.verify_id():
            return False, "message id mismatch"

        # 2. Signature is valid
        if not msg.verify_signature():
            return False, "invalid signature"

        # 3. Timestamp not absurdly in the future
        if msg.timestamp > time.time() + MAX_FUTURE_SECONDS:
            return False, "timestamp too far in the future"

        # 4. prev_hash references a known message or is genesis
        if msg.prev_hash != GENESIS_HASH:
            if not await self.store.has_message(msg.prev_hash):
                # We might not have the parent yet — accept optimistically
                # and rely on sync to fill the gap. This prevents deadlocks
                # when messages arrive out of order.
                pass

        return True, ""

    async def validate_chain(self, server_id: str, channel: str) -> list[str]:
        """Walk the chain for a channel, returning any integrity errors."""
        messages = await self.store.get_all_messages(server_id, channel)
        errors: list[str] = []
        known_ids: set[str] = set()

        for msg in messages:
            if not msg.verify_id():
                errors.append(f"msg {msg.id[:8]}: id mismatch")
            if not msg.verify_signature():
                errors.append(f"msg {msg.id[:8]}: bad signature")
            if msg.prev_hash != GENESIS_HASH and msg.prev_hash not in known_ids:
                errors.append(f"msg {msg.id[:8]}: unknown prev_hash {msg.prev_hash[:8]}")
            known_ids.add(msg.id)

        return errors

    @staticmethod
    def resolve_fork(messages: list[Message]) -> list[Message]:
        """Deterministic total ordering for messages that may form a DAG.

        All nodes apply the same rule: sort by (timestamp, message_id).
        """
        return sorted(messages, key=lambda m: (m.timestamp, m.id))

    @staticmethod
    def detect_missing(
        our_ids: set[str], peer_ids: set[str]
    ) -> tuple[set[str], set[str]]:
        """Compare message ID sets.

        Returns (we_need, they_need).
        """
        we_need = peer_ids - our_ids
        they_need = our_ids - peer_ids
        return we_need, they_need
