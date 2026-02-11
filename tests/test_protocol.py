"""Tests for wire protocol."""

import asyncio
import struct

from uncomms.protocol import Envelope, MsgType, read_envelope, write_envelope


def test_envelope_roundtrip():
    env = Envelope(
        msg_type=MsgType.NEW_MESSAGE,
        payload={"content": "hello", "id": "abc123"},
        sender_pubkey="deadbeef",
    )
    raw = env.to_bytes()

    # Parse length prefix
    length = struct.unpack(">I", raw[:4])[0]
    assert length == len(raw) - 4

    # Parse envelope
    restored = Envelope.from_json(raw[4:])
    assert restored.msg_type == MsgType.NEW_MESSAGE
    assert restored.payload["content"] == "hello"
    assert restored.sender_pubkey == "deadbeef"


def test_read_write_envelope():
    async def _test():
        reader_r, writer_w = await asyncio.open_connection("127.0.0.1", server_port)

        env = Envelope(
            msg_type=MsgType.HELLO,
            payload={"display_name": "Test"},
            sender_pubkey="aabb",
        )
        await write_envelope(writer_w, env)

        # Read from the server side
        received = await read_envelope(server_reader[0])
        assert received is not None
        assert received.msg_type == MsgType.HELLO
        assert received.payload["display_name"] == "Test"

        writer_w.close()

    server_reader = [None]

    async def _handler(reader, writer):
        server_reader[0] = reader

    async def _run():
        nonlocal server_port
        server = await asyncio.start_server(_handler, "127.0.0.1", 0)
        server_port = server.sockets[0].getsockname()[1]
        async with server:
            await _test()

    server_port = 0
    asyncio.get_event_loop().run_until_complete(_run())


def test_envelope_types():
    for mt in MsgType:
        env = Envelope(msg_type=mt, payload={})
        raw = env.to_bytes()
        restored = Envelope.from_json(raw[4:])
        assert restored.msg_type == mt
