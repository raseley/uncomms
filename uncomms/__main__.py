"""Entry point: python -m uncomms"""

from __future__ import annotations

import asyncio
import logging
import threading

from .bootstrap import BootstrapServer
from .config import parse_args
from .node import Node
from .ui import ChatUI


def main() -> None:
    cfg = parse_args()

    logging.basicConfig(
        level=logging.DEBUG,
        filename=str(cfg.data_dir / "uncomms.log"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    cfg.ensure_dirs()

    if cfg.serve_bootstrap:
        port = cfg.listen_port or 9999
        print(f"Starting bootstrap server on port {port}...")
        asyncio.run(BootstrapServer(port=port).start())
        return

    # Prompt for display name if not set and no identity file
    if not cfg.display_name and not cfg.identity_path.exists():
        try:
            name = input("Choose a display name: ").strip()
        except (EOFError, KeyboardInterrupt):
            name = ""
        cfg.display_name = name or "anon"

    node = Node(cfg)

    # Start asyncio event loop in a background thread
    loop = asyncio.new_event_loop()

    async def _start_node():
        await node.start()
        # Keep running
        while True:
            await asyncio.sleep(1)

    def _run_loop():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_start_node())
        except asyncio.CancelledError:
            pass

    bg = threading.Thread(target=_run_loop, daemon=True)
    bg.start()

    # Wait a moment for the node to initialize
    import time
    time.sleep(0.5)

    # Launch curses UI in the main thread
    ui = ChatUI(node, loop)
    try:
        ui.run()
    except KeyboardInterrupt:
        pass
    finally:
        # Shutdown
        fut = asyncio.run_coroutine_threadsafe(node.shutdown(), loop)
        try:
            fut.result(timeout=3)
        except Exception:
            pass
        loop.call_soon_threadsafe(loop.stop)


if __name__ == "__main__":
    main()
