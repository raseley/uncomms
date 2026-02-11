"""Curses-based terminal UI for Uncomms."""

from __future__ import annotations

import asyncio
import curses
import queue
import time
from datetime import datetime

from .message import Message
from .server import Server


class ChatUI:
    SIDEBAR_WIDTH = 24

    def __init__(self, node, loop: asyncio.AbstractEventLoop) -> None:
        self.node = node
        self.loop = loop
        self.current_server: str | None = None
        self.current_channel: str = "general"
        self.input_buffer: str = ""
        self.cursor_pos: int = 0
        self.messages: list[Message] = []
        self.scroll_offset: int = 0
        self.running: bool = True
        self.status_msg: str = ""
        self.status_time: float = 0

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, stdscr) -> None:
        self.stdscr = stdscr
        curses.curs_set(1)
        stdscr.timeout(100)  # 100ms poll for UI updates
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)    # headers
        curses.init_pair(2, curses.COLOR_GREEN, -1)    # own messages
        curses.init_pair(3, curses.COLOR_YELLOW, -1)   # timestamps
        curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLUE)  # status bar
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)  # system messages
        curses.init_pair(6, curses.COLOR_RED, -1)      # errors

        # If no server exists, show welcome
        if not self.node.server_mgr.servers:
            self._set_status("Welcome! Use /create <name> to create a server, or /join <id> <host:port> to join one")
        else:
            # Select first server
            self.current_server = next(iter(self.node.server_mgr.servers))
            self._load_messages()

        while self.running:
            self._draw()
            self._process_queue()
            self._handle_input()

    # -- drawing ---------------------------------------------------------------

    def _draw(self) -> None:
        try:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            if h < 6 or w < 40:
                self.stdscr.addstr(0, 0, "Terminal too small")
                self.stdscr.refresh()
                return

            self._draw_sidebar(h, w)
            self._draw_header(h, w)
            self._draw_messages(h, w)
            self._draw_input(h, w)
            self._draw_status(h, w)

            # Position cursor in input area
            input_y = h - 2
            input_x = self.SIDEBAR_WIDTH + 3 + self.cursor_pos
            if input_x < w - 1:
                try:
                    self.stdscr.move(input_y, input_x)
                except curses.error:
                    pass

            self.stdscr.refresh()
        except curses.error:
            pass

    def _draw_sidebar(self, h: int, w: int) -> None:
        sw = self.SIDEBAR_WIDTH

        # Vertical separator
        for y in range(h):
            try:
                self.stdscr.addch(y, sw, curses.ACS_VLINE)
            except curses.error:
                pass

        # Servers header
        self._addstr(0, 1, "SERVERS", curses.color_pair(1) | curses.A_BOLD)

        y = 1
        for sid, srv in self.node.server_mgr.servers.items():
            if y >= h - 8:
                break
            prefix = ">" if sid == self.current_server else " "
            attr = curses.A_BOLD if sid == self.current_server else 0
            self._addstr(y, 1, f"{prefix} {srv.name[:sw-4]}", attr)
            y += 1

            if sid == self.current_server:
                for ch in srv.channels:
                    if y >= h - 8:
                        break
                    ch_prefix = "#"
                    ch_attr = curses.A_BOLD if ch == self.current_channel else 0
                    self._addstr(y, 3, f"{ch_prefix}{ch[:sw-6]}", ch_attr)
                    y += 1

        # Peers section
        y = max(y + 1, h - 10)
        peers = self.node.network.get_peer_info() if self.node.network else []
        self._addstr(y, 1, f"PEERS ({len(peers)})", curses.color_pair(1) | curses.A_BOLD)
        y += 1
        for p in peers:
            if y >= h - 2:
                break
            name = p["display_name"][:10] or "?"
            fp = p["pubkey"][:6]
            self._addstr(y, 2, f"{name} {fp}", curses.color_pair(3))
            y += 1

        # Own identity
        if self.node.identity and y < h - 1:
            y = h - 1
            me = f"You: {self.node.identity.display_name} ({self.node.identity.fingerprint})"
            self._addstr(y, 1, me[:sw-2], curses.color_pair(2))

    def _draw_header(self, h: int, w: int) -> None:
        x_start = self.SIDEBAR_WIDTH + 1
        available = w - x_start - 1

        if self.current_server and self.current_server in self.node.server_mgr.servers:
            srv = self.node.server_mgr.servers[self.current_server]
            header = f" #{self.current_channel} @ {srv.name}"
            port_info = ""
            if self.node.network:
                port_info = f" | port:{self.node.network.actual_port}"
            header += port_info
        else:
            header = " Uncomms - Decentralized Chat"

        header = header[:available]
        self._addstr(0, x_start, header.ljust(available), curses.color_pair(4))

    def _draw_messages(self, h: int, w: int) -> None:
        x_start = self.SIDEBAR_WIDTH + 2
        msg_width = w - x_start - 1
        if msg_width < 10:
            return

        # Message area: rows 1 to h-3
        msg_area_h = h - 3
        if msg_area_h < 1:
            return

        lines: list[tuple[str, int]] = []  # (text, color_pair)
        own_pk = self.node.identity.pubkey_hex if self.node.identity else ""

        for msg in self.messages:
            ts = datetime.fromtimestamp(msg.timestamp).strftime("%H:%M")
            fp = msg.author_pubkey.hex()[:6]
            is_me = msg.author_pubkey.hex() == own_pk
            color = 2 if is_me else 0

            prefix = f"[{ts}] {msg.author_name} ({fp}): "
            text = prefix + msg.content

            # Word wrap
            while len(text) > msg_width:
                lines.append((text[:msg_width], color))
                text = "  " + text[msg_width:]
            lines.append((text, color))

        # Apply scroll — show last messages that fit
        total = len(lines)
        start = max(0, total - msg_area_h - self.scroll_offset)
        end = start + msg_area_h

        for i, (text, color) in enumerate(lines[start:end]):
            y = 1 + i
            attr = curses.color_pair(color) if color else 0
            self._addstr(y, x_start, text[:msg_width], attr)

    def _draw_input(self, h: int, w: int) -> None:
        x_start = self.SIDEBAR_WIDTH + 1
        input_w = w - x_start - 1
        y = h - 2

        # Separator line
        for x in range(x_start, w - 1):
            try:
                self.stdscr.addch(y - 1, x, curses.ACS_HLINE)
            except curses.error:
                pass

        prompt = "> "
        self._addstr(y, x_start, prompt, curses.color_pair(1))
        visible = self.input_buffer[: input_w - len(prompt) - 1]
        self._addstr(y, x_start + len(prompt), visible)

    def _draw_status(self, h: int, w: int) -> None:
        if self.status_msg and time.time() - self.status_time < 5:
            x_start = self.SIDEBAR_WIDTH + 1
            self._addstr(
                h - 1, x_start,
                self.status_msg[: w - x_start - 1],
                curses.color_pair(5),
            )

    def _addstr(self, y: int, x: int, text: str, attr: int = 0) -> None:
        h, w = self.stdscr.getmaxyx()
        if y < 0 or y >= h or x < 0 or x >= w:
            return
        try:
            self.stdscr.addnstr(y, x, text, w - x - 1, attr)
        except curses.error:
            pass

    # -- input handling --------------------------------------------------------

    def _handle_input(self) -> None:
        try:
            key = self.stdscr.getch()
        except curses.error:
            return

        if key == -1:
            return

        if key == curses.KEY_RESIZE:
            return

        if key in (curses.KEY_ENTER, 10, 13):
            self._submit_input()
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if self.input_buffer and self.cursor_pos > 0:
                self.input_buffer = (
                    self.input_buffer[: self.cursor_pos - 1]
                    + self.input_buffer[self.cursor_pos:]
                )
                self.cursor_pos -= 1
        elif key == curses.KEY_LEFT:
            self.cursor_pos = max(0, self.cursor_pos - 1)
        elif key == curses.KEY_RIGHT:
            self.cursor_pos = min(len(self.input_buffer), self.cursor_pos + 1)
        elif key == curses.KEY_UP:
            self.scroll_offset = min(
                self.scroll_offset + 3, max(0, len(self.messages) * 2)
            )
        elif key == curses.KEY_DOWN:
            self.scroll_offset = max(0, self.scroll_offset - 3)
        elif key == curses.KEY_PPAGE:  # Page Up
            self.scroll_offset += 10
        elif key == curses.KEY_NPAGE:  # Page Down
            self.scroll_offset = max(0, self.scroll_offset - 10)
        elif key == 9:  # Tab — cycle channels
            self._cycle_channel()
        elif 32 <= key <= 126:
            ch = chr(key)
            self.input_buffer = (
                self.input_buffer[: self.cursor_pos]
                + ch
                + self.input_buffer[self.cursor_pos:]
            )
            self.cursor_pos += 1

    def _submit_input(self) -> None:
        text = self.input_buffer.strip()
        self.input_buffer = ""
        self.cursor_pos = 0
        self.scroll_offset = 0

        if not text:
            return

        if text.startswith("/"):
            self._handle_command(text)
        elif self.current_server:
            # Send message
            fut = asyncio.run_coroutine_threadsafe(
                self.node.send_message(self.current_server, self.current_channel, text),
                self.loop,
            )
            # Non-blocking — message will appear via UI queue
        else:
            self._set_status("No server selected. Use /create <name> or /join <id> <host:port>")

    def _handle_command(self, text: str) -> None:
        parts = text.split(maxsplit=2)
        cmd = parts[0].lower()

        if cmd == "/quit":
            self.running = False
            return

        if cmd == "/create" and len(parts) >= 2:
            name = parts[1]
            fut = asyncio.run_coroutine_threadsafe(
                self.node.create_server(name), self.loop
            )
            try:
                srv = fut.result(timeout=3)
                self.current_server = srv.id
                self.current_channel = "general"
                self._load_messages()
                self._set_status(f"Created server '{srv.name}' (ID: {srv.id})")
            except Exception as e:
                self._set_status(f"Error: {e}")
            return

        if cmd == "/join" and len(parts) >= 3:
            server_id = parts[1]
            peer_spec = parts[2]
            host, _, port_s = peer_spec.rpartition(":")
            host = host or "127.0.0.1"
            try:
                port = int(port_s)
            except ValueError:
                self._set_status("Invalid port")
                return

            fut = asyncio.run_coroutine_threadsafe(
                self.node.join_server(server_id, host, port), self.loop
            )
            try:
                ok = fut.result(timeout=5)
                if ok:
                    self.current_server = server_id
                    self.current_channel = "general"
                    self._set_status(f"Joined server {server_id[:8]}...")
                    # Wait a moment for sync then reload messages
                    import time as _t
                    _t.sleep(1)
                    self._load_messages()
                else:
                    self._set_status("Failed to connect to peer")
            except Exception as e:
                self._set_status(f"Error: {e}")
            return

        if cmd == "/channel" and len(parts) >= 2:
            ch_name = parts[1].lstrip("#")
            if self.current_server:
                self.node.create_channel(self.current_server, ch_name)
                self.current_channel = ch_name
                self._load_messages()
                self._set_status(f"Switched to #{ch_name}")
            return

        if cmd == "/server" and len(parts) >= 2:
            # Switch to a server by name or id
            target = parts[1].lower()
            for sid, srv in self.node.server_mgr.servers.items():
                if sid.startswith(target) or srv.name.lower() == target:
                    self.current_server = sid
                    self.current_channel = "general"
                    self._load_messages()
                    self._set_status(f"Switched to {srv.name}")
                    return
            self._set_status(f"Server '{target}' not found")
            return

        if cmd == "/peers":
            peers = self.node.network.get_peer_info() if self.node.network else []
            if peers:
                info = ", ".join(f"{p['display_name']}({p['pubkey'][:6]})" for p in peers)
                self._set_status(f"Peers: {info}")
            else:
                self._set_status("No peers connected")
            return

        if cmd == "/id":
            if self.node.identity:
                self._set_status(
                    f"Identity: {self.node.identity.display_name} "
                    f"({self.node.identity.pubkey_hex[:16]}...)"
                )
            return

        if cmd == "/help":
            self._set_status(
                "/create <name> | /join <id> <host:port> | /channel <name> | "
                "/server <name> | /peers | /id | /quit"
            )
            return

        self._set_status(f"Unknown command: {cmd}. Type /help for commands.")

    # -- helpers ---------------------------------------------------------------

    def _load_messages(self) -> None:
        """Load messages for current server/channel from store."""
        if not self.current_server:
            self.messages = []
            return
        fut = asyncio.run_coroutine_threadsafe(
            self.node.store.get_channel_messages(
                self.current_server, self.current_channel
            ),
            self.loop,
        )
        try:
            self.messages = fut.result(timeout=3)
        except Exception:
            self.messages = []

    def _process_queue(self) -> None:
        """Drain the UI queue and apply updates."""
        try:
            while True:
                event, data = self.node.ui_queue.get_nowait()
                if event == "new_message":
                    msg: Message = data
                    if (
                        msg.server_id == self.current_server
                        and msg.channel == self.current_channel
                    ):
                        # Avoid duplicates
                        if not any(m.id == msg.id for m in self.messages):
                            self.messages.append(msg)
                elif event == "server_update":
                    pass  # sidebar redraws automatically
                elif event == "peer_update":
                    pass  # sidebar redraws automatically
        except queue.Empty:
            pass

    def _cycle_channel(self) -> None:
        if not self.current_server:
            return
        srv = self.node.server_mgr.get_server(self.current_server)
        if not srv or not srv.channels:
            return
        try:
            idx = srv.channels.index(self.current_channel)
            idx = (idx + 1) % len(srv.channels)
        except ValueError:
            idx = 0
        self.current_channel = srv.channels[idx]
        self._load_messages()
        self._set_status(f"Switched to #{self.current_channel}")

    def _set_status(self, msg: str) -> None:
        self.status_msg = msg
        self.status_time = time.time()
