"""Configuration for an Uncomms node."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    data_dir: Path = field(default_factory=lambda: Path.home() / ".uncomms")
    listen_host: str = "0.0.0.0"
    listen_port: int = 0  # 0 = OS auto-assign
    bootstrap: str | None = None  # host:port of bootstrap node
    initial_peers: list[tuple[str, int]] = field(default_factory=list)
    display_name: str | None = None
    serve_bootstrap: bool = False

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def identity_path(self) -> Path:
        return self.data_dir / "identity.json"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "messages.db"


def parse_args(argv: list[str] | None = None) -> Config:
    p = argparse.ArgumentParser(
        prog="uncomms",
        description="Uncomms \u2014 decentralized, censorship-resistant chat",
    )
    p.add_argument("--port", type=int, default=0, help="Listen port (0=auto)")
    p.add_argument("--name", type=str, help="Display name")
    p.add_argument("--bootstrap", type=str, help="Bootstrap node host:port")
    p.add_argument(
        "--peer", type=str, action="append", default=[], help="Direct peer host:port"
    )
    p.add_argument(
        "--serve-bootstrap", action="store_true", help="Run as bootstrap node only"
    )
    p.add_argument("--data-dir", type=str, default=None)
    args = p.parse_args(argv)

    peers: list[tuple[str, int]] = []
    for spec in args.peer:
        host, _, port_s = spec.rpartition(":")
        peers.append((host or "127.0.0.1", int(port_s)))

    cfg = Config(
        listen_port=args.port,
        display_name=args.name,
        bootstrap=args.bootstrap,
        initial_peers=peers,
        serve_bootstrap=args.serve_bootstrap,
    )
    if args.data_dir:
        cfg.data_dir = Path(args.data_dir)
    return cfg
