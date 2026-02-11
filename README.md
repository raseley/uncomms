# Uncomms

Decentralized, censorship-resistant chat. A minimalist Discord clone where each server is a peer-to-peer mesh of its members — no central authority, no single point of control.

## How it works

Every participant runs a node. Nodes connect directly to each other over TCP, forming a mesh network. Messages propagate via gossip (every node rebroadcasts to all its peers), and are stored in a cryptographic hashchain — an append-only log where each message references the SHA-256 hash of the previous one.

This makes censorship, tampering, and omission **detectable by every participant**:

- **Tamper evidence** — Altering any message breaks the hashchain from that point forward. Every peer can detect this.
- **Omission detection** — During sync, nodes compare histories. Missing messages are fetched from any peer that has them. One honest node is enough.
- **Signature non-repudiation** — Every message is Ed25519-signed. Authorship is unforgeable and undeniable.
- **No single point of control** — There is no admin who can delete messages. All nodes hold the full history. There is no server to shut down.
- **Gossip routing** — A censoring node can refuse to relay, but messages propagate through every other path in the mesh.

## Quick start

```bash
pip install PyNaCl

# Terminal 1 — Alice starts a node
python -m uncomms --port 8001 --name Alice

# Terminal 2 — Bob connects to Alice
python -m uncomms --port 8002 --name Bob --peer localhost:8001

# Terminal 3 — Charlie connects to Alice
python -m uncomms --port 8003 --name Charlie --peer localhost:8001
```

Alice creates a server with `/create myserver`. Bob and Charlie join with `/join <server_id> localhost:8001` (the server ID is shown in Alice's status bar after creation). Messages are typed directly into the input bar.

## UI

```
┌──────────────┬───────────────────────────────────────┐
│ SERVERS      │  #general @ MyServer      | port:8001 │
│  > MyServer  │──────────────────────────────────────-│
│    #general  │  [12:34] Alice (a3f829): Hello!       │
│    #random   │  [12:35] Bob (7c2de1): Hey Alice!     │
│              │  [12:36] Charlie (e91b44): Sup         │
│ PEERS (2)    │                                       │
│  Bob   7c2de1│                                       │
│  Charlie e91b│───────────────────────────────────────│
│              │ > _                                    │
│You: Alice ...│                                       │
└──────────────┴───────────────────────────────────────┘
```

### Commands

| Command | Description |
|---------|-------------|
| `/create <name>` | Create a new server |
| `/join <id> <host:port>` | Join a server via a peer |
| `/channel <name>` | Create or switch to a channel |
| `/server <name>` | Switch to a server by name or ID prefix |
| `/peers` | List connected peers |
| `/id` | Show your identity and public key |
| `/help` | Show available commands |
| `/quit` | Exit |

### Keyboard

| Key | Action |
|-----|--------|
| `Enter` | Send message / execute command |
| `Tab` | Cycle through channels |
| `Up/Down` | Scroll message history |
| `PgUp/PgDn` | Fast scroll |
| `Left/Right` | Move cursor in input |

## Architecture

```
┌─────────┐  TCP mesh   ┌─────────┐  TCP mesh   ┌─────────┐
│  Node A  │◄──────────►│  Node B  │◄──────────►│  Node C  │
│ (Alice)  │            │  (Bob)   │            │(Charlie) │
│ curses UI│            │ curses UI│            │ curses UI│
│ SQLite   │            │ SQLite   │            │ SQLite   │
└─────────┘             └─────────┘             └─────────┘
      ▲                       ▲                       ▲
      └───────── gossip ──────┴───── gossip ──────────┘
```

### Modules

| Module | Responsibility |
|--------|---------------|
| `identity.py` | Ed25519 key generation, signing, verification |
| `message.py` | Message model, canonical hashing, hashchain linking |
| `store.py` | SQLite append-only persistence (WAL mode) |
| `consensus.py` | Chain validation, fork resolution, censorship detection |
| `protocol.py` | Length-prefixed JSON wire protocol |
| `network.py` | Async TCP mesh, gossip broadcast, sync |
| `bootstrap.py` | Optional rendezvous server for peer discovery |
| `server.py` | Server and channel management |
| `node.py` | Main orchestrator |
| `ui.py` | Curses terminal interface |

### Message format

Every message contains:

| Field | Description |
|-------|-------------|
| `id` | SHA-256 hash of canonical content (the message's address) |
| `server_id` | Which server this belongs to |
| `channel` | Channel name |
| `author_pubkey` | 32-byte Ed25519 public key |
| `author_name` | Display name |
| `content` | Message text |
| `timestamp` | Unix timestamp |
| `prev_hash` | Hash of previous message in channel (genesis: `"0"*64`) |
| `signature` | 64-byte Ed25519 signature over canonical bytes |

The `prev_hash` field forms the hashchain. If two messages reference the same parent (concurrent sends / fork), both are accepted and ordered deterministically by `(timestamp, message_id)` — all nodes converge to the same order.

### Wire protocol

Messages between peers use length-prefixed JSON framing:

```
[4-byte big-endian uint32 length][JSON payload]
```

Protocol message types: `HELLO`, `HELLO_ACK`, `NEW_MESSAGE`, `SYNC_REQUEST`, `SYNC_RESPONSE`, `PEER_LIST`, `REGISTER`, `DISCOVER`, `DISCOVER_RESPONSE`, `SERVER_INFO`.

### Data flow

1. User types a message in the UI
2. Node creates a `Message`, signs it, computes hash, links to chain head
3. Message is stored locally in SQLite
4. Message is gossiped to all connected peers
5. Each peer validates (signature + hash), stores, re-gossips to its peers
6. Any node connecting later syncs the full history from peers

## Bootstrap server

For easier peer discovery, an optional bootstrap/rendezvous server can be run:

```bash
# Start bootstrap
python -m uncomms --serve-bootstrap --port 9999

# Nodes register and discover peers via bootstrap
python -m uncomms --port 8001 --name Alice --bootstrap localhost:9999
```

The bootstrap server is stateless — it keeps an in-memory registry of `(server_id, host, port)` with 5-minute expiry. It stores no messages and is entirely optional. Peers can always connect directly with `--peer`.

## Dependencies

**One external dependency**: [PyNaCl](https://pynacl.readthedocs.io/) (libsodium bindings for Ed25519 signatures).

Everything else is Python 3.10+ stdlib: `asyncio`, `sqlite3`, `hashlib`, `curses`, `json`, `struct`, `argparse`, `dataclasses`, `pathlib`, `threading`, `queue`.

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

32 tests covering identity, message model, SQLite store, wire protocol, consensus validation, and multi-node integration (gossip propagation, 3-node relay, sync-on-connect).

## Limitations

- **No NAT traversal** — nodes need direct connectivity (same LAN or port-forwarded). UDP hole punching is out of scope.
- **No encryption in transit** — messages are signed but not encrypted on the wire. For production use, wrap connections in TLS.
- **No access control** — anyone who knows a server ID can join. This is by design for censorship resistance, but means servers are public.
- **Full replication** — every node stores the complete history. Fine for chat-scale data, not for file sharing.
- **No message deletion** — append-only by design. Once sent, a message exists on every node permanently.

## License

MIT
