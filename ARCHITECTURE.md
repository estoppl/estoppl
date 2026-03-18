# Architecture

## Overview

estoppl is a transparent proxy that sits between AI agent hosts and MCP servers. It intercepts every tool call at the protocol layer, enforces guardrails, and produces a signed, hash-chained audit log.

```
Agent Host ──▶ estoppl ──▶ MCP Server
              │
              ├── Policy evaluation (allow/block/flag)
              ├── Event signing (Ed25519)
              ├── Hash chaining (SHA-256)
              └── SQLite append
```

## Source layout

```
src/
├── main.rs          CLI entry point (clap), command handlers
├── config/mod.rs    ProxyConfig, RulesConfig, TOML serialization
├── mcp/
│   ├── mod.rs
│   └── types.rs     JsonRpcRequest, JsonRpcResponse, ToolCallParams
├── identity/mod.rs  KeyManager (Ed25519 keypair load/generate/sign)
├── policy/mod.rs    PolicyEngine, PolicyDecision, RateTracker
├── ledger/
│   ├── mod.rs
│   ├── event.rs     AgentActionEvent schema, hash computation
│   └── local.rs     LocalLedger (SQLite), stats, chain verification
├── proxy/
│   ├── mod.rs       Shared log_event function (both proxy modes)
│   ├── stdio.rs     run_stdio_proxy — stdio intercept loop
│   └── http.rs      run_http_proxy — HTTP/SSE reverse proxy (axum)
├── sync/mod.rs      CloudSyncer — background sync with gap reconciliation
├── report/mod.rs    HTML activity report generator
├── wrap/mod.rs      Auto-wrap MCP client configs
└── dashboard/
    ├── mod.rs       Local web dashboard server (axum, JSON API)
    └── static/
        └── index.html  Embedded single-page dashboard UI
```

## Key design decisions

### Events are logged at interception time

When a tool call arrives, estoppl evaluates the policy and writes the event to SQLite immediately — before forwarding to the upstream server. This guarantees no events are lost even if the proxy exits mid-call or the upstream never responds.

Blocked calls are logged with the error response. Allowed and human-review calls are logged with `output_hash=""` and `latency_ms=0` since the response hasn't arrived yet. Completeness is more important than latency metadata for a compliance tool.

### Zero-data retention

Raw tool call inputs and outputs are never stored. Only SHA-256 hashes are logged. This is critical for handling sensitive data — PII, financial data, API keys. The hash proves *that* a specific input was seen without storing *what* it was.

### Hash chaining

Each event stores the SHA-256 hash of the previous event, creating a tamper-evident chain. If any event is modified, deleted, or inserted, the chain breaks and `estoppl audit --verify` detects it.

The event hash is computed over: `event_id | agent_id | agent_version | session_id | timestamp | tool_name | tool_server | input_hash | output_hash | policy_decision | sequence_number | prev_hash`. Changing any field invalidates the hash.

### Sequence numbers

Every event has a monotonically increasing `sequence_number` (per proxy instance), included in the event hash. This enables:
- Gap detection during cloud sync ("I have 1-50, you sent 53-100, where are 51-52?")
- Tamper evidence — changing or removing a sequence number invalidates the event hash

### Guardrails before forwarding

Blocked calls never reach the upstream MCP server. The proxy synthesizes a JSON-RPC error response directly. The evaluation order is:

1. **Block list** — highest priority, always blocked
2. **Allow list** — if non-empty, only listed tools pass (everything else blocked)
3. **Human review** — call goes through, flagged as `HUMAN_REQUIRED`
4. **Amount threshold** — blocks if amount field exceeds configured limit
5. **Rate limiting** — blocks if calls per minute exceed configured limit
6. **Default** — allow

### Protocol-agnostic event schema

`AgentActionEvent` doesn't depend on MCP specifics. The interception layer is MCP-specific, but the logging/signing/policy layer is designed to support future protocols (A2A, OpenAI function calling).

### Proxy modes

**stdio**: The proxy spawns the upstream MCP server as a child process, intercepts stdin/stdout JSON-RPC messages. On stdin EOF (agent disconnects), the proxy drains in-flight responses before exiting.

**HTTP/SSE**: The proxy listens on a local port (default 4100) and reverse-proxies to the upstream MCP server. Handles POST (JSON-RPC, including batches), GET (SSE streams), and DELETE (session termination). Session IDs and auth headers are forwarded transparently.

Both modes use the same `log_event` function in `proxy/mod.rs`. The `tool_server` field distinguishes the transport ("stdio" vs upstream URL).

### Cloud sync

The `--sync` flag spawns a background `CloudSyncer` that polls local SQLite for unsynced events and POSTs batches to the cloud endpoint.

- Uses a `sync_state` table with a rowid watermark
- Events always persist locally first; cloud sync is best-effort
- Exponential backoff on failures (1s → 2s → 4s → ... capped at 5min)
- Idempotent (dedupes on event_id)

### Chain integrity under network partition

Each sync batch includes `ChainMetadata`:

- **`first_sequence` / `last_sequence`** — lets the cloud detect gaps
- **`expected_prev_hash`** — the event hash the cloud should already have for the event before this batch, proving chain continuity across batch boundaries
- **`batch_hash`** — SHA-256 of all event hashes in the batch, verifying nothing was tampered with in transit

On gap detection (cloud returns `409 + gap_from_sequence`), the proxy resets its sync cursor and re-sends missing events. The local hash chain stays valid regardless of sync state.

### Dashboard

The dashboard is a single-page web UI served from the binary via `include_str!`. It reopens the SQLite connection per request (same pattern as `cmd_tail`) to ensure it sees WAL commits from a concurrently running proxy process.

API endpoints:
- `GET /api/stats` — summary stats + latency percentiles
- `GET /api/events?limit=&tool=&decision=&since=` — filtered events
- `GET /api/tools` — per-tool breakdown
- `GET /api/verify` — chain verification result

### Wrap

`estoppl wrap` reads MCP client config files for Claude Desktop, Cursor, and Windsurf. For each stdio server, it rewrites the command to route through `estoppl start`. Marker fields (`_estoppl_wrapped`, `_estoppl_original`) ensure idempotency and enable `estoppl unwrap` to restore the original config. HTTP-only servers are skipped.

## Runtime artifacts

All stored under `.estoppl/` in the working directory:
- `.estoppl/keys/estoppl-signing.key` — Ed25519 private key (mode 0600)
- `.estoppl/keys/estoppl-signing.pub` — Ed25519 public key
- `.estoppl/events.db` — SQLite database with audit events

## Vision: trust layer for AI agent tool calls

The long-term architecture positions estoppl as a trust layer between AI agents and API providers — analogous to how Visa sits between cardholders and merchants.

Today, estoppl is a local proxy: it logs and enforces guardrails, but the upstream API provider doesn't know estoppl exists. The next evolution adds **attestation and verification**, making estoppl required by both sides.

### How it works

```
Agent → estoppl proxy → [attestation ID] → API Provider (MCP Server)
            ↓                                       ↓
        syncs event                          calls estoppl cloud:
        to cloud ledger                      "verify this attestation"
            ↓                                       ↓
        estoppl cloud ◀─────────────────── "valid: agent=treasury-bot,
        (WORM, hash-chained)                 user=alice@acme.com,
                                             decision=ALLOW, chain=intact"
```

1. Agent makes a tool call — estoppl proxy intercepts, evaluates policy, logs the event
2. Event syncs to the estoppl cloud ledger (tamper-proof, hash-chained)
3. Proxy forwards the call with an attestation ID header
4. API provider calls `api.estoppl.com/verify/{attestation_id}` to verify
5. Cloud confirms the event exists, the chain is intact, and the policy was evaluated
6. API provider proceeds or rejects

### Why cloud verification is required

A local-only signature can be forged — the agent operator controls the signing key. The cloud is the neutral third party neither side controls, which is why both sides can trust it. This is the same trust model as payment networks: the merchant doesn't trust the cardholder's signature, they call the network.

### Phases

- **Phase 1 (current)**: OSS proxy with local logging, signing, and guardrails
- **Phase 2**: Attestation header added to forwarded requests (self-contained, signed)
- **Phase 3**: Cloud verification API — API providers verify attestations against the cloud ledger
- **Phase 4**: API providers require estoppl attestation for high-risk operations
- **Phase 5**: Registry and network effects — public key directory, cross-org trust

## Build and test

```bash
cargo build          # builds the estoppl binary
cargo test           # runs all 82 tests (unit + integration)
cargo fmt --check    # check formatting
cargo clippy -- -D warnings  # lint
```

CI runs all three on every push/PR. Release workflow builds binaries for macOS (arm64, x64) and Linux (x64, arm64), publishes to GitHub Releases, crates.io, npm, and updates the Homebrew tap.
