# CLAUDE.md

## Project overview

estoppl is an open-source transparent proxy for MCP (Model Context Protocol) tool calls, built by Estoppl. It sits between AI agent hosts and MCP servers, giving developers visibility into every tool call, enforcing guardrails, and producing a signed, hash-chained audit log.

This is the OSS layer of a two-layer architecture:
- **estoppl (this repo)** — open source, installed everywhere, intercepts and logs
- **estoppl-ledger (separate, closed)** — proprietary cloud service for WORM storage, compliance evidence packs, regulatory certification

## Architecture

- **Language**: Rust (tokio async runtime)
- **Binary name**: `estoppl` (crate name is `estoppl`)
- **Proxy modes**: stdio intercept + HTTP/SSE reverse proxy (MCP Streamable HTTP transport)
- **Policy engine**: Simple TOML-configured rules (OPA integration is a future milestone)
- **Storage**: Local SQLite with WAL mode, hash-chained events
- **Signing**: Ed25519 via ed25519-dalek
- **HTTP framework**: axum (for HTTP proxy mode + dashboard)
- **CLI**: clap with subcommands: `init`, `start`, `start-http`, `audit`, `report`, `tail`, `stats`, `wrap`, `dashboard`
- **Distribution**: GitHub Releases, crates.io (`cargo install estoppl`), npm (`npx estoppl`), Homebrew (`brew install estoppl`)

## Source layout

```
src/
├── main.rs          CLI entry point, command handlers
├── config/mod.rs    ProxyConfig, RulesConfig, TOML serialization
├── mcp/
│   ├── mod.rs
│   └── types.rs     JsonRpcRequest, JsonRpcResponse, ToolCallParams
├── identity/mod.rs  KeyManager (Ed25519 keypair load/generate/sign)
├── policy/mod.rs    PolicyEngine, PolicyDecision, RateTracker (in-memory rate limiting)
├── ledger/
│   ├── mod.rs
│   ├── event.rs     AgentActionEvent schema, hash computation
│   └── local.rs     LocalLedger (SQLite), ReportStats, ToolStats, LatencyStats, chain verification, filtered queries, tail support, sync state with sequence tracking
├── proxy/
│   ├── mod.rs       Shared log_event function used by both proxy modes
│   ├── stdio.rs     run_stdio_proxy — stdio intercept loop
│   └── http.rs      run_http_proxy — HTTP/SSE reverse proxy (axum, MCP Streamable HTTP)
├── sync/mod.rs      CloudSyncer — background sync with chain metadata, gap reconciliation, partition recovery
├── report/mod.rs    HTML activity report generator
├── wrap/mod.rs      Auto-wrap MCP client configs (Claude Desktop, Cursor, Windsurf)
└── dashboard/
    ├── mod.rs       Local web dashboard server (axum, JSON API)
    └── static/
        └── index.html  Embedded single-page dashboard UI
```

## Key design decisions

- **Zero-data retention**: Raw tool call inputs/outputs are never stored. Only SHA-256 hashes are logged. Important for handling sensitive data (PII, financial data, API keys).
- **Hash chaining**: Each event stores the SHA-256 hash of the previous event, creating a tamper-evident chain. Breakage is detectable via `estoppl audit --verify`.
- **Guardrails before forwarding**: Blocked calls never reach the upstream MCP server. The proxy synthesizes a JSON-RPC error response directly.
- **Tracing to stderr**: All log output goes to stderr so it doesn't interfere with stdio JSON-RPC on stdout.
- **Protocol-agnostic event schema**: AgentActionEvent doesn't depend on MCP specifics. The interception layer is MCP-specific, but the logging/signing/policy layer is designed to support future protocols (A2A, ACP).
- **HTTP proxy uses axum + reqwest**: The HTTP proxy listens on a single endpoint, handles POST/GET/DELETE per the MCP Streamable HTTP spec. Session IDs and auth headers are forwarded transparently. SSE streams are passed through with inline inspection for tool call response logging.
- **Shared log_event**: Both stdio and HTTP proxy use the same `log_event` function in `proxy/mod.rs`. The `tool_server` field distinguishes the transport ("stdio" vs upstream URL).
- **Cloud sync is additive**: The `--sync` flag spawns a background `CloudSyncer` that polls local SQLite for unsynced events and POSTs batches to the cloud endpoint. Uses a `sync_state` table with a rowid watermark. Events always persist locally first; cloud sync is best-effort with exponential backoff. Idempotent (dedupes on event_id).
- **Chain integrity under network partition**: Every event has a monotonically increasing `sequence_number` (per proxy instance, included in the event hash). Sync batches include `ChainMetadata` with `first_sequence`, `last_sequence`, `expected_prev_hash`, and `batch_hash`. The cloud uses sequence numbers to detect gaps and `expected_prev_hash` to verify chain continuity across batch boundaries. On gap detection (cloud returns `409 + gap_from_sequence`), the proxy resets its sync cursor and re-sends missing events. Local hash chain stays valid regardless of sync state.
- **Wrap uses marker fields**: `_estoppl_wrapped` and `_estoppl_original` are added to wrapped MCP server entries for idempotency and restore. HTTP-only servers (no `command` field) are skipped.
- **Dashboard reopens SQLite per request**: Same pattern as `cmd_tail` — ensures the dashboard sees WAL commits from a concurrently running proxy process. HTML/CSS/JS is embedded in the binary via `include_str!`.

## Build and test

```bash
cargo build          # builds the `estoppl` binary
cargo test           # runs all 77 tests (unit + integration)
cargo run -- init    # test the init command
```

### Test coverage

- **Unit tests** (65): inline `#[cfg(test)]` modules in each source file
  - `mcp/types.rs` — JSON-RPC parsing, tool call detection, serialization
  - `identity/mod.rs` — key generation, persistence, sign/verify roundtrip
  - `ledger/event.rs` — hash determinism, field sensitivity, chain linking, sequence number tamper-evidence
  - `ledger/local.rs` — append/query, chain verification (intact/broken/tampered), filters, stats, tail, sequence numbers, sync cursor reset
  - `policy/mod.rs` — block lists, wildcards, human review, amount thresholds, rate limiting
  - `proxy/http.rs` — response merging (single + blocked, batch + blocked, empty blocked), policy in batch context
  - `sync/mod.rs` — sync cursor, chain metadata, gap reconciliation, network partition + reconnect, batch hash, response parsing
  - `wrap/mod.rs` — config transformation, idempotency, restore, HTTP-only skip, empty config
  - `dashboard/mod.rs` — embedded HTML validation
- **Integration tests** (12): `tests/integration.rs`
  - CLI commands (`init`, `audit`, `audit --verify`, `report`, `stats`, `--help`)
  - Audit filters (`--tool`, `--decision`, `--since`)
  - Report with custom output path
  - Wrap (`--dry-run`, no configs found)
  - End-to-end stdio proxy with a fake MCP server (allowed + blocked calls, chain verification)

## CI

- `.github/workflows/ci.yml` — runs `cargo test`, `cargo clippy`, `cargo fmt --check` on every push/PR to main
- `.github/workflows/release.yml` — builds prebuilt binaries for macOS (arm64, x64) and Linux (x64, arm64) on version tags, publishes to GitHub Releases, crates.io, npm, and updates Homebrew tap

## Config file

`estoppl.toml` in the working directory. Generated by `estoppl init`. Key sections:
- `[agent]` — agent ID, version, authorized user
- `[rules]` — block_tools, human_review_tools, max_amount_usd, amount_field, rate_limit_per_minute, rate_limit_tools
- `[ledger]` — db_path, cloud_endpoint, cloud_api_key (used by `--sync`)

## Runtime artifacts

All stored under `.estoppl/` in the working directory:
- `.estoppl/keys/estoppl-signing.key` — Ed25519 private key (mode 0600)
- `.estoppl/keys/estoppl-signing.pub` — Ed25519 public key
- `.estoppl/events.db` — SQLite database with audit events
