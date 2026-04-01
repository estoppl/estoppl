# CLAUDE.md

## Project overview

estoppl is an open-source transparent proxy for MCP (Model Context Protocol) tool calls, built by Estoppl. It sits between AI agent hosts and MCP servers, giving developers visibility into every tool call, enforcing guardrails, and producing a signed, hash-chained audit log.

The long-term vision is to become the trust layer for AI agent tool calls — analogous to Visa for payments. API providers verify estoppl attestations before processing high-risk operations.

This is the OSS layer of a two-layer architecture:
- **estoppl (this repo)** — open source proxy, installed everywhere, intercepts/logs/attests
- **estoppl cloud (estoppl/api, closed-source)** — verification API, cloud dashboard (org-wide monitoring, policy kill switch, human review, compliance exports), WORM storage

## Architecture

- **Language**: Rust (tokio async runtime)
- **Binary name**: `estoppl` (crate name is `estoppl`)
- **Proxy modes**: stdio intercept + HTTP/SSE reverse proxy (MCP Streamable HTTP transport)
- **Policy engine**: TOML-configured rules locally + cloud-managed JSONB rules (hot-reloaded every 5s). Custom conditional rules, per-agent overrides, wildcards.
- **Storage**: Local SQLite with WAL mode, hash-chained events
- **Signing**: Ed25519 via ed25519-dalek
- **HTTP framework**: axum (for HTTP proxy mode + dashboard)
- **CLI**: clap with subcommands: `init`, `start`, `start-http`, `audit` (`--verify`, `--verify-receipt`, `--verify-export`), `bench`, `report`, `tail`, `stats`, `wrap`, `unwrap`, `dashboard`
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
├── wrap/mod.rs      Auto-wrap MCP client configs (Claude Desktop, Cursor, Windsurf — Windsurf untested)
└── dashboard/
    ├── mod.rs       Local web dashboard server (axum, JSON API)
    └── static/
        └── index.html  Embedded single-page dashboard UI
```

## Key design decisions

- **Rich event logging with redaction**: By default, raw tool arguments are logged and synced to the cloud for auditing. Configurable `redact_fields` in estoppl.toml strips sensitive fields (SSN, credit card, etc.) before syncing — replaced with `"[REDACTED]"`. Input/output hashes are always stored regardless of redaction.
- **Custom conditional rules**: Users define arbitrary rules checking any field in tool arguments with any operator (gt, lt, eq, neq, contains, etc.) and any action (block, human_review, allow). Supports wildcard tool matching (`*`, `wire_*`) and nested field paths (`payment.total`).
- **Per-agent policy rules**: Different agents can have different rules via `agent_rules` map in cloud policy. Agent-specific rules override org-wide defaults.
- **Blocking human review**: When cloud sync is active and policy decision is `HUMAN_REQUIRED`, the proxy holds the call (using `FuturesUnordered` for non-blocking), submits a review to the cloud, and polls every 2 seconds for approval. On approve: forwards to upstream. On deny/timeout (5 min): returns JSON-RPC error. Other tool calls continue flowing while a review is pending.
- **Offline receipt verification**: `estoppl audit --verify-receipt` recomputes SHA-256 from the receipt's `hash_input` and compares to `event_hash`. Also verifies Ed25519 signature against local keys and checks field integrity against local DB.
- **Offline export verification**: `estoppl audit --verify-export` verifies an entire compliance export — recomputes hashes for all events and checks chain linkage (prev_hash) per proxy_key_id.
- **Latency benchmark**: `estoppl bench` runs tool calls direct vs through proxy, reports p50/p95/p99 overhead. Proves proxy adds <2ms latency.
- **Hash chaining**: Each event stores the SHA-256 hash of the previous event, creating a tamper-evident chain. Breakage is detectable via `estoppl audit --verify`.
- **Guardrails before forwarding**: Blocked calls never reach the upstream MCP server. The proxy synthesizes a JSON-RPC error response directly.
- **Tracing to stderr**: All log output goes to stderr so it doesn't interfere with stdio JSON-RPC on stdout.
- **Protocol-agnostic event schema**: AgentActionEvent doesn't depend on MCP specifics. The interception layer is MCP-specific, but the logging/signing/policy layer is designed to support future protocols (A2A, ACP).
- **X-Estoppl-Attestation header**: In HTTP proxy mode, the proxy adds `X-Estoppl-Attestation: {event_id}` to every forwarded tool call request. Events are logged before forwarding (not after response) so the attestation ID is available for upstream verification. This is the "Visa for AI agents" — upstream MCP servers can call `GET /v1/verify/{attestationID}` to confirm governance before processing. Only applies to HTTP mode (stdio has no HTTP headers).
- **HTTP proxy uses axum + reqwest**: The HTTP proxy listens on a single endpoint, handles POST/GET/DELETE per the MCP Streamable HTTP spec. Session IDs and auth headers are forwarded transparently. SSE streams are passed through with inline inspection for tool call response logging. Adds `X-Estoppl-Attestation` header to forwarded requests.
- **Shared log_event**: Both stdio and HTTP proxy use the same `log_event` function in `proxy/mod.rs`. The `tool_server` field distinguishes the transport ("stdio" vs upstream URL).
- **Cloud sync is automatic**: When `cloud_api_key` is set in `estoppl.toml`, the proxy automatically spawns a background `CloudSyncer` that polls local SQLite for unsynced events and POSTs batches to the cloud endpoint (defaults to `https://api.estoppl.ai/v1/events`). Uses a `sync_state` table with a rowid watermark. Events always persist locally first; cloud sync is best-effort with exponential backoff. Idempotent (dedupes on event_id). The shutdown channel sender must be kept alive (`std::mem::forget`) to prevent the sync loop from exiting prematurely.
- **Policy hot-reload from cloud**: When `cloud_api_key` and `org_id` are configured, a `PolicySyncer` background task polls `GET /v1/policy/{org_id}` every 5 seconds. If the returned version is newer, the `PolicyEngine`'s rules are hot-swapped via `Arc<RwLock<RulesConfig>>`. This is the kill switch — an admin blocks a tool in the dashboard, and within 5 seconds the proxy starts rejecting that tool.
- **Chain integrity under network partition**: Every event has a monotonically increasing `sequence_number` (per proxy instance, included in the event hash). Sync batches include `ChainMetadata` with `first_sequence`, `last_sequence`, `expected_prev_hash`, and `batch_hash`. The cloud uses sequence numbers to detect gaps and `expected_prev_hash` to verify chain continuity across batch boundaries. On gap detection (cloud returns `409 + gap_from_sequence`), the proxy resets its sync cursor and re-sends missing events. Local hash chain stays valid regardless of sync state.
- **Wrap uses marker fields**: `_estoppl_wrapped` and `_estoppl_original` are added to wrapped MCP server entries for idempotency and restore. HTTP-only servers (no `command` field) are skipped. Wrap embeds `--config` with the absolute path to `estoppl.toml` (if found in cwd) so the proxy finds its config regardless of the MCP client's working directory.
- **Config-relative paths**: Both `db_path` and `.estoppl/keys` are resolved against the config file's directory, not the process cwd. This is critical for sandboxed MCP clients like Claude Desktop, which launch subprocesses with `cwd=/`. Without this, the proxy tries to write to `/.estoppl/keys/` and fails with "Read-only file system."
- **Wrap client filter accepts hyphens**: `--client claude-desktop` works (normalizes hyphens to spaces before matching). Partial matches work too: `--client claude` matches "Claude Desktop."
- **Dashboard reopens SQLite per request**: Same pattern as `cmd_tail` — ensures the dashboard sees WAL commits from a concurrently running proxy process. HTML/CSS/JS is embedded in the binary via `include_str!`.

## Build and test

```bash
cargo build          # builds the `estoppl` binary
cargo test           # runs all tests (unit + integration)
cargo run -- init    # test the init command
```

### Test coverage

- **Unit tests** (70): inline `#[cfg(test)]` modules in each source file
  - `mcp/types.rs` — JSON-RPC parsing, tool call detection, serialization
  - `identity/mod.rs` — key generation, persistence, sign/verify roundtrip
  - `ledger/event.rs` — hash determinism, field sensitivity, chain linking, sequence number tamper-evidence
  - `ledger/local.rs` — append/query, chain verification (intact/broken/tampered), filters, stats, tail, sequence numbers, sync cursor reset
  - `policy/mod.rs` — allow lists, block lists, wildcards, block-overrides-allow, human review, amount thresholds, rate limiting
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
- `[ledger]` — db_path (auto-resolved relative to config file), cloud_api_key, org_id (cloud_endpoint defaults to `https://api.estoppl.ai/v1/events`)

## Runtime artifacts

All stored under `.estoppl/` in the working directory:
- `.estoppl/keys/estoppl-signing.key` — Ed25519 private key (mode 0600)
- `.estoppl/keys/estoppl-signing.pub` — Ed25519 public key
- `.estoppl/events.db` — SQLite database with audit events
