# estoppl

See what your AI agent is doing. Stop it when it goes wrong.

`estoppl` is a transparent proxy for MCP (Model Context Protocol) that gives you full visibility into every tool call your agent makes — and lets you set guardrails so it can't do things it shouldn't.

```
stdio mode:
┌──────────────┐                  ┌─────────────┐                  ┌──────────────┐
│  Agent Host  │ ── stdin ──────▶ │   estoppl   │ ── stdin ──────▶ │  MCP Server  │
│  (Claude,    │ ◀── stdout ───── │             │ ◀── stdout ───── │  (local)     │
│   LangChain) │                  │  intercept  │                  └──────────────┘
└──────────────┘                  │  guardrails │
                                  │  log + sign │
HTTP mode:                        └──────┬──────┘
┌──────────────┐                  ┌──────┴──────┐                  ┌──────────────┐
│  MCP Client  │ ── POST/SSE ──▶  │   estoppl   │ ── POST/SSE ──▶  │  MCP Server  │
│              │ ◀── JSON/SSE ──  │  :4100      │ ◀── JSON/SSE ──  │  (remote)    │
└──────────────┘                  └──────┬──────┘                  └──────────────┘
                                         │
                                  ┌──────▼──────┐
                                  │  audit log  │
                                  │  (signed,   │
                                  │   chained)  │
                                  └─────────────┘
```

## Why

AI agents call tools autonomously. Without visibility, you don't know what your agent did, how many times it called an API, or whether it tried something it shouldn't have. You find out when something breaks — or when you get the bill.

Estoppl fixes this:

- **Visibility** — every tool call is logged with timestamps, inputs (hashed), outputs (hashed), and latency
- **Guardrails** — block specific tools, set amount thresholds, flag sensitive operations for human review
- **Tamper-evident audit trail** — signed, hash-chained events that prove what happened and when

One config line. Zero code changes. Sub-millisecond overhead.

## Install

**Homebrew** (macOS and Linux):
```bash
brew tap estoppl/tap
brew install estoppl
```

**npm** (any platform with Node.js):
```bash
npx estoppl
# or install globally
npm install -g estoppl
```

**Cargo** (Rust toolchain):
```bash
cargo install estoppl
```

**Binary download** (no dependencies):
```bash
# macOS Apple Silicon
curl -L https://github.com/estoppl/estoppl/releases/latest/download/estoppl-darwin-aarch64.tar.gz | tar xz
sudo mv estoppl-darwin-aarch64 /usr/local/bin/estoppl

# macOS Intel
curl -L https://github.com/estoppl/estoppl/releases/latest/download/estoppl-darwin-x86_64.tar.gz | tar xz
sudo mv estoppl-darwin-x86_64 /usr/local/bin/estoppl

# Linux x86_64
curl -L https://github.com/estoppl/estoppl/releases/latest/download/estoppl-linux-x86_64.tar.gz | tar xz
sudo mv estoppl-linux-x86_64 /usr/local/bin/estoppl

# Linux ARM64
curl -L https://github.com/estoppl/estoppl/releases/latest/download/estoppl-linux-aarch64.tar.gz | tar xz
sudo mv estoppl-linux-aarch64 /usr/local/bin/estoppl
```

## Quick start

```bash
# Initialize config, keypair, and database
estoppl init --agent-id my-agent

# Start the proxy — stdio mode (wraps a local MCP server process)
estoppl start --upstream-cmd npx --upstream-args @stripe/mcp-server

# Start the proxy — HTTP mode (reverse proxy for remote MCP servers)
estoppl start-http --upstream-url http://localhost:3000/mcp

# See what your agent has been doing
estoppl audit -n 50

# Verify the audit chain hasn't been tampered with
estoppl audit --verify

# Filter audit events
estoppl audit --tool stripe.create_payment --decision block --since 2026-03-01T00:00:00Z

# Live-stream tool calls as they happen
estoppl tail

# View tool call statistics — volume, latency, per-tool breakdown
estoppl stats

# Generate an HTML report
estoppl report

# Auto-wrap your MCP client configs to route through estoppl
estoppl wrap              # wraps Claude Desktop, Cursor, Windsurf configs
estoppl wrap --dry-run    # preview changes without modifying
estoppl wrap --restore    # restore original configs from backup
estoppl unwrap            # same as wrap --restore

# Open the local web dashboard
estoppl dashboard         # http://127.0.0.1:4200
```

## MCP client configuration

### stdio mode (local MCP servers)

Drop the proxy into your MCP client config — one change, zero code modifications:

```json
{
  "mcpServers": {
    "stripe": {
      "command": "estoppl",
      "args": [
        "start",
        "--upstream-cmd", "npx",
        "--upstream-args", "@stripe/mcp-server"
      ]
    }
  }
}
```

### HTTP mode (remote MCP servers)

For MCP servers running over HTTP (Streamable HTTP transport), run the proxy as a reverse proxy:

```bash
# Start the proxy (listens on 127.0.0.1:4100 by default)
estoppl start-http --upstream-url https://mcp.stripe.com/v1

# Point your MCP client at the proxy instead of the upstream server
```

```json
{
  "mcpServers": {
    "stripe": {
      "url": "http://127.0.0.1:4100"
    }
  }
}
```

The HTTP proxy supports the full MCP Streamable HTTP transport: POST (JSON-RPC requests, including batches), GET (SSE streams for server-initiated messages), and DELETE (session termination). Session IDs and auth headers are forwarded transparently.

Your agent doesn't know estoppl is there. Every tool call passes through transparently.

## Configuration

`estoppl init` generates an `estoppl.toml`:

```toml
[agent]
id = "my-agent"
version = "0.1.0"

[rules]
# Allow only these tools (empty = allow all). Supports wildcards.
# allow_tools = ["read_portfolio", "get_balance", "stripe.list_*"]
allow_tools = []

# Block these tools entirely — they never reach the MCP server
block_tools = []

# Flag these for human review (call goes through, logged as HUMAN_REQUIRED)
human_review_tools = ["wire_transfer", "execute_trade"]

# Block any tool call where the amount exceeds this value
max_amount_usd = 50000.0

# Where to find the amount in tool arguments (supports dot notation)
amount_field = "amount"

# Max calls per tool per minute (0 = unlimited). Prevents runaway agents.
# rate_limit_per_minute = 30

# Per-tool rate limit overrides
# [rules.rate_limit_tools]
# "stripe.create_payment" = 5
# "execute_trade" = 10

[ledger]
db_path = ".estoppl/events.db"
# Cloud sync — stream signed events to the Estoppl cloud ledger
# cloud_endpoint = "https://api.estoppl.com/v1/events"
# cloud_api_key = "sk_your_key"
```

### Guardrails

**Allow tools** — if set, only these tools are permitted. Everything else is blocked. Use this for a secure-by-default posture: `allow_tools = ["read_portfolio", "get_balance"]`. Supports wildcards: `"read.*"` allows all read tools. Block list still takes priority over allow list.

**Block tools** — tool calls matching these names are rejected before reaching the upstream server. The agent gets a JSON-RPC error. Supports wildcards: `"stripe.*"` blocks all Stripe tools. Block list overrides allow list.

**Human review** — tool calls go through but are flagged as `HUMAN_REQUIRED` in the audit log. Use this for sensitive operations you want visibility into.

**Amount thresholds** — tool calls with an amount field exceeding the limit are blocked automatically. Catches runaway agents before they do damage.

**Rate limiting** — cap how many times any tool (or a specific tool) can be called per minute. If an agent enters a loop calling Stripe 200 times, it gets cut off after the limit. Configure globally with `rate_limit_per_minute` or per-tool with `rate_limit_tools`.

## Audit log

Every tool call produces a signed event:

```
EVENT      TOOL                           DECISION     TIMESTAMP              LATENCY
a1b2c3d4   stripe.create_payment          ALLOW        2026-03-05 14:23:01    2ms
e5f6g7h8   wire_transfer                  HUMAN_REQ    2026-03-05 14:23:03    1ms
i9j0k1l2   stripe.create_payment          BLOCK        2026-03-05 14:23:05    0ms
```

Each event is:
- **Signed** with Ed25519 — proves the proxy produced it
- **Hash-chained** — each event links to the previous one; tampering breaks the chain
- **Sequence-numbered** — monotonically increasing per proxy instance; enables gap detection during cloud sync
- **Zero-retention** — only SHA-256 hashes of inputs/outputs are stored, never raw data

Verify the chain hasn't been tampered with:
```bash
estoppl audit --verify
# Hash chain INTACT — 847 events verified
```

Generate an HTML report to share with your team:
```bash
estoppl report --output report.html
```

## Cloud sync

Stream your signed audit events to the Estoppl cloud for centralized monitoring, alerting, and compliance evidence.

```bash
# Configure the cloud endpoint in estoppl.toml
# [ledger]
# cloud_endpoint = "https://api.estoppl.com/v1/events"
# cloud_api_key = "sk_your_key"

# Start the proxy with cloud sync enabled
estoppl start --upstream-cmd npx --upstream-args @stripe/mcp-server --sync
estoppl start-http --upstream-url http://localhost:3000/mcp --sync
```

The `--sync` flag starts a background task that:
- Polls local SQLite for new events every 5 seconds
- Batches events (up to 100) and POSTs them to the cloud endpoint
- Tracks a sync watermark so it picks up where it left off (survives restarts)
- Retries with exponential backoff on failures (1s → 2s → 4s → ... capped at 5min)

All events stay in the local audit log regardless of sync status. The cloud is additive — if the network is down, events queue locally and sync when connectivity returns.

### Chain integrity under network partition

Every event carries a monotonically increasing `sequence_number` that is included in the event hash (tamper-evident). Each sync batch includes chain metadata:

- **Sequence range** (`first_sequence` / `last_sequence`) — lets the cloud detect gaps (e.g., "I have 1-50, you sent 53-100, where are 51-52?")
- **`expected_prev_hash`** — the event hash the cloud should already have for the event before this batch, proving chain continuity across batch boundaries
- **`batch_hash`** — SHA-256 of all event hashes in the batch, verifying nothing was tampered with in transit

If the cloud detects a gap, it responds with `gap_from_sequence` and the proxy automatically rewinds its cursor and re-sends the missing events. The local hash chain stays valid regardless of sync state — events are always chained correctly in SQLite first, then synced to cloud as a best-effort background operation.

## Project structure

```
src/
├── main.rs          CLI entry point (clap)
├── config/          Configuration loading and defaults
├── mcp/             MCP JSON-RPC type definitions
├── identity/        Ed25519 key management and signing
├── policy/          Rules-based policy engine
├── ledger/          Local SQLite storage with hash chaining
├── proxy/           stdio + HTTP/SSE proxy core
├── sync/            Cloud sync background task
├── report/          HTML compliance report generator
├── wrap/            Auto-wrap MCP client configs
└── dashboard/       Local web dashboard (axum + embedded HTML)
```

## Roadmap

### Current (v0.13.0)
- [x] stdio proxy mode (transparent MCP interception)
- [x] HTTP/SSE proxy mode (MCP Streamable HTTP transport — POST, GET SSE, DELETE)
- [x] JSON-RPC batch support (mixed blocked + allowed in same batch)
- [x] Guardrails: allow lists, block lists (with wildcards), amount thresholds, human review flags
- [x] Ed25519 event signing
- [x] Hash-chained local SQLite audit log
- [x] CLI: `init`, `start`, `start-http`, `audit`, `report`, `tail`, `stats`, `wrap`, `unwrap`, `dashboard`
- [x] HTML activity report
- [x] `estoppl tail` — live-stream tool calls in your terminal as they happen
- [x] Rate limiting / circuit breaker — block tools called more than N times per minute
- [x] `estoppl stats` — tool call volume, latency percentiles, per-tool and per-session breakdown
- [x] Audit filters — `--tool`, `--decision`, `--since`
- [x] CI + prebuilt binaries (macOS, Linux) via GitHub Releases
- [x] `--sync` flag — stream signed events to cloud endpoint
- [x] Homebrew tap (`brew install estoppl`)
- [x] npm wrapper package (`npx estoppl` — binary distribution, no Rust required)
- [x] `estoppl wrap` — auto-detect and wrap existing MCP client configs (Claude Desktop, Cursor, Windsurf)
- [x] `estoppl dashboard` — local web UI for browsing audit events, guardrail hits, and chain verification

### Future (cloud / 3P integrations)
- [ ] Blocking human review — tools pause and wait for explicit approval via dashboard or webhook
- [ ] Cloud dashboard with real-time event feed and alerting
- [ ] Cloud ledger with immutable WORM storage for regulated industries (SEC 17a-4)
- [ ] OPA (Open Policy Agent) integration for enterprise policy management
- [ ] Framework-agnostic compliance report templates (EU AI Act, SEC, SOC 2)
- [ ] OpenAI function calling interception (beyond MCP)
- [ ] A2A (Agent-to-Agent) protocol interception for multi-agent delegation chains
- [ ] Kubernetes sidecar deployment
- [ ] Cross-org agent trust verification

## For regulated teams

If you're in financial services and need legally defensible audit records — immutable WORM storage (SEC 17a-4), regulatory evidence packs, cross-org trust verification — see [estoppl.ai](https://estoppl.ai) for the enterprise platform. This proxy is the open-source foundation; the cloud ledger is where compliance certification lives.

## License

Apache 2.0
