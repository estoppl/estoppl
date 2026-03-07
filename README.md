# estoppl-proxy

See what your AI agent is doing. Stop it when it goes wrong.

`estoppl` is a transparent proxy for MCP (Model Context Protocol) that gives you full visibility into every tool call your agent makes — and lets you set guardrails so it can't do things it shouldn't.

```
┌──────────────┐                  ┌─────────────┐                  ┌──────────────┐
│  Agent Host  │ ── stdin ──────▶ │   estoppl   │ ── stdin ──────▶ │  MCP Server  │
│  (Claude,    │ ◀── stdout ───── │             │ ◀── stdout ───── │  (Stripe,    │
│   LangChain) │                  │  intercept  │                  │   Plaid, etc)│
└──────────────┘                  │  guardrails │                  └──────────────┘
                                  │  log + sign │
                                  └──────┬──────┘
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

## Quick start

```bash
# Install
cargo install --path .

# Initialize config, keypair, and database
estoppl init --agent-id my-agent

# Start the proxy (wraps your MCP server)
estoppl start --upstream-cmd npx --upstream-args @stripe/mcp-server

# See what your agent has been doing
estoppl audit -n 50

# Generate an HTML report
estoppl report
```

## MCP client configuration

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

Your agent doesn't know estoppl is there. Every tool call passes through transparently.

## Configuration

`estoppl init` generates an `estoppl.toml`:

```toml
[agent]
id = "my-agent"
version = "0.1.0"

[rules]
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
```

### Guardrails

**Block tools** — tool calls matching these names are rejected before reaching the upstream server. The agent gets a JSON-RPC error. Supports wildcards: `"stripe.*"` blocks all Stripe tools.

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

## Project structure

```
src/
├── main.rs          CLI entry point (clap)
├── config/          Configuration loading and defaults
├── mcp/             MCP JSON-RPC type definitions
├── identity/        Ed25519 key management and signing
├── policy/          Rules-based policy engine
├── ledger/          Local SQLite storage with hash chaining
├── proxy/           stdio proxy core
└── report/          HTML compliance report generator
```

## Roadmap

### Current (v0.2)
- [x] stdio proxy mode (transparent MCP interception)
- [x] Guardrails: tool block/allow lists, amount thresholds, human review flags
- [x] Ed25519 event signing
- [x] Hash-chained local SQLite audit log
- [x] CLI: `init`, `start`, `audit`, `report`, `tail`, `stats`
- [x] HTML activity report
- [x] `estoppl tail` — live-stream tool calls in your terminal as they happen
- [x] Rate limiting / circuit breaker — block tools called more than N times per minute
- [x] `estoppl stats` — tool call volume, latency percentiles, per-tool and per-session breakdown
- [x] Audit filters — `--tool`, `--decision`, `--since`
- [x] CI + prebuilt binaries (macOS, Linux) via GitHub Releases

### Next (v0.3)
- [ ] Homebrew tap (`brew install estoppl`)
- [ ] npm wrapper package (`npx estoppl` — binary distribution, no Rust required)
- [ ] pip wrapper package (`pip install estoppl`)
- [ ] HTTP/SSE reverse proxy mode (for remote MCP servers)
- [ ] OPA (Open Policy Agent) integration for enterprise policy management

### Future
- [ ] Python and TypeScript SDKs
- [ ] Cloud ledger with immutable WORM storage for regulated industries
- [ ] Compliance evidence packs for SEC, FINRA, and EU AI Act
- [ ] Kubernetes sidecar deployment
- [ ] A2A (Agent-to-Agent) protocol support
- [ ] Cross-org agent trust verification

## For regulated teams

If you're in financial services and need legally defensible audit records — immutable WORM storage (SEC 17a-4), regulatory evidence packs, cross-org trust verification — see [estoppl.ai](https://estoppl.ai) for the enterprise platform. This proxy is the open-source foundation; the cloud ledger is where compliance certification lives.

## License

Apache 2.0
