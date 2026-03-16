mod config;
mod identity;
mod ledger;
mod mcp;
mod policy;
mod proxy;
mod report;
mod sync;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "estoppl",
    version,
    about = "See what your AI agent is doing. Stop it when it goes wrong."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new estoppl config, keypair, and database in the current directory.
    Init {
        /// Agent identifier (e.g. "treasury-bot-v2").
        #[arg(long, default_value = "my-agent")]
        agent_id: String,
    },

    /// Start the stdio proxy — intercepts MCP tool calls between agent and upstream server process.
    Start {
        /// Command to launch the upstream MCP server.
        #[arg(long)]
        upstream_cmd: String,

        /// Arguments to pass to the upstream command.
        #[arg(long, num_args = 0..)]
        upstream_args: Vec<String>,

        /// Stream signed events to the cloud endpoint configured in estoppl.toml.
        #[arg(long)]
        sync: bool,

        /// Path to estoppl config file.
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },

    /// Start the HTTP proxy — intercepts MCP tool calls over HTTP/SSE (Streamable HTTP transport).
    StartHttp {
        /// URL of the upstream MCP server (e.g. "http://localhost:3000/mcp").
        #[arg(long)]
        upstream_url: String,

        /// Address to listen on (e.g. "127.0.0.1:4100").
        #[arg(long, default_value = "127.0.0.1:4100")]
        listen: String,

        /// Stream signed events to the cloud endpoint configured in estoppl.toml.
        #[arg(long)]
        sync: bool,

        /// Path to estoppl config file.
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },

    /// Generate a local activity report (HTML) from logged events.
    Report {
        /// Output file path.
        #[arg(long, short, default_value = "estoppl-report.html")]
        output: PathBuf,

        /// Path to estoppl config file (for database location).
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },

    /// View and verify the local audit log.
    Audit {
        /// Number of recent events to show.
        #[arg(long, short = 'n', default_value = "20")]
        limit: u32,

        /// Verify hash chain integrity.
        #[arg(long)]
        verify: bool,

        /// Filter by tool name (exact match or use % for wildcard, e.g. "stripe%").
        #[arg(long)]
        tool: Option<String>,

        /// Filter by decision: allow, block, or human_required.
        #[arg(long)]
        decision: Option<String>,

        /// Show events since this timestamp (RFC3339, e.g. "2026-03-01T00:00:00Z").
        #[arg(long)]
        since: Option<String>,

        /// Path to estoppl config file.
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },

    /// Live-stream tool calls as they happen (like tail -f).
    Tail {
        /// Path to estoppl config file.
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },

    /// Show tool call statistics — volume, latency, per-tool breakdown.
    Stats {
        /// Path to estoppl config file.
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { agent_id } => cmd_init(&agent_id)?,
        Commands::Start {
            upstream_cmd,
            upstream_args,
            sync,
            config,
        } => cmd_start(&upstream_cmd, &upstream_args, sync, &config).await?,
        Commands::StartHttp {
            upstream_url,
            listen,
            sync,
            config,
        } => cmd_start_http(&upstream_url, &listen, sync, &config).await?,
        Commands::Report { output, config } => cmd_report(&output, &config)?,
        Commands::Audit {
            limit,
            verify,
            tool,
            decision,
            since,
            config,
        } => cmd_audit(limit, verify, tool, decision, since, &config)?,
        Commands::Tail { config } => cmd_tail(&config).await?,
        Commands::Stats { config } => cmd_stats(&config)?,
    }

    Ok(())
}

fn cmd_init(agent_id: &str) -> Result<()> {
    let config = config::ProxyConfig::generate_default(agent_id);
    let config_path = PathBuf::from("estoppl.toml");

    if config_path.exists() {
        anyhow::bail!("estoppl.toml already exists. Remove it first to reinitialize.");
    }

    // Write config.
    let toml_str = config.to_toml()?;
    std::fs::write(&config_path, &toml_str)?;
    println!("Created estoppl.toml");

    // Generate keypair.
    let key_dir = PathBuf::from(".estoppl/keys");
    let km = identity::KeyManager::load_or_generate(&key_dir)?;
    println!("Generated Ed25519 keypair (key_id: {})", km.key_id);

    // Initialize database.
    let db_path = config.ledger.db_path;
    let _ledger = ledger::LocalLedger::open(&db_path)?;
    println!("Initialized database at {}", db_path.display());

    println!();
    println!("Ready. Start the proxy with:");
    println!("  estoppl start --upstream-cmd <your-mcp-server-command>        (stdio mode)");
    println!("  estoppl start-http --upstream-url <http://host:port/mcp>      (HTTP mode)");
    Ok(())
}

async fn cmd_start(
    upstream_cmd: &str,
    upstream_args: &[String],
    sync_enabled: bool,
    config_path: &Path,
) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    let key_dir = PathBuf::from(".estoppl/keys");
    let key_manager = identity::KeyManager::load_or_generate(&key_dir)?;
    let db_ledger = ledger::LocalLedger::open(&config.ledger.db_path)?;
    let policy_engine = policy::PolicyEngine::new(config.rules.clone());

    tracing::info!(
        agent_id = config.agent.id,
        key_id = key_manager.key_id,
        "Estoppl proxy starting"
    );

    // Start cloud sync background task if --sync is enabled.
    let _sync_handle = maybe_start_sync(sync_enabled, &config)?;

    proxy::run_stdio_proxy(
        upstream_cmd,
        upstream_args,
        &config.agent.id,
        &config.agent.version,
        config.agent.authorized_by.as_deref().unwrap_or("unknown"),
        &key_manager,
        &db_ledger,
        &policy_engine,
    )
    .await
}

async fn cmd_start_http(
    upstream_url: &str,
    listen_addr: &str,
    sync_enabled: bool,
    config_path: &Path,
) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    let key_dir = PathBuf::from(".estoppl/keys");
    let key_manager = identity::KeyManager::load_or_generate(&key_dir)?;
    let db_ledger = ledger::LocalLedger::open(&config.ledger.db_path)?;
    let policy_engine = policy::PolicyEngine::new(config.rules.clone());

    tracing::info!(
        agent_id = config.agent.id,
        key_id = key_manager.key_id,
        listen = listen_addr,
        upstream = upstream_url,
        "Estoppl HTTP proxy starting"
    );

    // Start cloud sync background task if --sync is enabled.
    let _sync_handle = maybe_start_sync(sync_enabled, &config)?;

    proxy::run_http_proxy(
        listen_addr,
        upstream_url,
        &config.agent.id,
        &config.agent.version,
        config.agent.authorized_by.as_deref().unwrap_or("unknown"),
        key_manager,
        db_ledger,
        policy_engine,
    )
    .await
}

/// Start the cloud sync background task if --sync is enabled and cloud_endpoint is configured.
/// Returns the task handle (kept alive by the caller) or None.
fn maybe_start_sync(
    sync_enabled: bool,
    config: &config::ProxyConfig,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    if !sync_enabled {
        return Ok(None);
    }

    let sync_config = sync::sync_config_from_ledger(
        config.ledger.cloud_endpoint.as_deref(),
        config.ledger.cloud_api_key.as_deref(),
    );

    let sync_config = match sync_config {
        Some(c) => c,
        None => {
            anyhow::bail!(
                "--sync requires [ledger] cloud_endpoint in estoppl.toml.\n\
                 Example:\n  [ledger]\n  cloud_endpoint = \"https://api.estoppl.com/v1/events\"\n  cloud_api_key = \"sk_your_key\""
            );
        }
    };

    tracing::info!(endpoint = sync_config.endpoint, "Cloud sync enabled");

    let (_shutdown_tx, shutdown_rx) = sync::shutdown_channel();
    let syncer = sync::CloudSyncer::new(sync_config, config.ledger.db_path.clone(), shutdown_rx);
    let handle = syncer.spawn();

    Ok(Some(handle))
}

fn cmd_report(output: &Path, config_path: &Path) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    let db_ledger = ledger::LocalLedger::open(&config.ledger.db_path)?;

    let html = report::generate_html_report(&db_ledger)?;
    std::fs::write(output, &html)
        .with_context(|| format!("Failed to write report to {}", output.display()))?;

    println!("Report written to {}", output.display());
    Ok(())
}

fn cmd_audit(
    limit: u32,
    verify: bool,
    tool: Option<String>,
    decision: Option<String>,
    since: Option<String>,
    config_path: &Path,
) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    let db_ledger = ledger::LocalLedger::open(&config.ledger.db_path)?;

    if verify {
        let (total, broken) = db_ledger.verify_chain()?;
        if broken.is_empty() {
            println!("Hash chain INTACT — {} events verified", total);
        } else {
            println!(
                "Hash chain BROKEN — {} events, {} issues:",
                total,
                broken.len()
            );
            for issue in &broken {
                println!("  - {}", issue);
            }
        }
        return Ok(());
    }

    let events = db_ledger.query_events_filtered(
        Some(limit),
        None,
        tool.as_deref(),
        decision.as_deref(),
        since.as_deref(),
    )?;

    if events.is_empty() {
        println!("No events found.");
        return Ok(());
    }

    print_event_table(&events);

    let stats = db_ledger.summary_stats()?;
    println!();
    println!(
        "Total: {} | Allowed: {} | Blocked: {} | Human Review: {}",
        stats.total_events, stats.allowed, stats.blocked, stats.human_required
    );

    Ok(())
}

async fn cmd_tail(config_path: &Path) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    let db_path = config.ledger.db_path;

    println!(
        "Tailing events from {}... (Ctrl+C to stop)",
        db_path.display()
    );
    println!();
    println!(
        "{:<10} {:<30} {:<12} {:<22} LATENCY",
        "EVENT", "TOOL", "DECISION", "TIMESTAMP"
    );
    println!("{}", "-".repeat(90));

    // Start from the current end so we only show new events.
    let ledger = ledger::LocalLedger::open(&db_path)?;
    let mut last_rowid = ledger.max_rowid()?;
    drop(ledger);

    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Reopen the connection each poll to see WAL commits from the proxy process.
        let ledger = ledger::LocalLedger::open(&db_path)?;
        let (events, new_rowid) = ledger.events_after_rowid(last_rowid)?;

        for e in &events {
            let decision_colored = match e.policy_decision.as_str() {
                "BLOCK" => format!("\x1b[31m{}\x1b[0m", e.policy_decision),
                "HUMAN_REQUIRED" => format!("\x1b[33m{}\x1b[0m", e.policy_decision),
                _ => e.policy_decision.clone(),
            };
            println!(
                "{:<10} {:<30} {:<21} {:<22} {}ms",
                &e.event_id[..8],
                truncate(&e.tool_name, 28),
                decision_colored,
                e.timestamp.format("%Y-%m-%d %H:%M:%S"),
                e.latency_ms,
            );
        }

        last_rowid = new_rowid;
    }
}

fn cmd_stats(config_path: &Path) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    let db_ledger = ledger::LocalLedger::open(&config.ledger.db_path)?;

    let summary = db_ledger.summary_stats()?;

    if summary.total_events == 0 {
        println!("No events recorded yet.");
        return Ok(());
    }

    // Overall summary.
    println!("=== Overview ===");
    println!("Total events:    {}", summary.total_events);
    println!("  Allowed:       {}", summary.allowed);
    println!("  Blocked:       {}", summary.blocked);
    println!("  Human Review:  {}", summary.human_required);
    println!("Unique tools:    {}", summary.unique_tools);
    println!("Unique agents:   {}", summary.unique_agents);
    if let (Some(first), Some(last)) = (&summary.first_event, &summary.last_event) {
        println!("Time range:      {} → {}", first, last);
    }

    // Latency percentiles.
    let latency = db_ledger.latency_percentiles()?;
    println!();
    println!("=== Latency (allowed calls) ===");
    println!(
        "  p50: {}ms    p90: {}ms    p99: {}ms    max: {}ms",
        latency.p50, latency.p90, latency.p99, latency.max
    );

    // Per-tool breakdown.
    let tool_stats = db_ledger.tool_stats()?;
    if !tool_stats.is_empty() {
        println!();
        println!("=== Per-Tool Breakdown ===");
        println!(
            "{:<30} {:>6} {:>8} {:>8} {:>8} {:>10}",
            "TOOL", "CALLS", "ALLOW", "BLOCK", "HUMAN", "AVG(ms)"
        );
        println!("{}", "-".repeat(80));
        for ts in &tool_stats {
            println!(
                "{:<30} {:>6} {:>8} {:>8} {:>8} {:>10.1}",
                truncate(&ts.tool_name, 28),
                ts.call_count,
                ts.allowed,
                ts.blocked,
                ts.human_required,
                ts.avg_latency_ms,
            );
        }
    }

    // Recent sessions.
    let sessions = db_ledger.session_stats()?;
    if !sessions.is_empty() {
        println!();
        println!("=== Recent Sessions ===");
        println!(
            "{:<10} {:<20} {:>6} {:<22} LAST CALL",
            "SESSION", "AGENT", "CALLS", "STARTED"
        );
        println!("{}", "-".repeat(80));
        for s in &sessions {
            println!(
                "{:<10} {:<20} {:>6} {:<22} {}",
                &s.session_id[..8],
                truncate(&s.agent_id, 18),
                s.call_count,
                &s.first_call[..19],
                &s.last_call[..19],
            );
        }
    }

    Ok(())
}

fn print_event_table(events: &[ledger::AgentActionEvent]) {
    println!(
        "{:<10} {:<30} {:<12} {:<22} LATENCY",
        "EVENT", "TOOL", "DECISION", "TIMESTAMP"
    );
    println!("{}", "-".repeat(90));

    for e in events {
        println!(
            "{:<10} {:<30} {:<12} {:<22} {}ms",
            &e.event_id[..8],
            truncate(&e.tool_name, 28),
            e.policy_decision,
            e.timestamp.format("%Y-%m-%d %H:%M:%S"),
            e.latency_ms,
        );
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}
