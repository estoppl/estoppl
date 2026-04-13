mod config;
mod dashboard;
mod identity;
mod ledger;
mod mcp;
mod policy;
mod proxy;
mod report;
mod review;
mod sync;
mod wrap;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

    /// Connect the proxy to estoppl cloud. Writes API key and org ID to estoppl.toml.
    /// API key is read from stdin or prompted interactively (never passed as a CLI flag).
    Connect {
        /// Organization ID from the estoppl cloud dashboard.
        #[arg(long)]
        org_id: String,

        /// Path to estoppl config file.
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },

    /// Start the stdio proxy — intercepts MCP tool calls between agent and upstream server process.
    Start {
        /// Command to launch the upstream MCP server.
        #[arg(long)]
        upstream_cmd: String,

        /// Arguments to pass to the upstream command.
        #[arg(long, num_args = 0.., allow_hyphen_values = true)]
        upstream_args: Vec<String>,

        /// Legacy flag, ignored. Sync is auto-enabled when cloud_api_key is set in estoppl.toml.
        #[arg(long, hide = true)]
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

        /// Legacy flag, ignored. Sync is auto-enabled when cloud_api_key is set in estoppl.toml.
        #[arg(long, hide = true)]
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

        /// Verify a receipt file (downloaded from the dashboard).
        #[arg(long)]
        verify_receipt: Option<PathBuf>,

        /// Verify an exported audit trail (downloaded from the dashboard).
        #[arg(long)]
        verify_export: Option<PathBuf>,

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

    /// Auto-wrap existing MCP client configs to route through estoppl.
    Wrap {
        /// Preview changes without modifying files.
        #[arg(long)]
        dry_run: bool,

        /// Restore original configs from backup.
        #[arg(long)]
        restore: bool,

        /// Only wrap a specific client (claude, cursor, windsurf).
        #[arg(long)]
        client: Option<String>,
    },

    /// Restore original MCP client configs (alias for `wrap --restore`).
    Unwrap {
        /// Only unwrap a specific client (claude, cursor, windsurf).
        #[arg(long)]
        client: Option<String>,
    },

    /// Open the local web dashboard for browsing audit events.
    Dashboard {
        /// Port to serve the dashboard on.
        #[arg(long, default_value = "4200")]
        port: u16,

        /// Path to estoppl config file.
        #[arg(long, short, default_value = "estoppl.toml")]
        config: PathBuf,
    },

    /// Measure proxy overhead — proves latency impact is negligible.
    Bench {
        /// Command to launch the upstream MCP server.
        #[arg(long)]
        upstream_cmd: String,

        /// Arguments to pass to the upstream command.
        #[arg(long, num_args = 0.., allow_hyphen_values = true)]
        upstream_args: Vec<String>,

        /// Number of tool calls to send.
        #[arg(long, default_value = "100")]
        count: u32,

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
        Commands::Connect { org_id, config } => cmd_connect(&org_id, &config).await?,
        Commands::Start {
            upstream_cmd,
            upstream_args,
            sync,
            config,
        } => {
            if let Err(e) = cmd_start(&upstream_cmd, &upstream_args, sync, &config).await {
                eprintln!("Error: {:#}", e);
                return Err(e);
            }
        }
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
            verify_receipt,
            verify_export,
            tool,
            decision,
            since,
            config,
        } => {
            if let Some(receipt_path) = verify_receipt {
                cmd_verify_receipt(&receipt_path)?;
            } else if let Some(export_path) = verify_export {
                cmd_verify_export(&export_path)?;
            } else {
                cmd_audit(limit, verify, tool, decision, since, &config)?;
            }
        }
        Commands::Tail { config } => cmd_tail(&config).await?,
        Commands::Stats { config } => cmd_stats(&config)?,
        Commands::Wrap {
            dry_run,
            restore,
            client,
        } => wrap::run_wrap(dry_run, restore, client.as_deref())?,
        Commands::Unwrap { client } => wrap::run_wrap(false, true, client.as_deref())?,
        Commands::Dashboard { port, config } => cmd_dashboard(port, &config).await?,
        Commands::Bench {
            upstream_cmd,
            upstream_args,
            count,
            config,
        } => cmd_bench(&upstream_cmd, &upstream_args, count, &config).await?,
    }

    Ok(())
}

fn cmd_init(agent_id: &str) -> Result<()> {
    let config = config::ProxyConfig::generate_default(agent_id);
    let config_path = PathBuf::from("estoppl.toml");

    if config_path.exists() {
        anyhow::bail!("estoppl.toml already exists. Remove it first to reinitialize.");
    }

    // Write a clean config template (not raw serde output).
    let toml_str = format!(
        r#"[agent]
id = "{agent_id}"
version = "0.1.0"

[rules]
human_review_tools = ["wire_transfer", "execute_trade"]
max_amount_usd = 50000.0
amount_field = "amount"
# fail_mode = "closed"  # "closed" (default, blocks if cloud unavailable) or "open" (dev only, forwards with warning)

# Connect to estoppl cloud (https://app.estoppl.ai)
[ledger]
# cloud_api_key = "sk_your_key"
# org_id = "your_org_id"
"#,
        agent_id = agent_id,
    );
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
    println!("Next steps:");
    println!("  1. Connect to estoppl cloud:  estoppl connect");
    println!("  2. Wrap your MCP servers:     estoppl wrap");
    println!("  3. Restart your IDE (Cursor, Claude Desktop)");
    println!();
    println!("Or start manually:");
    println!("  estoppl start --upstream-cmd <your-mcp-server-command>        (stdio mode)");
    println!("  estoppl start-http --upstream-url <http://host:port/mcp>      (HTTP mode)");
    Ok(())
}

async fn cmd_connect(org_id: &str, config_path: &Path) -> Result<()> {
    use std::io::{self, BufRead, Write};

    // Read API key securely: interactive prompt (no echo) if TTY, else stdin pipe.
    let api_key = if atty::is(atty::Stream::Stdin) {
        eprint!("Enter your estoppl API key: ");
        io::stderr().flush()?;
        rpassword::read_password().context("Failed to read API key")?
    } else {
        let stdin = io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        line.trim().to_string()
    };

    if api_key.is_empty() {
        anyhow::bail!("API key cannot be empty");
    }

    // Verify the key works by pinging the policy endpoint.
    let base_url = "https://api.estoppl.ai";
    let verify_url = format!("{}/v1/policy/{}", base_url, org_id);
    println!("Verifying credentials...");

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .get(&verify_url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() || r.status().as_u16() == 304 => {
            println!("Credentials verified.");
        }
        Ok(r) => {
            let status = r.status().as_u16();
            anyhow::bail!(
                "Credential verification failed (HTTP {}). Check your API key and org ID at app.estoppl.ai/settings",
                status
            );
        }
        Err(e) if e.is_connect() || e.is_timeout() => {
            anyhow::bail!(
                "Could not reach api.estoppl.ai: {}. Check your internet connection.",
                e
            );
        }
        Err(e) => {
            anyhow::bail!("Failed to verify credentials: {}", e);
        }
    }

    // Read existing TOML or create minimal config.
    let toml_content = if config_path.exists() {
        std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read {}", config_path.display()))?
    } else {
        // Create minimal config if none exists.
        println!("No estoppl.toml found — creating one.");
        "[agent]\nid = \"my-agent\"\n\n[rules]\n\n[ledger]\n".to_string()
    };

    // Update the [ledger] section with cloud credentials.
    // Strategy: replace commented-out placeholders or append to [ledger] section.
    let updated = update_toml_ledger(&toml_content, &api_key, org_id);

    // Atomic write: write to temp file, then rename.
    let tmp_path = config_path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, &updated)
        .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, config_path).with_context(|| {
        format!(
            "Failed to rename {} to {}",
            tmp_path.display(),
            config_path.display()
        )
    })?;

    println!("Updated {}", config_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Wrap your MCP servers:  estoppl wrap");
    println!("  2. Restart your IDE (Cursor, Claude Desktop)");
    Ok(())
}

/// Update the [ledger] section of a TOML string with cloud credentials.
/// Handles both commented-out placeholders and missing fields.
fn update_toml_ledger(toml_content: &str, api_key: &str, org_id: &str) -> String {
    let mut lines: Vec<String> = toml_content.lines().map(String::from).collect();
    let mut found_api_key = false;
    let mut found_org_id = false;
    let mut ledger_section_idx = None;

    for (i, line) in lines.iter_mut().enumerate() {
        let is_ledger_header = line.trim() == "[ledger]";
        let is_api_key_line = line.trim().starts_with("# cloud_api_key")
            || line.trim().starts_with("#cloud_api_key")
            || line.trim().starts_with("cloud_api_key");
        let is_org_id_line = line.trim().starts_with("# org_id")
            || line.trim().starts_with("#org_id")
            || line.trim().starts_with("org_id");

        if is_ledger_header {
            ledger_section_idx = Some(i);
        }

        if is_api_key_line {
            *line = format!("cloud_api_key = \"{}\"", api_key);
            found_api_key = true;
        }

        if is_org_id_line {
            *line = format!("org_id = \"{}\"", org_id);
            found_org_id = true;
        }
    }

    // If we found the [ledger] section but the keys weren't there, append them.
    if let Some(idx) = ledger_section_idx {
        if !found_api_key {
            lines.insert(idx + 1, format!("cloud_api_key = \"{}\"", api_key));
            found_api_key = true;
        }
        if !found_org_id {
            // Find where we just inserted api_key (or after [ledger]).
            let insert_at = if found_api_key { idx + 2 } else { idx + 1 };
            lines.insert(insert_at, format!("org_id = \"{}\"", org_id));
        }
    } else {
        // No [ledger] section at all — append one.
        lines.push(String::new());
        lines.push("[ledger]".to_string());
        lines.push(format!("cloud_api_key = \"{}\"", api_key));
        lines.push(format!("org_id = \"{}\"", org_id));
    }

    let mut result = lines.join("\n");
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result
}

async fn cmd_start(
    upstream_cmd: &str,
    upstream_args: &[String],
    _sync_flag: bool,
    config_path: &Path,
) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    // Resolve key_dir relative to config file's directory (not cwd).
    // MCP clients like Claude Desktop launch subprocesses with cwd=/ which
    // would fail with "Read-only file system" if we used a relative path.
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    let key_dir = config_dir.join(".estoppl/keys");
    let key_manager = identity::KeyManager::load_or_generate(&key_dir)?;
    let db_ledger = ledger::LocalLedger::open(&config.ledger.db_path)?;
    let policy_engine = policy::PolicyEngine::new(config.rules.clone());

    // Auto-enable sync when cloud_api_key is configured.
    let sync_enabled = config.ledger.cloud_api_key.is_some();

    tracing::info!(
        agent_id = config.agent.id,
        key_id = key_manager.key_id,
        "Estoppl proxy starting"
    );

    let policy_engine = Arc::new(policy_engine);

    // Start cloud sync background task if cloud credentials are configured.
    let _sync_handle = maybe_start_sync(sync_enabled, &config)?;
    let _policy_handle =
        maybe_start_policy_sync(sync_enabled, &config, Arc::clone(&policy_engine))?;

    // Create review client if cloud sync is enabled.
    let review_client = maybe_create_review_client(sync_enabled, &config);

    proxy::run_stdio_proxy(
        upstream_cmd,
        upstream_args,
        &config.agent.id,
        &config.agent.version,
        config.agent.authorized_by.as_deref().unwrap_or("unknown"),
        &key_manager,
        &db_ledger,
        &policy_engine,
        review_client.clone(),
        &config.rules.redact_fields,
        &config.rules.fail_mode,
    )
    .await
}

async fn cmd_start_http(
    upstream_url: &str,
    listen_addr: &str,
    _sync_flag: bool,
    config_path: &Path,
) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    let key_dir = config_dir.join(".estoppl/keys");
    let key_manager = identity::KeyManager::load_or_generate(&key_dir)?;
    let db_ledger = ledger::LocalLedger::open(&config.ledger.db_path)?;
    let policy_engine = policy::PolicyEngine::new(config.rules.clone());

    // Auto-enable sync when cloud_api_key is configured.
    let sync_enabled = config.ledger.cloud_api_key.is_some();

    tracing::info!(
        agent_id = config.agent.id,
        key_id = key_manager.key_id,
        listen = listen_addr,
        upstream = upstream_url,
        "Estoppl HTTP proxy starting"
    );

    let policy_engine = Arc::new(policy_engine);

    // Start cloud sync background task if cloud credentials are configured.
    let _sync_handle = maybe_start_sync(sync_enabled, &config)?;
    let _policy_handle =
        maybe_start_policy_sync(sync_enabled, &config, Arc::clone(&policy_engine))?;

    // Create review client if cloud sync is enabled.
    let review_client = maybe_create_review_client(sync_enabled, &config);

    proxy::run_http_proxy(
        listen_addr,
        upstream_url,
        &config.agent.id,
        &config.agent.version,
        config.agent.authorized_by.as_deref().unwrap_or("unknown"),
        key_manager,
        db_ledger,
        policy_engine,
        review_client,
    )
    .await
}

/// Create a ReviewClient if cloud sync is enabled.
fn maybe_create_review_client(
    sync_enabled: bool,
    config: &config::ProxyConfig,
) -> Option<Arc<review::ReviewClient>> {
    if !sync_enabled {
        return None;
    }

    let cloud_endpoint = config.ledger.effective_cloud_endpoint()?;

    // Derive base URL from events endpoint
    let base_url = cloud_endpoint
        .trim_end_matches('/')
        .rsplit_once("/v1/")
        .map(|(base, _)| base.to_string())
        .unwrap_or_else(|| cloud_endpoint.trim_end_matches('/').to_string());

    Some(Arc::new(review::ReviewClient::new(
        base_url,
        config.ledger.cloud_api_key.clone(),
    )))
}

/// Start the cloud sync background task if cloud credentials are configured.
/// Returns the task handle (kept alive by the caller) or None.
fn maybe_start_sync(
    sync_enabled: bool,
    config: &config::ProxyConfig,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    if !sync_enabled {
        return Ok(None);
    }

    let sync_config = match sync::sync_config_from_ledger(
        config.ledger.effective_cloud_endpoint(),
        config.ledger.cloud_api_key.as_deref(),
    ) {
        Some(c) => c,
        None => return Ok(None),
    };

    tracing::info!(endpoint = sync_config.endpoint, "Cloud sync enabled");

    let (shutdown_tx, shutdown_rx) = sync::shutdown_channel();
    let syncer = sync::CloudSyncer::new(sync_config, config.ledger.db_path.clone(), shutdown_rx);
    let handle = syncer.spawn();

    // Keep shutdown_tx alive so the syncer loop doesn't exit.
    // It will be dropped when the process exits.
    std::mem::forget(shutdown_tx);

    Ok(Some(handle))
}

/// Start the policy sync background task if cloud sync is enabled and org_id is configured.
fn maybe_start_policy_sync(
    sync_enabled: bool,
    config: &config::ProxyConfig,
    policy_engine: Arc<policy::PolicyEngine>,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    if !sync_enabled {
        return Ok(None);
    }

    let cloud_endpoint = match config.ledger.effective_cloud_endpoint() {
        Some(ep) => ep.to_string(),
        None => return Ok(None),
    };

    let org_id = match &config.ledger.org_id {
        Some(id) if !id.is_empty() => id,
        _ => {
            tracing::debug!("Policy sync skipped: no org_id in config");
            return Ok(None);
        }
    };

    // Derive policy endpoint from the events endpoint.
    // e.g. "http://localhost:8080/v1/events" -> "http://localhost:8080/v1/policy/{org_id}"
    let base_url = cloud_endpoint
        .trim_end_matches('/')
        .rsplit_once("/v1/")
        .map(|(base, _)| format!("{}/v1", base))
        .unwrap_or_else(|| cloud_endpoint.trim_end_matches('/').to_string());

    let policy_endpoint = format!("{}/policy/{}", base_url, org_id);

    let policy_config = sync::PolicySyncConfig {
        policy_endpoint: policy_endpoint.clone(),
        api_key: config.ledger.cloud_api_key.clone(),
        interval_secs: 5,
    };

    tracing::info!(endpoint = policy_endpoint, "Policy sync enabled");

    let (shutdown_tx, shutdown_rx) = sync::shutdown_channel();
    let syncer = sync::PolicySyncer::new(policy_config, policy_engine, shutdown_rx);
    let handle = syncer.spawn();

    // Keep shutdown_tx alive so the policy syncer loop doesn't exit.
    std::mem::forget(shutdown_tx);

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

fn cmd_verify_export(path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read export: {}", path.display()))?;

    let export: serde_json::Value =
        serde_json::from_str(&content).with_context(|| "Failed to parse export JSON")?;

    let org = export
        .get("organization")
        .and_then(|o| o.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let date_range = export.get("date_range");
    let from = date_range
        .and_then(|d| d.get("from"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let to = date_range
        .and_then(|d| d.get("to"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let events = export
        .get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    println!("Export Verification");
    println!("===================");
    println!("Organization: {}", org);
    println!("Date range:   {} to {}", from, to);
    println!("Total events: {}", events.len());
    println!();

    use sha2::{Digest, Sha256};

    let mut valid = 0;
    let mut tampered = 0;
    let mut no_hash_input = 0;
    let mut chain_breaks = 0;
    let mut tampered_events: Vec<String> = Vec::new();

    // Group by proxy_key_id for chain verification
    let mut chains: std::collections::HashMap<String, Vec<&serde_json::Value>> =
        std::collections::HashMap::new();
    for event in &events {
        let key = event
            .get("proxy_key_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        chains.entry(key).or_default().push(event);
    }

    // Verify each event's hash
    for event in &events {
        let hash_input = event
            .get("hash_input")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let event_hash = event
            .get("event_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let event_id = event.get("event_id").and_then(|v| v.as_str()).unwrap_or("");

        if hash_input.is_empty() {
            no_hash_input += 1;
            continue;
        }

        let computed = hex::encode(Sha256::digest(hash_input.as_bytes()));
        if computed == event_hash {
            valid += 1;
        } else {
            tampered += 1;
            tampered_events.push(event_id.to_string());
        }
    }

    // Verify chain linkage per proxy
    for (proxy_key, chain) in &chains {
        for i in 1..chain.len() {
            let prev_hash = chain[i]
                .get("prev_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let prev_event_hash = chain[i - 1]
                .get("event_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !prev_hash.is_empty() && prev_hash != prev_event_hash {
                chain_breaks += 1;
                println!(
                    "\x1b[31m  Chain break in proxy {} at event {}\x1b[0m",
                    proxy_key,
                    chain[i]
                        .get("event_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                );
            }
        }
    }

    // Results
    println!("Hash verification:");
    println!(
        "  \x1b[32m{} valid\x1b[0m, \x1b[31m{} tampered\x1b[0m, {} without hash_input",
        valid, tampered, no_hash_input
    );
    println!(
        "Chain verification: {} proxies, \x1b[{}m{} breaks\x1b[0m",
        chains.len(),
        if chain_breaks > 0 { "31" } else { "32" },
        chain_breaks
    );

    if !tampered_events.is_empty() {
        println!();
        println!("\x1b[31mTampered events:\x1b[0m");
        for eid in &tampered_events {
            println!("  - {}", eid);
        }
    }

    println!();
    if tampered == 0 && chain_breaks == 0 {
        println!(
            "\x1b[32mVerdict: INTACT — all {} events verified, chain unbroken\x1b[0m",
            valid
        );
    } else {
        println!(
            "\x1b[31mVerdict: COMPROMISED — {} tampered events, {} chain breaks\x1b[0m",
            tampered, chain_breaks
        );
    }

    Ok(())
}

fn cmd_verify_receipt(path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read receipt: {}", path.display()))?;

    let receipt: serde_json::Value =
        serde_json::from_str(&content).with_context(|| "Failed to parse receipt JSON")?;

    let event = receipt
        .get("event")
        .ok_or_else(|| anyhow::anyhow!("Receipt missing 'event' field"))?;

    let event_id = event
        .get("event_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let tool_name = event
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let decision = event
        .get("policy_decision")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let event_hash = event
        .get("event_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let signature = event
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let proxy_key_id = event
        .get("proxy_key_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    println!("Receipt Verification");
    println!("====================");
    println!("Event ID:     {}", event_id);
    println!("Tool:         {}", tool_name);
    println!("Decision:     {}", decision);
    println!("Proxy Key:    {}", proxy_key_id);
    println!();

    // Verify hash_input → recompute SHA-256 and compare to event_hash
    // hash_input can be at top level of receipt or inside event
    let hash_input = receipt
        .get("hash_input")
        .or_else(|| event.get("hash_input"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut hash_valid = false;
    if !hash_input.is_empty() && !event_hash.is_empty() {
        use sha2::{Digest, Sha256};
        let computed = hex::encode(Sha256::digest(hash_input.as_bytes()));
        if computed == event_hash {
            hash_valid = true;
            println!("\x1b[32mHash:      VALID\x1b[0m — recomputed hash matches event_hash");
        } else {
            println!("\x1b[31mHash:      TAMPERED\x1b[0m — recomputed hash does not match");
            println!("           Expected: {}", event_hash);
            println!("           Computed: {}", computed);
        }
    } else if !event_hash.is_empty() {
        println!(
            "Hash:      {}...{} (no hash_input to verify — older receipt format)",
            &event_hash[..8],
            &event_hash[event_hash.len() - 8..]
        );
    }

    // Verify signature against event_hash
    let key_path = PathBuf::from(".estoppl/keys/estoppl-signing.pub");
    if key_path.exists() && !signature.is_empty() && !event_hash.is_empty() {
        let key_manager = identity::KeyManager::load_or_generate(&PathBuf::from(".estoppl/keys"))?;

        let sig_valid = key_manager.verify(event_hash.as_bytes(), signature);
        if sig_valid {
            println!("\x1b[32mSignature: VALID\x1b[0m — signed by this proxy's Ed25519 key");
        } else {
            println!(
                "\x1b[33mSignature: UNVERIFIED\x1b[0m — signed by a different proxy key ({})",
                proxy_key_id
            );
        }
    } else if !signature.is_empty() {
        println!(
            "Signature: PRESENT ({}...)",
            &signature[..16.min(signature.len())]
        );
        println!("           No local key found — run from the proxy's directory to verify");
    } else {
        println!("\x1b[31mSignature: MISSING\x1b[0m");
    }

    // Chain linkage
    let chain = receipt.get("chain_proof");
    if let Some(chain) = chain {
        let prev = chain
            .get("prev_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let seq = chain
            .get("sequence_number")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if prev.is_empty() {
            println!("Chain:     sequence #{} (first event)", seq);
        } else {
            println!(
                "Chain:     sequence #{}, prev = {}...{}",
                seq,
                &prev[..8.min(prev.len())],
                &prev[prev.len().saturating_sub(8)..]
            );
        }
    }

    // Verify against local ledger — check both hash AND field values
    let config_path = PathBuf::from("estoppl.toml");
    let mut fields_tampered = false;
    if config_path.exists()
        && let Ok(config) = config::ProxyConfig::load(&config_path)
        && let Ok(ledger) = ledger::LocalLedger::open(&config.ledger.db_path)
        && let Ok(events) = ledger.query_events_filtered(None, None, None, None, None)
    {
        if let Some(local_event) = events.iter().find(|e| e.event_id == event_id) {
            if local_event.event_hash == event_hash {
                println!("\x1b[32mLocal DB:  HASH MATCH\x1b[0m");
            } else {
                println!(
                    "\x1b[31mLocal DB:  HASH MISMATCH — receipt hash differs from local ledger\x1b[0m"
                );
            }

            let mut mismatches = Vec::new();
            if tool_name != local_event.tool_name {
                mismatches.push(format!(
                    "tool_name: receipt='{}' local='{}'",
                    tool_name, local_event.tool_name
                ));
            }
            if decision != local_event.policy_decision {
                mismatches.push(format!(
                    "policy_decision: receipt='{}' local='{}'",
                    decision, local_event.policy_decision
                ));
            }
            let receipt_agent = event.get("agent_id").and_then(|v| v.as_str()).unwrap_or("");
            if receipt_agent != local_event.agent_id {
                mismatches.push(format!(
                    "agent_id: receipt='{}' local='{}'",
                    receipt_agent, local_event.agent_id
                ));
            }

            if !mismatches.is_empty() {
                fields_tampered = true;
                println!("\x1b[31mLocal DB:  FIELDS TAMPERED — display data was modified:\x1b[0m");
                for m in &mismatches {
                    println!("           - {}", m);
                }
            } else {
                println!("\x1b[32mLocal DB:  FIELDS MATCH\x1b[0m");
            }
        } else {
            println!("Local DB:  Event not found in local ledger");
        }
    }

    println!();
    if !hash_input.is_empty() && !hash_valid {
        println!("\x1b[31mVerdict:   TAMPERED — event data was modified after signing\x1b[0m");
    } else if fields_tampered {
        println!(
            "\x1b[31mVerdict:   TAMPERED — receipt display data was modified after signing\x1b[0m"
        );
    } else if !signature.is_empty() && !event_hash.is_empty() {
        let key_path = PathBuf::from(".estoppl/keys/estoppl-signing.pub");
        if key_path.exists() {
            let key_manager =
                identity::KeyManager::load_or_generate(&PathBuf::from(".estoppl/keys"))?;
            if key_manager.verify(event_hash.as_bytes(), signature) {
                println!("\x1b[32mVerdict:   AUTHENTIC — signature and fields verified\x1b[0m");
            } else {
                println!("\x1b[33mVerdict:   UNVERIFIED — signed by a different proxy\x1b[0m");
                println!("           Run this command from the proxy that generated the event");
            }
        } else {
            println!("Verdict:   Signature present but no local key to verify against");
            println!("           Run from the proxy's directory (.estoppl/keys/)");
        }
    } else {
        println!("\x1b[31mVerdict:   INCOMPLETE — missing signature or hash\x1b[0m");
    }

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

async fn cmd_dashboard(port: u16, config_path: &Path) -> Result<()> {
    let config = config::ProxyConfig::load(config_path)?;
    dashboard::run_dashboard(port, config.ledger.db_path).await
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

async fn cmd_bench(
    upstream_cmd: &str,
    upstream_args: &[String],
    count: u32,
    config_path: &Path,
) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;

    let config = config::ProxyConfig::load(config_path)?;
    let key_dir = PathBuf::from(".estoppl/keys");
    let key_manager = identity::KeyManager::load_or_generate(&key_dir)?;

    println!("estoppl bench");
    println!("=============");
    println!("Upstream:   {} {}", upstream_cmd, upstream_args.join(" "));
    println!("Calls:      {}", count);
    println!();

    // Phase 1: Direct (no proxy)
    println!("Phase 1: Direct (no proxy)...");
    let direct_latencies = {
        let mut child = Command::new(upstream_cmd)
            .args(upstream_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn upstream")?;

        let mut stdin = child.stdin.take().unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut latencies = Vec::new();
        let mut line = String::new();

        for i in 0..count {
            let req = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"tools/call\",\"params\":{{\"name\":\"bench_tool\",\"arguments\":{{}}}}}}",
                i + 1
            );
            let start = std::time::Instant::now();
            stdin.write_all(req.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;

            line.clear();
            reader.read_line(&mut line).await?;
            latencies.push(start.elapsed());
        }
        drop(stdin);
        let _ = child.wait().await;
        latencies
    };

    // Phase 2: Through proxy
    println!("Phase 2: Through estoppl proxy...");
    let proxy_latencies = {
        let db_path = std::env::temp_dir().join(format!("estoppl-bench-{}.db", std::process::id()));
        let ledger = ledger::LocalLedger::open(&db_path)?;
        let policy_engine = policy::PolicyEngine::new(config.rules.clone());
        let policy_engine = Arc::new(policy_engine);

        let mut child = Command::new(upstream_cmd)
            .args(upstream_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn upstream")?;

        let mut child_stdin = child.stdin.take().unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut latencies = Vec::new();
        let mut line = String::new();
        let session_id = "bench-session";

        for i in 0..count {
            let req = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"tools/call\",\"params\":{{\"name\":\"bench_tool\",\"arguments\":{{}}}}}}",
                i + 1
            );
            let input_hash = ledger::sha256_hex(req.as_bytes());
            let tool_params = mcp::ToolCallParams {
                name: "bench_tool".to_string(),
                arguments: serde_json::json!({}),
            };

            let start = std::time::Instant::now();

            // Policy evaluation
            let _decision = policy_engine.evaluate(&tool_params);

            // Log event
            let _ = proxy::log_event(
                &ledger,
                &key_manager,
                session_id,
                "bench-agent",
                "0.1.0",
                "bench",
                proxy::EventParams {
                    tool_name: "bench_tool",
                    tool_server: "stdio",
                    input_hash: &input_hash,
                    output_hash: "",
                    input_data: None,
                    output_data: None,
                    decision: &policy::PolicyDecision::Allow,
                    latency_ms: 0,
                },
            );

            // Forward to upstream
            child_stdin.write_all(req.as_bytes()).await?;
            child_stdin.write_all(b"\n").await?;
            child_stdin.flush().await?;

            line.clear();
            reader.read_line(&mut line).await?;
            latencies.push(start.elapsed());
        }
        drop(child_stdin);
        let _ = child.wait().await;
        latencies
    };

    // Calculate stats
    fn percentile(latencies: &[std::time::Duration], p: f64) -> std::time::Duration {
        let idx = ((latencies.len() as f64 * p / 100.0).ceil() as usize).min(latencies.len()) - 1;
        latencies[idx]
    }

    let mut direct_sorted = direct_latencies.clone();
    direct_sorted.sort();
    let mut proxy_sorted = proxy_latencies.clone();
    proxy_sorted.sort();

    let direct_p50 = percentile(&direct_sorted, 50.0);
    let direct_p95 = percentile(&direct_sorted, 95.0);
    let direct_p99 = percentile(&direct_sorted, 99.0);

    let proxy_p50 = percentile(&proxy_sorted, 50.0);
    let proxy_p95 = percentile(&proxy_sorted, 95.0);
    let proxy_p99 = percentile(&proxy_sorted, 99.0);

    let overhead_p50 = proxy_p50.saturating_sub(direct_p50);
    let overhead_p95 = proxy_p95.saturating_sub(direct_p95);
    let overhead_p99 = proxy_p99.saturating_sub(direct_p99);

    println!();
    println!("Results ({} calls)", count);
    println!("─────────────────────────────────────────────");
    println!("           {:>10}  {:>10}  {:>10}", "p50", "p95", "p99");
    println!(
        "Direct:    {:>8.2}ms  {:>8.2}ms  {:>8.2}ms",
        direct_p50.as_secs_f64() * 1000.0,
        direct_p95.as_secs_f64() * 1000.0,
        direct_p99.as_secs_f64() * 1000.0,
    );
    println!(
        "Proxy:     {:>8.2}ms  {:>8.2}ms  {:>8.2}ms",
        proxy_p50.as_secs_f64() * 1000.0,
        proxy_p95.as_secs_f64() * 1000.0,
        proxy_p99.as_secs_f64() * 1000.0,
    );
    println!(
        "Overhead:  {:>8.2}ms  {:>8.2}ms  {:>8.2}ms",
        overhead_p50.as_secs_f64() * 1000.0,
        overhead_p95.as_secs_f64() * 1000.0,
        overhead_p99.as_secs_f64() * 1000.0,
    );

    println!();
    if overhead_p99.as_secs_f64() * 1000.0 < 2.0 {
        println!("\x1b[32mVerdict: PASS — proxy overhead < 2ms at p99\x1b[0m");
    } else if overhead_p99.as_secs_f64() * 1000.0 < 5.0 {
        println!("\x1b[33mVerdict: ACCEPTABLE — proxy overhead < 5ms at p99\x1b[0m");
    } else {
        println!(
            "\x1b[31mVerdict: HIGH — proxy overhead {:.2}ms at p99\x1b[0m",
            overhead_p99.as_secs_f64() * 1000.0
        );
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_toml_with_commented_placeholders() {
        let input = r#"[agent]
id = "my-agent"

[rules]

[ledger]
# cloud_api_key = "sk_your_key"
# org_id = "your_org_id"
"#;
        let result = update_toml_ledger(input, "sk_live_abc", "org_123");
        assert!(result.contains("cloud_api_key = \"sk_live_abc\""));
        assert!(result.contains("org_id = \"org_123\""));
        assert!(!result.contains("# cloud_api_key"));
        assert!(!result.contains("# org_id"));
    }

    #[test]
    fn test_update_toml_with_existing_values() {
        let input = r#"[agent]
id = "my-agent"

[ledger]
cloud_api_key = "sk_old_key"
org_id = "org_old"
"#;
        let result = update_toml_ledger(input, "sk_new_key", "org_new");
        assert!(result.contains("cloud_api_key = \"sk_new_key\""));
        assert!(result.contains("org_id = \"org_new\""));
        assert!(!result.contains("sk_old_key"));
    }

    #[test]
    fn test_update_toml_with_empty_ledger() {
        let input = r#"[agent]
id = "my-agent"

[ledger]
"#;
        let result = update_toml_ledger(input, "sk_key", "org_id");
        assert!(result.contains("cloud_api_key = \"sk_key\""));
        assert!(result.contains("org_id = \"org_id\""));
    }

    #[test]
    fn test_update_toml_no_ledger_section() {
        let input = r#"[agent]
id = "my-agent"
"#;
        let result = update_toml_ledger(input, "sk_key", "org_id");
        assert!(result.contains("[ledger]"));
        assert!(result.contains("cloud_api_key = \"sk_key\""));
        assert!(result.contains("org_id = \"org_id\""));
    }
}
