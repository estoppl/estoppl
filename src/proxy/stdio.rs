use anyhow::{Context, Result};
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use uuid::Uuid;

use crate::identity::KeyManager;
use crate::ledger::{LocalLedger, sha256_hex};
use crate::mcp::{JsonRpcRequest, JsonRpcResponse, ToolCallParams};
use crate::policy::{PolicyDecision, PolicyEngine};

/// Tracks an in-flight tools/call request so we can log the response too.
struct PendingCall {
    tool_name: String,
    #[allow(dead_code)]
    tool_params: Option<ToolCallParams>,
    input_hash: String,
    start: std::time::Instant,
    decision: PolicyDecision,
}

/// Run the stdio proxy: sits between the agent host and the upstream MCP server process.
///
/// The agent host writes JSON-RPC to our stdin, we intercept tools/call requests,
/// enforce policy, forward allowed calls to the upstream process, and log everything.
#[allow(clippy::too_many_arguments)]
pub async fn run_stdio_proxy(
    upstream_cmd: &str,
    upstream_args: &[String],
    agent_id: &str,
    agent_version: &str,
    authorized_by: &str,
    key_manager: &KeyManager,
    ledger: &LocalLedger,
    policy: &PolicyEngine,
) -> Result<()> {
    let session_id = Uuid::now_v7().to_string();

    tracing::info!(
        agent_id = agent_id,
        session_id = session_id,
        upstream = upstream_cmd,
        "Starting stdio proxy"
    );

    // Spawn the upstream MCP server process.
    let mut child = Command::new(upstream_cmd)
        .args(upstream_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "Failed to spawn upstream: {} {:?}",
                upstream_cmd, upstream_args
            )
        })?;

    let mut child_stdin = child
        .stdin
        .take()
        .context("Failed to capture child stdin")?;
    let child_stdout = child
        .stdout
        .take()
        .context("Failed to capture child stdout")?;

    let mut host_stdin = BufReader::new(tokio::io::stdin());
    let mut host_stdout = tokio::io::stdout();
    let mut upstream_reader = BufReader::new(child_stdout);

    // Track pending tools/call requests by their JSON-RPC id.
    let mut pending: HashMap<String, PendingCall> = HashMap::new();

    let mut host_line = String::new();
    let mut upstream_line = String::new();

    loop {
        tokio::select! {
            // Read from agent host (our stdin).
            result = host_stdin.read_line(&mut host_line) => {
                let n = result.context("Failed to read from stdin")?;
                if n == 0 {
                    tracing::info!("Agent host closed stdin");
                    break;
                }

                let trimmed = host_line.trim();
                if !trimmed.is_empty()
                    && let Ok(req) = serde_json::from_str::<JsonRpcRequest>(trimmed)
                    && req.is_tool_call()
                {
                    let tool_params = req.tool_call_params();
                    let tool_name = tool_params
                        .as_ref()
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    let input_hash = sha256_hex(trimmed.as_bytes());

                    // Evaluate policy.
                    let decision = tool_params
                        .as_ref()
                        .map(|p| policy.evaluate(p))
                        .unwrap_or(PolicyDecision::Allow);

                    let req_id_key = req
                        .id
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_default();

                    tracing::info!(
                        tool = tool_name,
                        decision = decision.as_str(),
                        "Intercepted tools/call"
                    );

                    match &decision {
                        PolicyDecision::Block { rule } => {
                            // Don't forward to upstream. Send error response to host.
                            let err_resp = JsonRpcResponse::error(
                                req.id.clone(),
                                -32001,
                                format!("Blocked by policy: {}", rule),
                            );
                            let err_json = serde_json::to_string(&err_resp)?;

                            // Log the blocked call.
                            super::log_event(
                                ledger,
                                key_manager,
                                &session_id,
                                agent_id,
                                agent_version,
                                authorized_by,
                                &tool_name,
                                "stdio",
                                &input_hash,
                                "",
                                &decision,
                                0,
                            )?;

                            host_stdout.write_all(err_json.as_bytes()).await?;
                            host_stdout.write_all(b"\n").await?;
                            host_stdout.flush().await?;

                            host_line.clear();
                            continue;
                        }
                        _ => {
                            // ALLOW or HUMAN_REQUIRED — forward to upstream, track it.
                            pending.insert(
                                req_id_key,
                                PendingCall {
                                    tool_name,
                                    tool_params,
                                    input_hash,
                                    start: std::time::Instant::now(),
                                    decision: decision.clone(),
                                },
                            );
                        }
                    }
                }

                // Forward to upstream (for non-blocked requests and non-tool-call messages).
                child_stdin.write_all(host_line.as_bytes()).await?;
                child_stdin.flush().await?;
                host_line.clear();
            }

            // Read from upstream MCP server (child stdout).
            result = upstream_reader.read_line(&mut upstream_line) => {
                let n = result.context("Failed to read from upstream")?;
                if n == 0 {
                    tracing::info!("Upstream process closed stdout");
                    break;
                }

                let trimmed = upstream_line.trim();
                if !trimmed.is_empty()
                    && let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(trimmed)
                {
                    let resp_id_key = resp
                        .id
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_default();

                    if let Some(call) = pending.remove(&resp_id_key) {
                        let output_hash = sha256_hex(trimmed.as_bytes());
                        let latency_ms = call.start.elapsed().as_millis() as i64;

                        super::log_event(
                            ledger,
                            key_manager,
                            &session_id,
                            agent_id,
                            agent_version,
                            authorized_by,
                            &call.tool_name,
                            "stdio",
                            &call.input_hash,
                            &output_hash,
                            &call.decision,
                            latency_ms,
                        )?;

                        tracing::info!(
                            tool = call.tool_name,
                            latency_ms = latency_ms,
                            "Logged tool call response"
                        );
                    }
                }

                // Forward response to agent host.
                host_stdout.write_all(upstream_line.as_bytes()).await?;
                host_stdout.flush().await?;
                upstream_line.clear();
            }

            // Wait for child process to exit.
            status = child.wait() => {
                let code = status.context("Failed to wait for child")?;
                tracing::info!(exit_code = ?code.code(), "Upstream process exited");
                break;
            }
        }
    }

    Ok(())
}
