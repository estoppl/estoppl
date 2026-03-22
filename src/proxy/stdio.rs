use anyhow::{Context, Result};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use uuid::Uuid;

use crate::identity::KeyManager;
use crate::ledger::{LocalLedger, sha256_hex};
use crate::mcp::{JsonRpcRequest, JsonRpcResponse};
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::review::{ReviewClient, ReviewOutcome};

/// Redact specified fields from a JSON value, replacing with "[REDACTED]".
fn redact_fields(value: &serde_json::Value, fields: &[String]) -> serde_json::Value {
    if fields.is_empty() {
        return value.clone();
    }
    match value {
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (k, v) in map {
                if fields.iter().any(|f| f == k) {
                    redacted.insert(
                        k.clone(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                } else {
                    redacted.insert(k.clone(), redact_fields(v, fields));
                }
            }
            serde_json::Value::Object(redacted)
        }
        _ => value.clone(),
    }
}

/// Tracks an in-flight tools/call request so we can log the response too.
struct PendingCall {
    tool_name: String,
    event_id: String,
    start: std::time::Instant,
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
    review_client: Option<Arc<ReviewClient>>,
    redact_fields: &[String],
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

    let mut child_stdin = Some(
        child
            .stdin
            .take()
            .context("Failed to capture child stdin")?,
    );
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

    let mut stdin_closed = false;

    // Track in-flight human review waits.
    type ReviewFuture = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = (
                        Result<ReviewOutcome>,
                        String,                    // held_request
                        Option<serde_json::Value>, // req_id
                        String,                    // tool_name
                        String,                    // event_id
                    ),
                > + Send,
        >,
    >;
    let mut review_futures: FuturesUnordered<ReviewFuture> = FuturesUnordered::new();

    loop {
        // If stdin is closed and no pending calls, we're done.
        if stdin_closed && pending.is_empty() {
            break;
        }

        tokio::select! {
            // Read from agent host (our stdin).
            result = host_stdin.read_line(&mut host_line), if !stdin_closed => {
                let n = result.context("Failed to read from stdin")?;
                if n == 0 {
                    tracing::info!("Agent host closed stdin — draining {} in-flight calls", pending.len());
                    stdin_closed = true;
                    // Close upstream stdin so the server knows no more input is coming.
                    child_stdin.take();
                    if pending.is_empty() {
                        break;
                    }
                    continue;
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
                    let input_data = tool_params
                        .as_ref()
                        .map(|p| self::redact_fields(&p.arguments, redact_fields));

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

                            // Log the blocked call immediately.
                            super::log_event(
                                ledger, key_manager, &session_id,
                                agent_id, agent_version, authorized_by,
                                super::EventParams {
                                    tool_name: &tool_name, tool_server: "stdio",
                                    input_hash: &input_hash, output_hash: "",
                                    input_data: input_data.clone(), output_data: None,
                                    decision: &decision, latency_ms: 0,
                                },
                            )?;

                            host_stdout.write_all(err_json.as_bytes()).await?;
                            host_stdout.write_all(b"\n").await?;
                            host_stdout.flush().await?;

                            host_line.clear();
                            continue;
                        }
                        PolicyDecision::HumanRequired { .. } if review_client.is_some() => {
                            // Hold the call — don't forward until human approves.
                            let event_id = super::log_event(
                                ledger, key_manager, &session_id,
                                agent_id, agent_version, authorized_by,
                                super::EventParams {
                                    tool_name: &tool_name, tool_server: "stdio",
                                    input_hash: &input_hash, output_hash: "",
                                    input_data: input_data.clone(), output_data: None,
                                    decision: &decision, latency_ms: 0,
                                },
                            )?;

                            tracing::info!(
                                tool = tool_name,
                                event_id = event_id,
                                "Holding tool call for human review"
                            );

                            let rc = Arc::clone(review_client.as_ref().unwrap());
                            let held_request = host_line.clone();
                            let req_id = req.id.clone();
                            let tn = tool_name.clone();
                            let ih = input_hash.clone();
                            let aid = agent_id.to_string();
                            let pkid = key_manager.key_id.clone();

                            review_futures.push(Box::pin(async move {
                                // Submit review request to cloud
                                if let Err(e) = rc.submit_review(
                                    &event_id, &tn, &aid, &ih, &pkid, 300,
                                ).await {
                                    tracing::warn!(error = %e, "Failed to submit review");
                                }

                                // Wait for decision
                                let outcome = rc.wait_for_decision(
                                    &event_id,
                                    Duration::from_secs(295), // slightly less than cloud's 300s
                                    Duration::from_secs(2),
                                ).await;

                                (outcome, held_request, req_id, tn, event_id)
                            }));

                            host_line.clear();
                            continue;
                        }
                        _ => {
                            // ALLOW (or HUMAN_REQUIRED without review client) — log and forward.
                            if matches!(&decision, PolicyDecision::HumanRequired { .. }) {
                                tracing::warn!(
                                    "HUMAN_REQUIRED but --sync not enabled; forwarding without review"
                                );
                            }

                            let event_id = super::log_event(
                                ledger, key_manager, &session_id,
                                agent_id, agent_version, authorized_by,
                                super::EventParams {
                                    tool_name: &tool_name, tool_server: "stdio",
                                    input_hash: &input_hash, output_hash: "",
                                    input_data: input_data.clone(), output_data: None,
                                    decision: &decision, latency_ms: 0,
                                },
                            )?;

                            pending.insert(
                                req_id_key,
                                PendingCall {
                                    tool_name,
                                    event_id,
                                    start: std::time::Instant::now(),
                                },
                            );
                        }
                    }
                }

                // Forward to upstream (for non-blocked requests and non-tool-call messages).
                if let Some(ref mut stdin) = child_stdin {
                    stdin.write_all(host_line.as_bytes()).await?;
                    stdin.flush().await?;
                }
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
                        let latency_ms = call.start.elapsed().as_millis() as i64;

                        // Update the event with response data (local + cloud)
                        let output = resp.result.clone();
                        if let Err(e) = ledger.update_event_output(
                            &call.event_id,
                            output.clone(),
                        ) {
                            tracing::warn!(error = %e, "Failed to update local event with response");
                        }

                        // Send output_data to cloud
                        if let Some(ref rc) = review_client {
                            let eid = call.event_id.clone();
                            let rc = Arc::clone(rc);
                            let out = output.clone();
                            tokio::spawn(async move {
                                if let Err(e) = rc.update_event_output(&eid, out).await {
                                    tracing::warn!(error = %e, "Failed to sync response to cloud");
                                }
                            });
                        }

                        tracing::info!(
                            tool = call.tool_name,
                            latency_ms = latency_ms,
                            "Tool call completed"
                        );
                    }
                }

                // Forward response to agent host.
                host_stdout.write_all(upstream_line.as_bytes()).await?;
                host_stdout.flush().await?;
                upstream_line.clear();
            }

            // Check for completed human review decisions.
            Some((outcome, held_request, req_id, tool_name, evt_id)) = review_futures.next() => {
                match outcome {
                    Ok(ReviewOutcome::Approved) => {
                        tracing::info!(tool = tool_name, "Human review APPROVED — forwarding");
                        if let Some(ref mut stdin) = child_stdin {
                            stdin.write_all(held_request.as_bytes()).await?;
                            stdin.flush().await?;
                        }
                        let req_id_key = req_id.map(|v| v.to_string()).unwrap_or_default();
                        pending.insert(req_id_key, PendingCall {
                            tool_name,
                            event_id: evt_id,
                            start: std::time::Instant::now(),
                        });
                    }
                    Ok(outcome) => {
                        let reason = match outcome {
                            ReviewOutcome::Denied => "Denied by human review",
                            ReviewOutcome::Expired => "Human review timed out",
                            _ => unreachable!(),
                        };
                        tracing::info!(tool = tool_name, reason = reason, "Human review rejected");
                        let err_resp = JsonRpcResponse::error(
                            req_id, -32001, reason.to_string(),
                        );
                        let err_json = serde_json::to_string(&err_resp)?;
                        host_stdout.write_all(err_json.as_bytes()).await?;
                        host_stdout.write_all(b"\n").await?;
                        host_stdout.flush().await?;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, tool = tool_name, "Review polling failed — denying");
                        let err_resp = JsonRpcResponse::error(
                            req_id, -32001, "Human review unavailable".to_string(),
                        );
                        let err_json = serde_json::to_string(&err_resp)?;
                        host_stdout.write_all(err_json.as_bytes()).await?;
                        host_stdout.write_all(b"\n").await?;
                        host_stdout.flush().await?;
                    }
                }
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
