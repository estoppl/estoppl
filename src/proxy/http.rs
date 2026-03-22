use anyhow::Result;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::identity::KeyManager;
use crate::ledger::{LocalLedger, sha256_hex};
use crate::mcp::{JsonRpcRequest, JsonRpcResponse};
use crate::policy::{PolicyDecision, PolicyEngine};

/// Tracked tool call for logging when response arrives.
struct TrackedCall {
    tool_name: String,
    input_hash: String,
    decision: PolicyDecision,
    start: std::time::Instant,
}

/// Shared state for the HTTP proxy handlers.
/// Uses Mutex<LocalLedger> because rusqlite::Connection is not Sync.
struct ProxyState {
    upstream_url: String,
    agent_id: String,
    agent_version: String,
    authorized_by: String,
    session_id: String,
    key_manager: KeyManager,
    ledger: Mutex<LocalLedger>,
    policy: Arc<PolicyEngine>,
    #[allow(dead_code)] // Will be used when HTTP proxy review handling is wired up
    review_client: Option<Arc<crate::review::ReviewClient>>,
    http_client: reqwest::Client,
}

impl ProxyState {
    fn log_event(
        &self,
        tool_name: &str,
        input_hash: &str,
        output_hash: &str,
        input_data: Option<serde_json::Value>,
        output_data: Option<serde_json::Value>,
        decision: &PolicyDecision,
        latency_ms: i64,
    ) {
        let ledger = self.ledger.lock().unwrap();
        match super::log_event(
            &ledger,
            &self.key_manager,
            &self.session_id,
            &self.agent_id,
            &self.agent_version,
            &self.authorized_by,
            tool_name,
            &self.upstream_url,
            input_hash,
            output_hash,
            input_data,
            output_data,
            decision,
            latency_ms,
        ) {
            Ok(_event_id) => {}
            Err(e) => tracing::error!(error = %e, "Failed to log event"),
        }
    }
}

/// Run the HTTP/SSE proxy: sits between MCP clients and an upstream MCP server over HTTP.
///
/// Listens on `listen_addr`, forwards requests to `upstream_url`, intercepts tools/call
/// requests, enforces policy, and logs everything to the ledger.
#[allow(clippy::too_many_arguments)]
pub async fn run_http_proxy(
    listen_addr: &str,
    upstream_url: &str,
    agent_id: &str,
    agent_version: &str,
    authorized_by: &str,
    key_manager: KeyManager,
    ledger: LocalLedger,
    policy: Arc<PolicyEngine>,
    review_client: Option<Arc<crate::review::ReviewClient>>,
) -> Result<()> {
    let session_id = Uuid::now_v7().to_string();

    tracing::info!(
        agent_id = agent_id,
        session_id = session_id,
        listen_addr = listen_addr,
        upstream_url = upstream_url,
        "Starting HTTP proxy"
    );

    let state = Arc::new(ProxyState {
        upstream_url: upstream_url.to_string(),
        agent_id: agent_id.to_string(),
        agent_version: agent_version.to_string(),
        authorized_by: authorized_by.to_string(),
        session_id,
        key_manager,
        ledger: Mutex::new(ledger),
        policy,
        review_client,
        http_client: reqwest::Client::new(),
    });

    let app = Router::new().fallback(proxy_handler).with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!("HTTP proxy listening on {}", listen_addr);

    axum::serve(listener, app).await?;

    Ok(())
}

/// Single handler for all requests — routes based on HTTP method.
async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match method {
        Method::POST => handle_post(state, headers, body).await,
        Method::GET => handle_get_sse(state, headers).await,
        Method::DELETE => handle_delete(state, headers).await,
        _ => (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed").into_response(),
    }
}

/// Handle POST: JSON-RPC messages from client to server.
/// Intercepts tools/call requests and applies policy before forwarding.
async fn handle_post(state: Arc<ProxyState>, headers: HeaderMap, body: Bytes) -> Response {
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid UTF-8 body").into_response(),
    };

    // Try to parse as a single JSON-RPC request or a batch.
    let requests: Vec<JsonRpcRequest> = if body_str.trim_start().starts_with('[') {
        match serde_json::from_str(body_str) {
            Ok(batch) => batch,
            Err(_) => return forward_post_raw(&state, &headers, body).await,
        }
    } else {
        match serde_json::from_str::<JsonRpcRequest>(body_str) {
            Ok(req) => vec![req],
            Err(_) => return forward_post_raw(&state, &headers, body).await,
        }
    };

    // Check if any request is a tools/call that should be blocked.
    let mut blocked_responses: Vec<JsonRpcResponse> = Vec::new();
    let mut forward_requests: Vec<serde_json::Value> = Vec::new();
    let mut tracked: HashMap<String, TrackedCall> = HashMap::new();

    for req in &requests {
        if req.is_tool_call() {
            let tool_params = req.tool_call_params();
            let tool_name = tool_params
                .as_ref()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "unknown".to_string());

            let req_json = serde_json::to_string(&req).unwrap_or_default();
            let input_hash = sha256_hex(req_json.as_bytes());

            let decision = tool_params
                .as_ref()
                .map(|p| state.policy.evaluate(p))
                .unwrap_or(PolicyDecision::Allow);

            tracing::info!(
                tool = tool_name,
                decision = decision.as_str(),
                "Intercepted tools/call (HTTP)"
            );

            match &decision {
                PolicyDecision::Block { rule } => {
                    state.log_event(&tool_name, &input_hash, "", None, None, &decision, 0);

                    blocked_responses.push(JsonRpcResponse::error(
                        req.id.clone(),
                        -32001,
                        format!("Blocked by policy: {}", rule),
                    ));
                }
                _ => {
                    let req_id_key = req.id.as_ref().map(|v| v.to_string()).unwrap_or_default();

                    tracked.insert(
                        req_id_key,
                        TrackedCall {
                            tool_name,
                            input_hash,
                            decision: decision.clone(),
                            start: std::time::Instant::now(),
                        },
                    );

                    if let Ok(val) = serde_json::to_value(req) {
                        forward_requests.push(val);
                    }
                }
            }
        } else {
            // Non-tool-call — forward as-is.
            if let Ok(val) = serde_json::to_value(req) {
                forward_requests.push(val);
            }
        }
    }

    // If all requests were blocked, return blocked responses directly.
    if forward_requests.is_empty() {
        if blocked_responses.len() == 1 {
            let resp_json = serde_json::to_string(&blocked_responses[0]).unwrap_or_default();
            return (
                StatusCode::OK,
                [("content-type", "application/json")],
                resp_json,
            )
                .into_response();
        }
        let resp_json = serde_json::to_string(&blocked_responses).unwrap_or_default();
        return (
            StatusCode::OK,
            [("content-type", "application/json")],
            resp_json,
        )
            .into_response();
    }

    // Forward the remaining requests to upstream.
    let forward_body = if forward_requests.len() == 1 && requests.len() == 1 {
        serde_json::to_vec(&forward_requests[0]).unwrap_or_default()
    } else {
        serde_json::to_vec(&forward_requests).unwrap_or_default()
    };

    let upstream_resp = match forward_post_to_upstream(&state, &headers, forward_body.into()).await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, "Failed to forward to upstream");
            return (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e)).into_response();
        }
    };

    let upstream_status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();
    let content_type = upstream_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("text/event-stream") {
        // SSE response — stream through, intercepting each event for logging.
        return stream_sse_response(state, upstream_resp, tracked, blocked_responses).await;
    }

    // JSON response — parse, log tool call responses, merge blocked responses.
    let resp_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("Failed to read upstream: {}", e),
            )
                .into_response();
        }
    };

    // Log any tracked tool call responses.
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    log_tracked_responses(&state, &tracked, &resp_str);

    // If we have blocked responses to merge, combine them.
    let final_body = if blocked_responses.is_empty() {
        resp_bytes.to_vec()
    } else {
        merge_responses(&resp_bytes, &blocked_responses)
    };

    let mut response = Response::builder().status(upstream_status);
    for (key, value) in &upstream_headers {
        if key == "content-type" || key == "mcp-session-id" {
            response = response.header(key, value);
        }
    }

    response
        .body(Body::from(final_body))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response())
}

/// Handle GET: Open SSE stream for server-initiated messages.
async fn handle_get_sse(state: Arc<ProxyState>, headers: HeaderMap) -> Response {
    let mut req_builder = state
        .http_client
        .get(&state.upstream_url)
        .header("Accept", "text/event-stream");

    if let Some(session_id) = headers.get("mcp-session-id") {
        req_builder = req_builder.header("Mcp-Session-Id", session_id);
    }
    if let Some(auth) = headers.get("authorization") {
        req_builder = req_builder.header("Authorization", auth);
    }
    if let Some(last_event_id) = headers.get("last-event-id") {
        req_builder = req_builder.header("Last-Event-ID", last_event_id);
    }

    let upstream_resp = match req_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, "Failed to connect to upstream for SSE");
            return (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e)).into_response();
        }
    };

    let upstream_status = upstream_resp.status();

    if upstream_status == StatusCode::METHOD_NOT_ALLOWED {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            "Upstream does not support GET SSE",
        )
            .into_response();
    }

    // Stream the SSE response through transparently.
    let stream = upstream_resp
        .bytes_stream()
        .map(|result| result.map_err(|e| std::io::Error::other(format!("Stream error: {}", e))));

    Response::builder()
        .status(upstream_status)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response())
}

/// Handle DELETE: Session termination. Forward to upstream.
async fn handle_delete(state: Arc<ProxyState>, headers: HeaderMap) -> Response {
    let mut req_builder = state.http_client.delete(&state.upstream_url);

    if let Some(session_id) = headers.get("mcp-session-id") {
        req_builder = req_builder.header("Mcp-Session-Id", session_id);
    }
    if let Some(auth) = headers.get("authorization") {
        req_builder = req_builder.header("Authorization", auth);
    }

    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            tracing::info!(status = status.as_u16(), "Forwarded DELETE to upstream");
            (status, "").into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to forward DELETE");
            (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e)).into_response()
        }
    }
}

/// Forward a raw POST body to upstream without interception.
async fn forward_post_raw(state: &ProxyState, headers: &HeaderMap, body: Bytes) -> Response {
    match forward_post_to_upstream(state, headers, body).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();
            let body_bytes = resp.bytes().await.unwrap_or_default();

            let mut response = Response::builder().status(status);
            for (key, value) in &resp_headers {
                if key == "content-type" || key == "mcp-session-id" {
                    response = response.header(key, value);
                }
            }

            response.body(Body::from(body_bytes)).unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
            })
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e)).into_response(),
    }
}

/// Send a POST request to the upstream MCP server.
async fn forward_post_to_upstream(
    state: &ProxyState,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut req_builder = state
        .http_client
        .post(&state.upstream_url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");

    if let Some(session_id) = headers.get("mcp-session-id") {
        req_builder = req_builder.header("Mcp-Session-Id", session_id);
    }
    if let Some(auth) = headers.get("authorization") {
        req_builder = req_builder.header("Authorization", auth);
    }

    req_builder.body(body).send().await
}

/// Stream an SSE response from upstream through to the client,
/// logging tool call responses as they arrive.
async fn stream_sse_response(
    state: Arc<ProxyState>,
    upstream_resp: reqwest::Response,
    tracked: HashMap<String, TrackedCall>,
    blocked_responses: Vec<JsonRpcResponse>,
) -> Response {
    let tracked = Arc::new(Mutex::new(tracked));

    // Prepend blocked responses as SSE events.
    let mut prefix_events: Vec<Bytes> = Vec::new();
    for blocked in &blocked_responses {
        if let Ok(json) = serde_json::to_string(blocked) {
            let sse_event = format!("event: message\ndata: {}\n\n", json);
            prefix_events.push(Bytes::from(sse_event));
        }
    }

    let prefix_stream =
        futures::stream::iter(prefix_events.into_iter().map(Ok::<_, std::io::Error>));

    // Stream upstream SSE events, inspecting each for tool call responses.
    let upstream_stream = upstream_resp
        .bytes_stream()
        .map(move |result| match result {
            Ok(chunk) => {
                let chunk_str = String::from_utf8_lossy(&chunk);
                for line in chunk_str.lines() {
                    if let Some(data) = line.strip_prefix("data: ") {
                        let t = tracked.lock().unwrap();
                        log_tracked_responses(&state, &t, data);
                    }
                }
                Ok(chunk)
            }
            Err(e) => Err(std::io::Error::other(format!("Stream error: {}", e))),
        });

    let combined = prefix_stream.chain(upstream_stream);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .body(Body::from_stream(combined))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response())
}

/// Log any tool call responses found in a response string.
fn log_tracked_responses(
    state: &ProxyState,
    tracked: &HashMap<String, TrackedCall>,
    resp_str: &str,
) {
    if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(resp_str) {
        log_single_response(state, tracked, &resp, resp_str);
    } else if let Ok(batch) = serde_json::from_str::<Vec<JsonRpcResponse>>(resp_str) {
        for resp in &batch {
            let resp_json = serde_json::to_string(resp).unwrap_or_default();
            log_single_response(state, tracked, resp, &resp_json);
        }
    }
}

fn log_single_response(
    state: &ProxyState,
    tracked: &HashMap<String, TrackedCall>,
    resp: &JsonRpcResponse,
    resp_str: &str,
) {
    let resp_id_key = resp.id.as_ref().map(|v| v.to_string()).unwrap_or_default();

    if let Some(call) = tracked.get(&resp_id_key) {
        let output_hash = sha256_hex(resp_str.as_bytes());
        let latency_ms = call.start.elapsed().as_millis() as i64;

        state.log_event(
            &call.tool_name,
            &call.input_hash,
            &output_hash,
            None, // TODO: capture input_data in TrackedCall
            None, // TODO: capture output_data from response
            &call.decision,
            latency_ms,
        );

        tracing::info!(
            tool = call.tool_name,
            latency_ms = latency_ms,
            "Logged tool call response (HTTP)"
        );
    }
}

/// Merge blocked responses into the upstream response body.
fn merge_responses(upstream_body: &[u8], blocked: &[JsonRpcResponse]) -> Vec<u8> {
    if blocked.is_empty() {
        return upstream_body.to_vec();
    }

    let upstream_str = String::from_utf8_lossy(upstream_body);

    // If upstream returned a batch, merge blocked into it.
    if let Ok(mut batch) = serde_json::from_str::<Vec<serde_json::Value>>(&upstream_str) {
        for resp in blocked {
            if let Ok(val) = serde_json::to_value(resp) {
                batch.push(val);
            }
        }
        return serde_json::to_vec(&batch).unwrap_or_else(|_| upstream_body.to_vec());
    }

    // If upstream returned a single response and we have blocked ones, combine into a batch.
    if let Ok(single) = serde_json::from_str::<serde_json::Value>(&upstream_str) {
        let mut batch = vec![single];
        for resp in blocked {
            if let Ok(val) = serde_json::to_value(resp) {
                batch.push(val);
            }
        }
        return serde_json::to_vec(&batch).unwrap_or_else(|_| upstream_body.to_vec());
    }

    upstream_body.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RulesConfig;

    #[allow(dead_code)]
    fn make_policy() -> PolicyEngine {
        let rules = RulesConfig {
            block_tools: vec!["dangerous_tool".into()],
            human_review_tools: vec!["wire_transfer".into()],
            max_amount_usd: Some(50_000.0),
            ..Default::default()
        };
        PolicyEngine::new(rules)
    }

    #[test]
    fn test_merge_responses_single_plus_blocked() {
        let upstream = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;
        let blocked = vec![JsonRpcResponse::error(
            Some(serde_json::json!(2)),
            -32001,
            "Blocked by policy: block_tools:dangerous_tool".to_string(),
        )];

        let merged = merge_responses(upstream.as_bytes(), &blocked);
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&merged).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["id"], 1);
        assert_eq!(parsed[1]["id"], 2);
        assert!(
            parsed[1]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Blocked")
        );
    }

    #[test]
    fn test_merge_responses_batch_plus_blocked() {
        let upstream =
            r#"[{"jsonrpc":"2.0","id":1,"result":{}},{"jsonrpc":"2.0","id":3,"result":{}}]"#;
        let blocked = vec![JsonRpcResponse::error(
            Some(serde_json::json!(2)),
            -32001,
            "Blocked".to_string(),
        )];

        let merged = merge_responses(upstream.as_bytes(), &blocked);
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&merged).unwrap();
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn test_merge_responses_empty_blocked() {
        let upstream = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let merged = merge_responses(upstream.as_bytes(), &[]);
        assert_eq!(merged, upstream.as_bytes());
    }

    #[test]
    fn test_policy_blocks_in_batch_context() {
        let policy = make_policy();
        let tool_params = crate::mcp::ToolCallParams {
            name: "dangerous_tool".into(),
            arguments: serde_json::json!({}),
        };
        assert!(matches!(
            policy.evaluate(&tool_params),
            PolicyDecision::Block { .. }
        ));
    }
}
