pub mod http;
pub mod stdio;

pub use http::run_http_proxy;
pub use stdio::run_stdio_proxy;

use anyhow::Result;
use uuid::Uuid;

use crate::identity::KeyManager;
use crate::ledger::{AgentActionEvent, LocalLedger};
use crate::policy::PolicyDecision;

/// Parameters for logging a tool call event.
pub struct EventParams<'a> {
    pub tool_name: &'a str,
    pub tool_server: &'a str,
    pub input_hash: &'a str,
    pub output_hash: &'a str,
    pub input_data: Option<serde_json::Value>,
    pub output_data: Option<serde_json::Value>,
    pub decision: &'a PolicyDecision,
    pub latency_ms: i64,
}

/// Create, sign, and append an event to the local ledger.
/// Shared between stdio and HTTP proxy modes.
pub fn log_event(
    ledger: &LocalLedger,
    key_manager: &KeyManager,
    session_id: &str,
    agent_id: &str,
    agent_version: &str,
    authorized_by: &str,
    params: EventParams,
) -> Result<String> {
    let prev_hash = ledger.last_event_hash()?;
    let sequence_number = ledger.next_sequence_number()?;

    let mut event = AgentActionEvent {
        event_id: Uuid::now_v7().to_string(),
        agent_id: agent_id.to_string(),
        agent_version: agent_version.to_string(),
        authorized_by: authorized_by.to_string(),
        session_id: session_id.to_string(),
        timestamp: chrono::Utc::now(),
        tool_name: params.tool_name.to_string(),
        tool_server: params.tool_server.to_string(),
        input_hash: params.input_hash.to_string(),
        output_hash: params.output_hash.to_string(),
        input_data: params.input_data,
        output_data: params.output_data,
        policy_decision: params.decision.as_str().to_string(),
        policy_rule: params.decision.rule_name().to_string(),
        latency_ms: params.latency_ms,
        sequence_number,
        prev_hash,
        event_hash: String::new(),
        hash_input: None,
        signature: String::new(),
        proxy_key_id: key_manager.key_id.clone(),
    };

    let (hash, hash_input) = event.compute_hash_with_input();
    event.event_hash = hash;
    event.hash_input = Some(hash_input);
    event.signature = key_manager.sign(event.event_hash.as_bytes());

    let event_id = event.event_id.clone();
    ledger.append(&event)?;
    Ok(event_id)
}
