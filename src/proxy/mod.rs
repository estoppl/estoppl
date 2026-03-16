pub mod http;
pub mod stdio;

pub use http::run_http_proxy;
pub use stdio::run_stdio_proxy;

use anyhow::Result;
use uuid::Uuid;

use crate::identity::KeyManager;
use crate::ledger::{AgentActionEvent, LocalLedger};
use crate::policy::PolicyDecision;

/// Create, sign, and append an event to the local ledger.
/// Shared between stdio and HTTP proxy modes.
///
/// Assigns a monotonically increasing sequence number to each event.
/// The sequence number is included in the event hash, making it tamper-evident.
/// The cloud uses sequence numbers to detect gaps during sync (e.g., if the proxy
/// loses connection, events queue locally and the cloud can detect missing sequence
/// numbers on reconnect).
#[allow(clippy::too_many_arguments)]
pub fn log_event(
    ledger: &LocalLedger,
    key_manager: &KeyManager,
    session_id: &str,
    agent_id: &str,
    agent_version: &str,
    authorized_by: &str,
    tool_name: &str,
    tool_server: &str,
    input_hash: &str,
    output_hash: &str,
    decision: &PolicyDecision,
    latency_ms: i64,
) -> Result<()> {
    let prev_hash = ledger.last_event_hash()?;
    let sequence_number = ledger.next_sequence_number()?;

    let mut event = AgentActionEvent {
        event_id: Uuid::now_v7().to_string(),
        agent_id: agent_id.to_string(),
        agent_version: agent_version.to_string(),
        authorized_by: authorized_by.to_string(),
        session_id: session_id.to_string(),
        timestamp: chrono::Utc::now(),
        tool_name: tool_name.to_string(),
        tool_server: tool_server.to_string(),
        input_hash: input_hash.to_string(),
        output_hash: output_hash.to_string(),
        policy_decision: decision.as_str().to_string(),
        policy_rule: decision.rule_name().to_string(),
        latency_ms,
        sequence_number,
        prev_hash,
        event_hash: String::new(),
        signature: String::new(),
        proxy_key_id: key_manager.key_id.clone(),
    };

    event.event_hash = event.compute_hash();
    event.signature = key_manager.sign(event.event_hash.as_bytes());

    ledger.append(&event)?;
    Ok(())
}
