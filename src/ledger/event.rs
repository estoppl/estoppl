use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A single auditable agent action event.
/// This is the core schema — every tool call produces one of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActionEvent {
    // Identity
    pub event_id: String,
    pub agent_id: String,
    pub agent_version: String,
    pub authorized_by: String,
    pub session_id: String,

    // Action
    pub timestamp: DateTime<Utc>,
    pub tool_name: String,
    pub tool_server: String,
    pub input_hash: String,
    pub output_hash: String,

    // Raw data (sent to cloud for auditing, redacted fields stripped by proxy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_data: Option<serde_json::Value>,

    // Policy
    pub policy_decision: String,
    pub policy_rule: String,
    pub latency_ms: i64,

    // Tamper-evidence chain
    /// Monotonically increasing sequence number per proxy instance (proxy_key_id).
    /// Enables gap detection during cloud sync — if the cloud receives seq 50 then 53,
    /// it knows events 51-52 are missing and can request them.
    pub sequence_number: i64,
    pub prev_hash: String,
    pub event_hash: String,
    /// The canonical JSON string that was hashed to produce event_hash.
    /// Included in receipts so verifiers can recompute SHA-256 independently.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_input: Option<String>,
    pub signature: String,
    pub proxy_key_id: String,
}

impl AgentActionEvent {
    /// Compute the SHA-256 hash of this event (excluding event_hash and signature fields).
    /// Compute the SHA-256 hash and return both the hash and the canonical JSON
    /// that was hashed. The canonical JSON is stored so receipts can include it
    /// for independent verification without recomputing.
    pub fn compute_hash_with_input(&self) -> (String, String) {
        let hashable = serde_json::json!({
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "authorized_by": self.authorized_by,
            "session_id": self.session_id,
            "timestamp": self.timestamp.to_rfc3339(),
            "tool_name": self.tool_name,
            "tool_server": self.tool_server,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "policy_decision": self.policy_decision,
            "policy_rule": self.policy_rule,
            "latency_ms": self.latency_ms,
            "sequence_number": self.sequence_number,
            "prev_hash": self.prev_hash,
        });

        let canonical = serde_json::to_string(&hashable).expect("serialization cannot fail");
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        (hex::encode(hasher.finalize()), canonical)
    }

    /// Compute just the hash (backward compatible).
    pub fn compute_hash(&self) -> String {
        self.compute_hash_with_input().0
    }
}

/// Hash arbitrary data with SHA-256, returning hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_id: &str, prev_hash: &str) -> AgentActionEvent {
        AgentActionEvent {
            event_id: event_id.to_string(),
            agent_id: "test-agent".to_string(),
            agent_version: "0.1.0".to_string(),
            authorized_by: "tester".to_string(),
            session_id: "session-1".to_string(),
            timestamp: Utc::now(),
            tool_name: "test_tool".to_string(),
            tool_server: "".to_string(),
            input_hash: sha256_hex(b"input"),
            output_hash: sha256_hex(b"output"),
            input_data: None,
            output_data: None,
            policy_decision: "ALLOW".to_string(),
            policy_rule: "".to_string(),
            latency_ms: 2,
            sequence_number: 0,
            prev_hash: prev_hash.to_string(),
            event_hash: "".to_string(),
            hash_input: None,
            signature: "".to_string(),
            proxy_key_id: "test-key".to_string(),
        }
    }

    #[test]
    fn compute_hash_is_deterministic() {
        let event = make_event("evt-1", "");
        let hash1 = event.compute_hash();
        let hash2 = event.compute_hash();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn different_events_produce_different_hashes() {
        let e1 = make_event("evt-1", "");
        let e2 = make_event("evt-2", "");
        assert_ne!(e1.compute_hash(), e2.compute_hash());
    }

    #[test]
    fn hash_changes_when_field_changes() {
        let e1 = make_event("evt-1", "");
        let mut e2 = make_event("evt-1", "");
        e2.tool_name = "different_tool".to_string();
        assert_ne!(e1.compute_hash(), e2.compute_hash());
    }

    #[test]
    fn prev_hash_affects_event_hash() {
        let e1 = make_event("evt-1", "");
        let e2 = make_event("evt-1", "abc123");
        assert_ne!(e1.compute_hash(), e2.compute_hash());
    }

    #[test]
    fn sequence_number_affects_hash() {
        let e1 = make_event("evt-1", "");
        let mut e2 = make_event("evt-1", "");
        e2.sequence_number = 42;
        assert_ne!(e1.compute_hash(), e2.compute_hash());
    }

    #[test]
    fn sha256_hex_works() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash.len(), 64);
        // Known SHA-256 of "hello"
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
