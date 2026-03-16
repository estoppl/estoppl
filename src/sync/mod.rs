use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::watch;

use crate::ledger::LocalLedger;

/// Configuration for cloud sync behavior.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Cloud ledger endpoint URL (e.g. "https://api.estoppl.com/v1/events").
    pub endpoint: String,
    /// API key for authenticating with the cloud ledger.
    pub api_key: Option<String>,
    /// Number of events to send per batch.
    pub batch_size: u32,
    /// Polling interval in seconds.
    pub interval_secs: u64,
}

/// Chain metadata sent with each sync batch so the cloud can verify
/// hash chain continuity across network partitions.
///
/// The cloud uses this to:
/// 1. Detect gaps — if `first_sequence` != cloud's `last_received_sequence + 1`
/// 2. Verify chain link — if `expected_prev_hash` != cloud's last stored event_hash
/// 3. Verify batch integrity — `batch_hash` covers all event hashes in order
#[derive(Debug, Clone, Serialize)]
pub struct ChainMetadata {
    /// Proxy instance identity (used to scope sequence numbers).
    pub proxy_key_id: String,
    /// Sequence number of the first event in this batch.
    pub first_sequence: i64,
    /// Sequence number of the last event in this batch.
    pub last_sequence: i64,
    /// The event_hash of the event immediately before this batch
    /// (i.e., the last event the cloud should already have).
    /// Empty string for the very first batch from this proxy.
    pub expected_prev_hash: String,
    /// SHA-256 of all event_hash values concatenated in order.
    /// Lets the cloud verify the entire batch wasn't tampered with in transit.
    pub batch_hash: String,
}

/// Cloud response indicating sync result.
/// The proxy uses this to decide whether to advance the cursor or re-send.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SyncResponse {
    /// Number of events accepted.
    #[serde(default)]
    pub accepted: u64,
    /// Whether the cloud verified chain continuity with its stored state.
    #[serde(default)]
    pub chain_verified: bool,
    /// If the cloud detected a gap, this is the sequence number it needs next.
    /// The proxy should reset its sync cursor to re-send from this point.
    #[serde(default)]
    pub gap_from_sequence: Option<i64>,
    /// Receipt ID for this batch (for audit trail on both sides).
    #[serde(default)]
    pub receipt_id: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Cloud API contract (TODO: implement on the cloud side)
//
// POST {endpoint}
//   Headers:
//     Authorization: Bearer {api_key}
//     Content-Type: application/json
//
//   Body:
//     {
//       "events": [ ...array of AgentActionEvent with sequence_number... ],
//       "chain_metadata": {
//         "proxy_key_id": "abc123def456",
//         "first_sequence": 51,
//         "last_sequence": 100,
//         "expected_prev_hash": "sha256...",
//         "batch_hash": "sha256..."
//       },
//       "proxy_version": "0.1.0"
//     }
//
//   Response 200 (success):
//     {
//       "accepted": 50,
//       "chain_verified": true,
//       "receipt_id": "rec_abc123"
//     }
//
//   Response 200 (accepted but chain not verifiable — e.g., first batch ever):
//     {
//       "accepted": 50,
//       "chain_verified": false,
//       "receipt_id": "rec_abc123"
//     }
//
//   Response 409 (gap detected — cloud has up to seq N, proxy sent from M > N+1):
//     {
//       "accepted": 0,
//       "chain_verified": false,
//       "gap_from_sequence": 42
//     }
//     The proxy should reset its cursor to re-send from sequence 42.
//
//   Response 409 (duplicate — events already ingested, idempotent):
//     { "accepted": 0, "chain_verified": true }
//
//   Response 401: invalid API key
//   Response 429: rate limited (respect Retry-After header)
//
// ──────────────────────────────────────────────────────────────────────────────
// Cloud-side reconciliation logic (TODO: implement in estoppl-ledger)
//
// On receiving a batch:
// 1. Look up last_received_sequence for this proxy_key_id.
// 2. If batch.first_sequence > last_received_sequence + 1:
//    → Gap detected. Return 409 with gap_from_sequence = last_received_sequence + 1.
//    → Do NOT store the batch (would create a gap in the chain).
// 3. If batch.first_sequence <= last_received_sequence:
//    → Duplicate/overlap. Filter out already-stored events by event_id.
//    → If all are duplicates, return 409 duplicate.
// 4. Verify batch.expected_prev_hash matches stored event_hash for
//    sequence = batch.first_sequence - 1. If mismatch:
//    → Log a chain_continuity_warning (possible fork or tampering).
//    → Still accept the batch (don't block the proxy), but flag for review.
// 5. Verify each event's self-hash: event.compute_hash() == event.event_hash.
// 6. Verify each event's prev_hash links to the previous event in the batch.
// 7. Verify batch_hash matches SHA-256 of concatenated event hashes.
// 8. Verify event signatures using the proxy's registered public key.
// 9. Store events. Update last_received_sequence. Return 200.
//
// Cloud infrastructure recommendations:
//   - AWS: API Gateway + Lambda + DynamoDB (hot) + S3 Object Lock (WORM cold)
//   - Track per-proxy state: { proxy_key_id, last_sequence, last_hash, public_key }
//   - Event ingestion must be idempotent (dedupe on event_id)
//   - WORM: S3 Object Lock in Compliance mode for regulatory evidence
// ──────────────────────────────────────────────────────────────────────────────

/// Background task that streams signed events from the local SQLite ledger
/// to the Estoppl cloud endpoint.
///
/// Handles network partitions gracefully:
/// - Events always persist locally first (SQLite is the source of truth)
/// - Sequence numbers on every event let the cloud detect gaps
/// - Chain metadata in each batch lets the cloud verify continuity
/// - On gap detection from cloud, resets cursor and re-sends missing events
/// - Exponential backoff on transient failures (capped at 5 minutes)
pub struct CloudSyncer {
    config: SyncConfig,
    db_path: PathBuf,
    http_client: reqwest::Client,
    shutdown_rx: watch::Receiver<bool>,
}

impl CloudSyncer {
    pub fn new(config: SyncConfig, db_path: PathBuf, shutdown_rx: watch::Receiver<bool>) -> Self {
        Self {
            config,
            db_path,
            http_client: reqwest::Client::new(),
            shutdown_rx,
        }
    }

    /// Spawn the sync loop as a background tokio task.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = self.run().await {
                tracing::error!(error = %e, "Cloud syncer exited with error");
            }
        })
    }

    async fn run(mut self) -> Result<()> {
        let mut backoff_secs = 1u64;
        let max_backoff_secs = 300; // 5 minutes

        tracing::info!(
            endpoint = self.config.endpoint,
            interval_secs = self.config.interval_secs,
            batch_size = self.config.batch_size,
            "Cloud sync started"
        );

        loop {
            if *self.shutdown_rx.borrow() {
                tracing::info!("Cloud syncer shutting down");
                break;
            }

            match self.sync_batch().await {
                Ok(SyncOutcome::Synced(count)) => {
                    tracing::info!(events = count, "Synced events to cloud");
                    backoff_secs = 1;
                    // Full batch — more events may be waiting.
                    continue;
                }
                Ok(SyncOutcome::Empty) => {
                    backoff_secs = 1;
                }
                Ok(SyncOutcome::GapDetected { from_sequence }) => {
                    // Cloud has a gap — reset cursor and immediately retry.
                    tracing::warn!(
                        from_sequence = from_sequence,
                        "Cloud detected gap, resending from sequence"
                    );
                    if let Ok(ledger) = LocalLedger::open(&self.db_path)
                        && let Err(e) = ledger.reset_sync_cursor_to_sequence(from_sequence)
                    {
                        tracing::error!(error = %e, "Failed to reset sync cursor");
                    }
                    backoff_secs = 1;
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        retry_in_secs = backoff_secs,
                        "Cloud sync failed, will retry"
                    );

                    if let Ok(ledger) = LocalLedger::open(&self.db_path) {
                        let _ = ledger.increment_sync_errors();
                    }

                    let wait = tokio::time::Duration::from_secs(backoff_secs);
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = self.shutdown_rx.changed() => break,
                    }
                    backoff_secs = (backoff_secs * 2).min(max_backoff_secs);
                    continue;
                }
            }

            // Normal polling interval.
            let wait = tokio::time::Duration::from_secs(self.config.interval_secs);
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = self.shutdown_rx.changed() => break,
            }
        }

        Ok(())
    }

    /// Attempt to sync one batch of events.
    async fn sync_batch(&self) -> Result<SyncOutcome> {
        let ledger = LocalLedger::open(&self.db_path).context("Failed to open ledger for sync")?;

        let (events, max_rowid) = ledger.unsynced_events(self.config.batch_size)?;
        if events.is_empty() {
            return Ok(SyncOutcome::Empty);
        }

        let count = events.len();

        // Build chain metadata for this batch.
        let (last_synced_seq, last_synced_hash) = ledger.get_sync_chain_state()?;
        let first_sequence = events.first().map(|e| e.sequence_number).unwrap_or(0);
        let last_sequence = events.last().map(|e| e.sequence_number).unwrap_or(0);
        let last_event_hash = events
            .last()
            .map(|e| e.event_hash.clone())
            .unwrap_or_default();

        // Compute batch_hash: SHA-256 of all event hashes concatenated in order.
        let batch_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            for event in &events {
                hasher.update(event.event_hash.as_bytes());
            }
            hex::encode(hasher.finalize())
        };

        let proxy_key_id = events
            .first()
            .map(|e| e.proxy_key_id.clone())
            .unwrap_or_default();

        let chain_metadata = ChainMetadata {
            proxy_key_id,
            first_sequence,
            last_sequence,
            expected_prev_hash: last_synced_hash,
            batch_hash,
        };

        tracing::debug!(
            count = count,
            first_seq = first_sequence,
            last_seq = last_sequence,
            last_synced_seq = last_synced_seq,
            "Sending batch to cloud with chain metadata"
        );

        let payload = serde_json::json!({
            "events": events,
            "chain_metadata": chain_metadata,
            "proxy_version": env!("CARGO_PKG_VERSION"),
        });

        let mut req = self
            .http_client
            .post(&self.config.endpoint)
            .header("Content-Type", "application/json")
            .json(&payload);

        if let Some(api_key) = &self.config.api_key {
            req = req.header("Authorization", format!("Bearer {}", api_key));
        }

        let resp = req.send().await.context("Failed to send sync request")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            // Parse response to check for chain verification status.
            let sync_resp: SyncResponse = serde_json::from_str(&body).unwrap_or(SyncResponse {
                accepted: count as u64,
                chain_verified: false,
                gap_from_sequence: None,
                receipt_id: None,
            });

            if !sync_resp.chain_verified {
                tracing::warn!("Cloud accepted events but could not verify chain continuity");
            }

            if let Some(receipt) = &sync_resp.receipt_id {
                tracing::debug!(receipt_id = receipt, "Cloud receipt");
            }

            ledger.update_sync_cursor(max_rowid, last_sequence, &last_event_hash)?;
            return Ok(SyncOutcome::Synced(count));
        }

        if status.as_u16() == 409 {
            // Could be gap detection or duplicate.
            if let Ok(sync_resp) = serde_json::from_str::<SyncResponse>(&body) {
                if let Some(gap_seq) = sync_resp.gap_from_sequence {
                    return Ok(SyncOutcome::GapDetected {
                        from_sequence: gap_seq,
                    });
                }
                // Duplicate — treat as success.
                if sync_resp.chain_verified {
                    ledger.update_sync_cursor(max_rowid, last_sequence, &last_event_hash)?;
                    return Ok(SyncOutcome::Synced(count));
                }
            }
            // Unknown 409 — treat as duplicate success.
            ledger.update_sync_cursor(max_rowid, last_sequence, &last_event_hash)?;
            return Ok(SyncOutcome::Synced(count));
        }

        if status.as_u16() == 401 {
            anyhow::bail!("Cloud returned 401 Unauthorized — check cloud_api_key in estoppl.toml");
        }

        if status.as_u16() == 429 {
            anyhow::bail!("Cloud returned 429 Too Many Requests");
        }

        anyhow::bail!("Cloud returned {}: {}", status.as_u16(), body);
    }
}

/// Result of a single sync_batch attempt.
enum SyncOutcome {
    /// Successfully synced N events.
    Synced(usize),
    /// No events to sync.
    Empty,
    /// Cloud detected a gap — re-send from this sequence number.
    GapDetected { from_sequence: i64 },
}

/// Create a shutdown channel pair for the syncer.
pub fn shutdown_channel() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

/// Convenience: build a SyncConfig from the ProxyConfig's ledger section.
/// Returns None if cloud_endpoint is not configured.
pub fn sync_config_from_ledger(
    endpoint: Option<&str>,
    api_key: Option<&str>,
) -> Option<SyncConfig> {
    let endpoint = endpoint?.to_string();
    if endpoint.is_empty() {
        return None;
    }

    Some(SyncConfig {
        endpoint,
        api_key: api_key.map(|s| s.to_string()),
        batch_size: 100,
        interval_secs: 5,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::LocalLedger;
    use tempfile::TempDir;

    fn open_temp_ledger() -> (LocalLedger, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let ledger = LocalLedger::open(&db_path).unwrap();
        (ledger, dir)
    }

    fn make_signed_event(
        event_id: &str,
        prev_hash: &str,
        seq: i64,
    ) -> crate::ledger::AgentActionEvent {
        use crate::ledger::event::sha256_hex;
        let mut event = crate::ledger::AgentActionEvent {
            event_id: event_id.to_string(),
            agent_id: "test-agent".to_string(),
            agent_version: "0.1.0".to_string(),
            authorized_by: "tester".to_string(),
            session_id: "session-1".to_string(),
            timestamp: chrono::Utc::now(),
            tool_name: "test_tool".to_string(),
            tool_server: "stdio".to_string(),
            input_hash: sha256_hex(b"input"),
            output_hash: sha256_hex(b"output"),
            policy_decision: "ALLOW".to_string(),
            policy_rule: "".to_string(),
            latency_ms: 2,
            sequence_number: seq,
            prev_hash: prev_hash.to_string(),
            event_hash: "".to_string(),
            signature: "fake-sig".to_string(),
            proxy_key_id: "test-key".to_string(),
        };
        event.event_hash = event.compute_hash();
        event
    }

    /// Helper: insert a chain of N events and return the last event_hash.
    fn insert_chain(ledger: &LocalLedger, count: usize) -> String {
        let mut prev_hash = String::new();
        for i in 1..=count {
            let e = make_signed_event(&format!("evt-{}", i), &prev_hash, i as i64);
            prev_hash = e.event_hash.clone();
            ledger.append(&e).unwrap();
        }
        prev_hash
    }

    #[test]
    fn sync_cursor_starts_at_zero() {
        let (ledger, _dir) = open_temp_ledger();
        assert_eq!(ledger.get_sync_cursor().unwrap(), 0);
    }

    #[test]
    fn sync_cursor_updates_with_chain_state() {
        let (ledger, _dir) = open_temp_ledger();
        ledger.update_sync_cursor(42, 10, "hash123").unwrap();
        assert_eq!(ledger.get_sync_cursor().unwrap(), 42);
        let (seq, hash) = ledger.get_sync_chain_state().unwrap();
        assert_eq!(seq, 10);
        assert_eq!(hash, "hash123");
    }

    #[test]
    fn unsynced_events_returns_new_events() {
        let (ledger, _dir) = open_temp_ledger();
        let last_hash = insert_chain(&ledger, 2);

        let (events, max_rowid) = ledger.unsynced_events(100).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence_number, 1);
        assert_eq!(events[1].sequence_number, 2);
        assert!(max_rowid > 0);

        ledger.update_sync_cursor(max_rowid, 2, &last_hash).unwrap();
        let (events, _) = ledger.unsynced_events(100).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn unsynced_events_respects_batch_size() {
        let (ledger, _dir) = open_temp_ledger();
        insert_chain(&ledger, 3);

        let (events, max_rowid) = ledger.unsynced_events(2).unwrap();
        assert_eq!(events.len(), 2);

        let last_hash = events.last().unwrap().event_hash.clone();
        ledger.update_sync_cursor(max_rowid, 2, &last_hash).unwrap();

        let (events, _) = ledger.unsynced_events(2).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence_number, 3);
    }

    #[test]
    fn increment_sync_errors_works() {
        let (ledger, _dir) = open_temp_ledger();
        ledger.increment_sync_errors().unwrap();
        ledger.increment_sync_errors().unwrap();
    }

    #[test]
    fn sync_config_from_ledger_returns_none_when_empty() {
        assert!(sync_config_from_ledger(None, None).is_none());
        assert!(sync_config_from_ledger(Some(""), None).is_none());
    }

    #[test]
    fn sync_config_from_ledger_returns_config() {
        let config = sync_config_from_ledger(
            Some("https://api.estoppl.com/v1/events"),
            Some("sk_test_123"),
        );
        assert!(config.is_some());
        let c = config.unwrap();
        assert_eq!(c.endpoint, "https://api.estoppl.com/v1/events");
        assert_eq!(c.api_key.as_deref(), Some("sk_test_123"));
    }

    #[test]
    fn chain_metadata_captures_batch_boundary() {
        let (ledger, _dir) = open_temp_ledger();
        let last_hash = insert_chain(&ledger, 5);

        // Sync first 3 events.
        let (events, max_rowid) = ledger.unsynced_events(3).unwrap();
        assert_eq!(events.len(), 3);
        let batch3_last_hash = events[2].event_hash.clone();
        ledger
            .update_sync_cursor(max_rowid, 3, &batch3_last_hash)
            .unwrap();

        // Next batch should start at seq 4, and expected_prev_hash should be event 3's hash.
        let (events, _) = ledger.unsynced_events(100).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence_number, 4);
        assert_eq!(events[1].sequence_number, 5);

        let (last_synced_seq, last_synced_hash) = ledger.get_sync_chain_state().unwrap();
        assert_eq!(last_synced_seq, 3);
        assert_eq!(last_synced_hash, batch3_last_hash);

        // Verify event 4's prev_hash links to event 3.
        assert_eq!(events[0].prev_hash, batch3_last_hash);

        // And event 5's prev_hash links to event 4.
        assert_eq!(events[1].prev_hash, events[0].event_hash);

        // And event 5 is the last in the overall chain.
        assert_eq!(events[1].event_hash, last_hash);
    }

    #[test]
    fn gap_reconciliation_resends_missing_events() {
        let (ledger, _dir) = open_temp_ledger();
        insert_chain(&ledger, 10);

        // Sync all 10.
        let (events, max_rowid) = ledger.unsynced_events(100).unwrap();
        let last_hash = events.last().unwrap().event_hash.clone();
        ledger
            .update_sync_cursor(max_rowid, 10, &last_hash)
            .unwrap();

        // Simulate: cloud says "I only have up to seq 7, send from 8".
        ledger.reset_sync_cursor_to_sequence(8).unwrap();

        let (events, _) = ledger.unsynced_events(100).unwrap();
        assert_eq!(events.len(), 3); // seq 8, 9, 10
        assert_eq!(events[0].sequence_number, 8);
        assert_eq!(events[2].sequence_number, 10);

        // Chain state should be at seq 7.
        let (seq, _) = ledger.get_sync_chain_state().unwrap();
        assert_eq!(seq, 7);
    }

    #[test]
    fn partition_then_reconnect_preserves_chain() {
        // Simulates: proxy creates events 1-5, syncs 1-3, goes offline,
        // creates events 6-8 offline, reconnects, syncs remaining 4-8.
        let (ledger, _dir) = open_temp_ledger();
        let hash5 = insert_chain(&ledger, 5);

        // Sync first 3.
        let (events, max_rowid) = ledger.unsynced_events(3).unwrap();
        let hash3 = events[2].event_hash.clone();
        ledger.update_sync_cursor(max_rowid, 3, &hash3).unwrap();

        // "Go offline" — add 3 more events while disconnected.
        let e6 = make_signed_event("evt-6", &hash5, 6);
        ledger.append(&e6).unwrap();
        let e7 = make_signed_event("evt-7", &e6.event_hash, 7);
        ledger.append(&e7).unwrap();
        let e8 = make_signed_event("evt-8", &e7.event_hash, 8);
        ledger.append(&e8).unwrap();

        // "Reconnect" — unsynced should return events 4-8.
        let (events, _) = ledger.unsynced_events(100).unwrap();
        assert_eq!(events.len(), 5); // seq 4, 5, 6, 7, 8
        assert_eq!(events[0].sequence_number, 4);
        assert_eq!(events[4].sequence_number, 8);

        // The chain metadata would send expected_prev_hash = hash of event 3.
        let (_, last_synced_hash) = ledger.get_sync_chain_state().unwrap();
        assert_eq!(last_synced_hash, hash3);

        // Verify the chain is still intact locally.
        let (total, broken) = ledger.verify_chain().unwrap();
        assert_eq!(total, 8);
        assert!(broken.is_empty(), "Chain should be intact: {:?}", broken);
    }

    #[test]
    fn batch_hash_is_deterministic() {
        use sha2::{Digest, Sha256};

        let (ledger, _dir) = open_temp_ledger();
        insert_chain(&ledger, 3);

        let (events, _) = ledger.unsynced_events(100).unwrap();

        let compute_batch_hash = |evts: &[crate::ledger::AgentActionEvent]| -> String {
            let mut hasher = Sha256::new();
            for e in evts {
                hasher.update(e.event_hash.as_bytes());
            }
            hex::encode(hasher.finalize())
        };

        let hash1 = compute_batch_hash(&events);
        let hash2 = compute_batch_hash(&events);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn sync_response_deserializes() {
        let json = r#"{"accepted": 50, "chain_verified": true, "receipt_id": "rec_123"}"#;
        let resp: SyncResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.accepted, 50);
        assert!(resp.chain_verified);
        assert_eq!(resp.receipt_id.as_deref(), Some("rec_123"));
        assert!(resp.gap_from_sequence.is_none());
    }

    #[test]
    fn sync_response_with_gap() {
        let json = r#"{"accepted": 0, "chain_verified": false, "gap_from_sequence": 42}"#;
        let resp: SyncResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.accepted, 0);
        assert!(!resp.chain_verified);
        assert_eq!(resp.gap_from_sequence, Some(42));
    }
}
