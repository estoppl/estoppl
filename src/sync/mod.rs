use anyhow::{Context, Result};
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

/// Background task that streams signed events from the local SQLite ledger
/// to the Estoppl cloud endpoint.
///
/// Design:
/// - Polls local DB for events after the sync cursor (watermark)
/// - Batches events into POST requests to the cloud endpoint
/// - Updates the sync cursor on success
/// - Exponential backoff on failure (capped at 5 minutes)
/// - Graceful shutdown via watch channel
pub struct CloudSyncer {
    config: SyncConfig,
    db_path: PathBuf,
    http_client: reqwest::Client,
    shutdown_rx: watch::Receiver<bool>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Cloud API contract (TODO: implement on the cloud side)
//
// POST {endpoint}
//   Headers:
//     Authorization: Bearer {api_key}
//     Content-Type: application/json
//     X-Estoppl-Proxy-Key-Id: {proxy_key_id}
//
//   Body:
//     {
//       "events": [ ...array of AgentActionEvent... ],
//       "proxy_version": "0.1.0"
//     }
//
//   Response 200:
//     {
//       "accepted": 50,
//       "receipt_id": "rec_abc123",
//       "receipt_hash": "sha256..."
//     }
//
//   Response 409 (duplicate events — idempotent, treat as success):
//     { "accepted": 0, "message": "events already ingested" }
//
//   Response 401: invalid API key
//   Response 429: rate limited (respect Retry-After header)
//
// Cloud infrastructure recommendations (TODO):
//   - **Preferred**: AWS (API Gateway + Lambda + DynamoDB or S3 for WORM storage)
//     - DynamoDB for hot queries, S3 + Athena for cold audit trails
//     - API Gateway handles auth, rate limiting, TLS termination
//     - Lambda keeps costs near-zero at low volume
//   - **Alternative**: Fly.io or Railway for simpler deployment
//     - Postgres with append-only table + pg_partman for time partitions
//   - WORM storage: S3 Object Lock (Governance or Compliance mode) for
//     tamper-proof evidence packs
//   - Event ingestion should be idempotent (dedupe on event_id)
//   - Cloud should verify event signatures using the proxy's public key
//   - Cloud should verify hash chain continuity per proxy_key_id
// ──────────────────────────────────────────────────────────────────────────────

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
    /// Returns a JoinHandle that resolves when the syncer stops.
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
            // Check for shutdown signal.
            if *self.shutdown_rx.borrow() {
                tracing::info!("Cloud syncer shutting down");
                break;
            }

            match self.sync_batch().await {
                Ok(synced) => {
                    if synced > 0 {
                        tracing::info!(events = synced, "Synced events to cloud");
                        backoff_secs = 1; // Reset backoff on success.
                        // If we got a full batch, immediately try again (more events may be waiting).
                        continue;
                    }
                    // No events to sync — wait for the polling interval.
                    backoff_secs = 1;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        retry_in_secs = backoff_secs,
                        "Cloud sync failed, will retry"
                    );

                    // Track the error in the DB for observability.
                    if let Ok(ledger) = LocalLedger::open(&self.db_path) {
                        let _ = ledger.increment_sync_errors();
                    }

                    // Exponential backoff.
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

    /// Attempt to sync one batch of events. Returns number of events synced.
    async fn sync_batch(&self) -> Result<usize> {
        // Open a fresh connection each poll to see WAL commits from the proxy process.
        let ledger = LocalLedger::open(&self.db_path).context("Failed to open ledger for sync")?;

        let (events, max_rowid) = ledger.unsynced_events(self.config.batch_size)?;

        if events.is_empty() {
            return Ok(0);
        }

        let count = events.len();

        tracing::debug!(
            count = count,
            max_rowid = max_rowid,
            "Sending batch to cloud"
        );

        // Build the request payload.
        let payload = serde_json::json!({
            "events": events,
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

        if status.is_success() || status.as_u16() == 409 {
            // 200 = accepted, 409 = already ingested (idempotent success).
            ledger.update_sync_cursor(max_rowid)?;
            tracing::debug!(status = status.as_u16(), "Cloud accepted batch");
            return Ok(count);
        }

        if status.as_u16() == 401 {
            anyhow::bail!(
                "Cloud returned 401 Unauthorized — check your API key in estoppl.toml [ledger] cloud_api_key"
            );
        }

        if status.as_u16() == 429 {
            // Rate limited — the backoff in run() will handle retry timing.
            anyhow::bail!("Cloud returned 429 Too Many Requests");
        }

        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Cloud returned {}: {}", status.as_u16(), body);
    }
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

    fn make_signed_event(event_id: &str, prev_hash: &str) -> crate::ledger::AgentActionEvent {
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
            prev_hash: prev_hash.to_string(),
            event_hash: "".to_string(),
            signature: "fake-sig".to_string(),
            proxy_key_id: "test-key".to_string(),
        };
        event.event_hash = event.compute_hash();
        event
    }

    #[test]
    fn sync_cursor_starts_at_zero() {
        let (ledger, _dir) = open_temp_ledger();
        assert_eq!(ledger.get_sync_cursor().unwrap(), 0);
    }

    #[test]
    fn sync_cursor_updates() {
        let (ledger, _dir) = open_temp_ledger();
        ledger.update_sync_cursor(42).unwrap();
        assert_eq!(ledger.get_sync_cursor().unwrap(), 42);
    }

    #[test]
    fn unsynced_events_returns_new_events() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "");
        ledger.append(&e1).unwrap();
        let e2 = make_signed_event("evt-2", &e1.event_hash);
        ledger.append(&e2).unwrap();

        let (events, max_rowid) = ledger.unsynced_events(100).unwrap();
        assert_eq!(events.len(), 2);
        assert!(max_rowid > 0);

        // Mark as synced.
        ledger.update_sync_cursor(max_rowid).unwrap();

        // No more unsynced events.
        let (events, _) = ledger.unsynced_events(100).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn unsynced_events_respects_batch_size() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "");
        ledger.append(&e1).unwrap();
        let e2 = make_signed_event("evt-2", &e1.event_hash);
        ledger.append(&e2).unwrap();
        let e3 = make_signed_event("evt-3", &e2.event_hash);
        ledger.append(&e3).unwrap();

        // Only get first 2.
        let (events, max_rowid) = ledger.unsynced_events(2).unwrap();
        assert_eq!(events.len(), 2);

        ledger.update_sync_cursor(max_rowid).unwrap();

        // Get the remaining 1.
        let (events, _) = ledger.unsynced_events(2).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-3");
    }

    #[test]
    fn increment_sync_errors_works() {
        let (ledger, _dir) = open_temp_ledger();
        ledger.increment_sync_errors().unwrap();
        ledger.increment_sync_errors().unwrap();
        // Just verify it doesn't panic — the count is internal.
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
        assert_eq!(c.batch_size, 100);
        assert_eq!(c.interval_secs, 5);
    }
}
