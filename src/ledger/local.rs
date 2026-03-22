use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

use super::event::AgentActionEvent;

/// Local SQLite-backed ledger for development and standalone use.
pub struct LocalLedger {
    conn: Connection,
}

impl LocalLedger {
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;",
        )?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                event_id        TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                agent_version   TEXT NOT NULL,
                authorized_by   TEXT NOT NULL DEFAULT '',
                session_id      TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                tool_name       TEXT NOT NULL,
                tool_server     TEXT NOT NULL DEFAULT '',
                input_hash      TEXT NOT NULL,
                output_hash     TEXT NOT NULL DEFAULT '',
                policy_decision TEXT NOT NULL,
                policy_rule     TEXT NOT NULL DEFAULT '',
                latency_ms      INTEGER NOT NULL DEFAULT 0,
                sequence_number INTEGER NOT NULL DEFAULT 0,
                prev_hash       TEXT NOT NULL DEFAULT '',
                event_hash      TEXT NOT NULL,
                signature       TEXT NOT NULL,
                proxy_key_id    TEXT NOT NULL,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_tool_name ON events(tool_name);
            CREATE INDEX IF NOT EXISTS idx_events_policy_decision ON events(policy_decision);
            CREATE INDEX IF NOT EXISTS idx_events_sequence ON events(sequence_number);

            -- Tracks the sync watermark for cloud ledger streaming.
            -- last_synced_sequence + last_synced_hash enable chain continuity
            -- verification across network partitions.
            CREATE TABLE IF NOT EXISTS sync_state (
                id                   INTEGER PRIMARY KEY CHECK (id = 1),
                last_rowid           INTEGER NOT NULL DEFAULT 0,
                last_synced_sequence INTEGER NOT NULL DEFAULT 0,
                last_synced_hash     TEXT NOT NULL DEFAULT '',
                last_sync            TEXT NOT NULL DEFAULT '',
                sync_errors          INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO sync_state (id, last_rowid) VALUES (1, 0);",
        )?;

        Ok(Self { conn })
    }

    /// Append an event to the local ledger.
    pub fn append(&self, event: &AgentActionEvent) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (
                event_id, agent_id, agent_version, authorized_by, session_id,
                timestamp, tool_name, tool_server, input_hash, output_hash,
                policy_decision, policy_rule, latency_ms, sequence_number,
                prev_hash, event_hash, signature, proxy_key_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            rusqlite::params![
                event.event_id,
                event.agent_id,
                event.agent_version,
                event.authorized_by,
                event.session_id,
                event.timestamp.to_rfc3339(),
                event.tool_name,
                event.tool_server,
                event.input_hash,
                event.output_hash,
                event.policy_decision,
                event.policy_rule,
                event.latency_ms,
                event.sequence_number,
                event.prev_hash,
                event.event_hash,
                event.signature,
                event.proxy_key_id,
            ],
        )?;
        Ok(())
    }

    /// Get the next sequence number for this proxy instance.
    /// Sequence numbers are monotonically increasing and gap-free locally.
    /// The cloud uses these to detect missing events during sync.
    pub fn next_sequence_number(&self) -> Result<i64> {
        let max: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(sequence_number), 0) FROM events",
            [],
            |r| r.get(0),
        )?;
        Ok(max + 1)
    }

    /// Get the hash of the most recent event (for chain linking).
    pub fn last_event_hash(&self) -> Result<String> {
        let result: Option<String> = self
            .conn
            .query_row(
                "SELECT event_hash FROM events ORDER BY timestamp DESC, rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result.unwrap_or_default())
    }

    /// Query events with optional filters.
    pub fn query_events(
        &self,
        limit: Option<u32>,
        agent_id: Option<&str>,
    ) -> Result<Vec<AgentActionEvent>> {
        self.query_events_filtered(limit, agent_id, None, None, None)
    }

    /// Query events with full filter support.
    pub fn query_events_filtered(
        &self,
        limit: Option<u32>,
        agent_id: Option<&str>,
        tool_name: Option<&str>,
        decision: Option<&str>,
        since: Option<&str>,
    ) -> Result<Vec<AgentActionEvent>> {
        let mut sql = format!("SELECT {} FROM events", Self::EVENT_COLUMNS);

        let mut conditions: Vec<String> = vec![];
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];
        let mut param_idx = 1;

        if let Some(aid) = agent_id {
            conditions.push(format!("agent_id = ?{}", param_idx));
            params.push(Box::new(aid.to_string()));
            param_idx += 1;
        }
        if let Some(tool) = tool_name {
            if tool.contains('%') {
                conditions.push(format!("tool_name LIKE ?{}", param_idx));
            } else {
                conditions.push(format!("tool_name = ?{}", param_idx));
            }
            params.push(Box::new(tool.to_string()));
            param_idx += 1;
        }
        if let Some(dec) = decision {
            conditions.push(format!("policy_decision = ?{}", param_idx));
            params.push(Box::new(dec.to_uppercase()));
            param_idx += 1;
        }
        if let Some(ts) = since {
            conditions.push(format!("timestamp >= ?{}", param_idx));
            params.push(Box::new(ts.to_string()));
            // param_idx += 1; // last one, no need to increment
        }

        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }

        sql.push_str(" ORDER BY timestamp ASC, rowid ASC");

        if let Some(lim) = limit {
            sql.push_str(&format!(" LIMIT {}", lim));
        }

        let mut stmt = self.conn.prepare(&sql)?;
        let events = stmt
            .query_map(
                rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())),
                Self::row_to_event,
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(events)
    }

    /// Get events newer than the given rowid (for tail/streaming).
    pub fn events_after_rowid(&self, after_rowid: i64) -> Result<(Vec<AgentActionEvent>, i64)> {
        let sql = format!(
            "SELECT {}, rowid FROM events WHERE rowid > ?1 ORDER BY rowid ASC",
            Self::EVENT_COLUMNS,
        );
        let mut stmt = self.conn.prepare(&sql)?;

        let events: Vec<AgentActionEvent> = stmt
            .query_map([after_rowid], Self::row_to_event)?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // Get the current max rowid.
        let new_max: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(rowid), ?1) FROM events",
            [after_rowid],
            |r| r.get(0),
        )?;

        Ok((events, new_max))
    }

    /// Get the current max rowid (for initializing tail).
    pub fn max_rowid(&self) -> Result<i64> {
        let rowid: i64 =
            self.conn
                .query_row("SELECT COALESCE(MAX(rowid), 0) FROM events", [], |r| {
                    r.get(0)
                })?;
        Ok(rowid)
    }

    /// Get the current sync cursor (last synced rowid).
    pub fn get_sync_cursor(&self) -> Result<i64> {
        let rowid: i64 =
            self.conn
                .query_row("SELECT last_rowid FROM sync_state WHERE id = 1", [], |r| {
                    r.get(0)
                })?;
        Ok(rowid)
    }

    /// Update the sync cursor after successful cloud upload.
    /// Stores the rowid watermark, the last synced sequence number, and the
    /// event_hash of the last synced event (for chain continuity verification
    /// at the next batch boundary).
    pub fn update_sync_cursor(
        &self,
        rowid: i64,
        last_sequence: i64,
        last_hash: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE sync_state SET last_rowid = ?1, last_synced_sequence = ?2, last_synced_hash = ?3, last_sync = datetime('now'), sync_errors = 0 WHERE id = 1",
            rusqlite::params![rowid, last_sequence, last_hash],
        )?;
        Ok(())
    }

    /// Get the last synced sequence number and event hash.
    /// Used to build chain metadata for sync batches.
    pub fn get_sync_chain_state(&self) -> Result<(i64, String)> {
        let row: (i64, String) = self.conn.query_row(
            "SELECT last_synced_sequence, last_synced_hash FROM sync_state WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(row)
    }

    /// Reset the sync cursor to re-send events from a specific sequence number.
    /// Called when the cloud reports a gap and requests events starting from `from_sequence`.
    pub fn reset_sync_cursor_to_sequence(&self, from_sequence: i64) -> Result<()> {
        // Find the rowid of the event just before `from_sequence` so unsynced_events
        // will return events starting from `from_sequence`.
        let rowid: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(rowid), 0) FROM events WHERE sequence_number < ?1",
            rusqlite::params![from_sequence],
            |r| r.get(0),
        )?;

        // Also reset the last_synced_sequence/hash to the event just before the gap.
        let (seq, hash): (i64, String) = self
            .conn
            .query_row(
                "SELECT sequence_number, event_hash FROM events WHERE sequence_number < ?1 ORDER BY sequence_number DESC LIMIT 1",
                rusqlite::params![from_sequence],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or((0, String::new()));

        self.conn.execute(
            "UPDATE sync_state SET last_rowid = ?1, last_synced_sequence = ?2, last_synced_hash = ?3 WHERE id = 1",
            rusqlite::params![rowid, seq, hash],
        )?;
        Ok(())
    }

    /// Increment sync error count (for observability).
    pub fn increment_sync_errors(&self) -> Result<()> {
        self.conn.execute(
            "UPDATE sync_state SET sync_errors = sync_errors + 1 WHERE id = 1",
            [],
        )?;
        Ok(())
    }

    /// Get events that haven't been synced yet (after the sync cursor).
    pub fn unsynced_events(&self, batch_size: u32) -> Result<(Vec<AgentActionEvent>, i64)> {
        let cursor = self.get_sync_cursor()?;

        let sql = format!(
            "SELECT {}, rowid FROM events WHERE rowid > ?1 ORDER BY rowid ASC LIMIT ?2",
            Self::EVENT_COLUMNS,
        );
        let mut stmt = self.conn.prepare(&sql)?;

        let mut max_rowid = cursor;
        let events: Vec<AgentActionEvent> = stmt
            .query_map(rusqlite::params![cursor, batch_size], |row| {
                let rowid: i64 = row.get(18)?;
                let event = Self::row_to_event(row)?;
                Ok((event, rowid))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(event, rowid)| {
                if rowid > max_rowid {
                    max_rowid = rowid;
                }
                event
            })
            .collect();

        Ok((events, max_rowid))
    }

    /// Get per-tool statistics.
    pub fn tool_stats(&self) -> Result<Vec<ToolStats>> {
        let mut stmt = self.conn.prepare(
            "SELECT tool_name,
                    COUNT(*) as call_count,
                    SUM(CASE WHEN policy_decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN policy_decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN policy_decision = 'HUMAN_REQUIRED' THEN 1 ELSE 0 END) as human,
                    AVG(latency_ms) as avg_latency,
                    MIN(latency_ms) as min_latency,
                    MAX(latency_ms) as max_latency
             FROM events
             GROUP BY tool_name
             ORDER BY call_count DESC",
        )?;

        let stats = stmt
            .query_map([], |row| {
                Ok(ToolStats {
                    tool_name: row.get(0)?,
                    call_count: row.get(1)?,
                    allowed: row.get(2)?,
                    blocked: row.get(3)?,
                    human_required: row.get(4)?,
                    avg_latency_ms: row.get(5)?,
                    min_latency_ms: row.get(6)?,
                    max_latency_ms: row.get(7)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(stats)
    }

    /// Get latency percentiles across all events.
    pub fn latency_percentiles(&self) -> Result<LatencyStats> {
        let mut stmt = self.conn.prepare(
            "SELECT latency_ms FROM events WHERE policy_decision = 'ALLOW' ORDER BY latency_ms ASC",
        )?;
        let latencies: Vec<i64> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if latencies.is_empty() {
            return Ok(LatencyStats {
                p50: 0,
                p90: 0,
                p99: 0,
                max: 0,
            });
        }

        let p = |pct: f64| -> i64 {
            let idx = ((pct / 100.0) * (latencies.len() as f64 - 1.0)).round() as usize;
            latencies[idx.min(latencies.len() - 1)]
        };

        Ok(LatencyStats {
            p50: p(50.0),
            p90: p(90.0),
            p99: p(99.0),
            max: *latencies.last().unwrap(),
        })
    }

    /// Get per-session statistics.
    pub fn session_stats(&self) -> Result<Vec<SessionStats>> {
        let mut stmt = self.conn.prepare(
            "SELECT session_id, agent_id,
                    COUNT(*) as call_count,
                    MIN(timestamp) as first_call,
                    MAX(timestamp) as last_call
             FROM events
             GROUP BY session_id
             ORDER BY first_call DESC
             LIMIT 20",
        )?;

        let stats = stmt
            .query_map([], |row| {
                Ok(SessionStats {
                    session_id: row.get(0)?,
                    agent_id: row.get(1)?,
                    call_count: row.get(2)?,
                    first_call: row.get(3)?,
                    last_call: row.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(stats)
    }

    /// Standard SELECT column list for events (used by all query methods).
    const EVENT_COLUMNS: &str = "event_id, agent_id, agent_version, authorized_by, session_id,
         timestamp, tool_name, tool_server, input_hash, output_hash,
         policy_decision, policy_rule, latency_ms, sequence_number,
         prev_hash, event_hash, signature, proxy_key_id";

    fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<AgentActionEvent> {
        let ts_str: String = row.get(5)?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(&ts_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        Ok(AgentActionEvent {
            event_id: row.get(0)?,
            agent_id: row.get(1)?,
            agent_version: row.get(2)?,
            authorized_by: row.get(3)?,
            session_id: row.get(4)?,
            timestamp,
            tool_name: row.get(6)?,
            tool_server: row.get(7)?,
            input_hash: row.get(8)?,
            output_hash: row.get(9)?,
            input_data: None, // Not stored in local SQLite — only synced to cloud
            output_data: None,
            policy_decision: row.get(10)?,
            policy_rule: row.get(11)?,
            latency_ms: row.get(12)?,
            sequence_number: row.get(13)?,
            prev_hash: row.get(14)?,
            event_hash: row.get(15)?,
            signature: row.get(16)?,
            proxy_key_id: row.get(17)?,
        })
    }

    /// Verify the hash chain integrity. Returns (total_events, broken_links).
    pub fn verify_chain(&self) -> Result<(usize, Vec<String>)> {
        let events = self.query_events(None, None)?;
        let mut broken = vec![];

        for (i, event) in events.iter().enumerate() {
            // Verify self-hash
            let computed = event.compute_hash();
            if computed != event.event_hash {
                broken.push(format!("Event {} has invalid self-hash", event.event_id));
            }

            // Verify chain link
            if i > 0 {
                let prev = &events[i - 1];
                if event.prev_hash != prev.event_hash {
                    broken.push(format!(
                        "Event {} has broken chain link (expected prev_hash={}, got={})",
                        event.event_id, prev.event_hash, event.prev_hash
                    ));
                }
            }
        }

        Ok((events.len(), broken))
    }

    /// Get summary statistics for the report.
    pub fn summary_stats(&self) -> Result<ReportStats> {
        let total: u64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        let blocked: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE policy_decision = 'BLOCK'",
            [],
            |r| r.get(0),
        )?;
        let human_required: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE policy_decision = 'HUMAN_REQUIRED'",
            [],
            |r| r.get(0),
        )?;
        let allowed: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE policy_decision = 'ALLOW'",
            [],
            |r| r.get(0),
        )?;

        let unique_tools: u64 =
            self.conn
                .query_row("SELECT COUNT(DISTINCT tool_name) FROM events", [], |r| {
                    r.get(0)
                })?;
        let unique_agents: u64 =
            self.conn
                .query_row("SELECT COUNT(DISTINCT agent_id) FROM events", [], |r| {
                    r.get(0)
                })?;

        let first_event: Option<String> = self
            .conn
            .query_row("SELECT MIN(timestamp) FROM events", [], |r| r.get(0))
            .optional()?
            .flatten();
        let last_event: Option<String> = self
            .conn
            .query_row("SELECT MAX(timestamp) FROM events", [], |r| r.get(0))
            .optional()?
            .flatten();

        Ok(ReportStats {
            total_events: total,
            allowed,
            blocked,
            human_required,
            unique_tools,
            unique_agents,
            first_event,
            last_event,
        })
    }
}

#[derive(serde::Serialize)]
pub struct ReportStats {
    pub total_events: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub human_required: u64,
    pub unique_tools: u64,
    pub unique_agents: u64,
    pub first_event: Option<String>,
    pub last_event: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ToolStats {
    pub tool_name: String,
    pub call_count: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub human_required: u64,
    pub avg_latency_ms: f64,
    pub min_latency_ms: i64,
    pub max_latency_ms: i64,
}

#[derive(serde::Serialize)]
pub struct LatencyStats {
    pub p50: i64,
    pub p90: i64,
    pub p99: i64,
    pub max: i64,
}

#[derive(serde::Serialize)]
pub struct SessionStats {
    pub session_id: String,
    pub agent_id: String,
    pub call_count: u64,
    pub first_call: String,
    pub last_call: String,
}

/// Extension trait for optional query results.
trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for std::result::Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::event::sha256_hex;
    use tempfile::TempDir;

    fn make_signed_event(
        event_id: &str,
        tool_name: &str,
        decision: &str,
        prev_hash: &str,
    ) -> AgentActionEvent {
        make_signed_event_seq(event_id, tool_name, decision, prev_hash, 0)
    }

    fn make_signed_event_seq(
        event_id: &str,
        tool_name: &str,
        decision: &str,
        prev_hash: &str,
        sequence_number: i64,
    ) -> AgentActionEvent {
        let mut event = AgentActionEvent {
            event_id: event_id.to_string(),
            agent_id: "test-agent".to_string(),
            agent_version: "0.1.0".to_string(),
            authorized_by: "tester".to_string(),
            session_id: "session-1".to_string(),
            timestamp: chrono::Utc::now(),
            tool_name: tool_name.to_string(),
            tool_server: "".to_string(),
            input_hash: sha256_hex(b"input"),
            output_hash: sha256_hex(b"output"),
            input_data: None,
            output_data: None,
            policy_decision: decision.to_string(),
            policy_rule: "".to_string(),
            latency_ms: 2,
            sequence_number,
            prev_hash: prev_hash.to_string(),
            event_hash: "".to_string(),
            signature: "fake-sig".to_string(),
            proxy_key_id: "test-key".to_string(),
        };
        event.event_hash = event.compute_hash();
        event
    }

    fn open_temp_ledger() -> (LocalLedger, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let ledger = LocalLedger::open(&db_path).unwrap();
        (ledger, dir)
    }

    #[test]
    fn append_and_query_events() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "tool_a", "ALLOW", "");
        ledger.append(&e1).unwrap();

        let e2 = make_signed_event("evt-2", "tool_b", "BLOCK", &e1.event_hash);
        ledger.append(&e2).unwrap();

        let events = ledger.query_events(None, None).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, "evt-1");
        assert_eq!(events[1].event_id, "evt-2");
    }

    #[test]
    fn last_event_hash_empty_db() {
        let (ledger, _dir) = open_temp_ledger();
        assert_eq!(ledger.last_event_hash().unwrap(), "");
    }

    #[test]
    fn last_event_hash_returns_latest() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "tool_a", "ALLOW", "");
        ledger.append(&e1).unwrap();

        assert_eq!(ledger.last_event_hash().unwrap(), e1.event_hash);

        let e2 = make_signed_event("evt-2", "tool_b", "ALLOW", &e1.event_hash);
        ledger.append(&e2).unwrap();

        assert_eq!(ledger.last_event_hash().unwrap(), e2.event_hash);
    }

    #[test]
    fn verify_chain_intact() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "tool_a", "ALLOW", "");
        ledger.append(&e1).unwrap();

        let e2 = make_signed_event("evt-2", "tool_b", "ALLOW", &e1.event_hash);
        ledger.append(&e2).unwrap();

        let e3 = make_signed_event("evt-3", "tool_c", "BLOCK", &e2.event_hash);
        ledger.append(&e3).unwrap();

        let (total, broken) = ledger.verify_chain().unwrap();
        assert_eq!(total, 3);
        assert!(broken.is_empty());
    }

    #[test]
    fn verify_chain_detects_broken_link() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "tool_a", "ALLOW", "");
        ledger.append(&e1).unwrap();

        // e2 has wrong prev_hash — chain is broken.
        let e2 = make_signed_event("evt-2", "tool_b", "ALLOW", "wrong-hash");
        ledger.append(&e2).unwrap();

        let (total, broken) = ledger.verify_chain().unwrap();
        assert_eq!(total, 2);
        assert_eq!(broken.len(), 1);
        assert!(broken[0].contains("broken chain link"));
    }

    #[test]
    fn verify_chain_detects_tampered_hash() {
        let (ledger, _dir) = open_temp_ledger();

        let mut e1 = make_signed_event("evt-1", "tool_a", "ALLOW", "");
        // Tamper with the hash after computing it.
        e1.event_hash = "tampered".to_string();
        ledger.append(&e1).unwrap();

        let (total, broken) = ledger.verify_chain().unwrap();
        assert_eq!(total, 1);
        assert_eq!(broken.len(), 1);
        assert!(broken[0].contains("invalid self-hash"));
    }

    #[test]
    fn filter_by_tool_name() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "stripe.pay", "ALLOW", "");
        ledger.append(&e1).unwrap();
        let e2 = make_signed_event("evt-2", "plaid.auth", "ALLOW", &e1.event_hash);
        ledger.append(&e2).unwrap();

        let filtered = ledger
            .query_events_filtered(None, None, Some("stripe.pay"), None, None)
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].tool_name, "stripe.pay");
    }

    #[test]
    fn filter_by_decision() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "tool_a", "ALLOW", "");
        ledger.append(&e1).unwrap();
        let e2 = make_signed_event("evt-2", "tool_b", "BLOCK", &e1.event_hash);
        ledger.append(&e2).unwrap();
        let e3 = make_signed_event("evt-3", "tool_c", "ALLOW", &e2.event_hash);
        ledger.append(&e3).unwrap();

        let blocked = ledger
            .query_events_filtered(None, None, None, Some("BLOCK"), None)
            .unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].event_id, "evt-2");

        let allowed = ledger
            .query_events_filtered(None, None, None, Some("allow"), None)
            .unwrap();
        assert_eq!(allowed.len(), 2);
    }

    #[test]
    fn summary_stats() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "tool_a", "ALLOW", "");
        ledger.append(&e1).unwrap();
        let e2 = make_signed_event("evt-2", "tool_b", "BLOCK", &e1.event_hash);
        ledger.append(&e2).unwrap();
        let e3 = make_signed_event("evt-3", "tool_a", "HUMAN_REQUIRED", &e2.event_hash);
        ledger.append(&e3).unwrap();

        let stats = ledger.summary_stats().unwrap();
        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.blocked, 1);
        assert_eq!(stats.human_required, 1);
        assert_eq!(stats.unique_tools, 2);
        assert_eq!(stats.unique_agents, 1);
    }

    #[test]
    fn tool_stats_breakdown() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "tool_a", "ALLOW", "");
        ledger.append(&e1).unwrap();
        let e2 = make_signed_event("evt-2", "tool_a", "ALLOW", &e1.event_hash);
        ledger.append(&e2).unwrap();
        let e3 = make_signed_event("evt-3", "tool_b", "BLOCK", &e2.event_hash);
        ledger.append(&e3).unwrap();

        let stats = ledger.tool_stats().unwrap();
        assert_eq!(stats.len(), 2);
        // tool_a has more calls, should be first (ordered by count DESC).
        assert_eq!(stats[0].tool_name, "tool_a");
        assert_eq!(stats[0].call_count, 2);
        assert_eq!(stats[1].tool_name, "tool_b");
        assert_eq!(stats[1].call_count, 1);
    }

    #[test]
    fn tail_events_after_rowid() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event("evt-1", "tool_a", "ALLOW", "");
        ledger.append(&e1).unwrap();

        let rowid = ledger.max_rowid().unwrap();

        let e2 = make_signed_event("evt-2", "tool_b", "ALLOW", &e1.event_hash);
        ledger.append(&e2).unwrap();

        let (new_events, new_rowid) = ledger.events_after_rowid(rowid).unwrap();
        assert_eq!(new_events.len(), 1);
        assert_eq!(new_events[0].event_id, "evt-2");
        assert!(new_rowid > rowid);
    }

    #[test]
    fn next_sequence_number_starts_at_one() {
        let (ledger, _dir) = open_temp_ledger();
        assert_eq!(ledger.next_sequence_number().unwrap(), 1);
    }

    #[test]
    fn next_sequence_number_increments() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event_seq("evt-1", "tool_a", "ALLOW", "", 1);
        ledger.append(&e1).unwrap();
        assert_eq!(ledger.next_sequence_number().unwrap(), 2);

        let e2 = make_signed_event_seq("evt-2", "tool_b", "ALLOW", &e1.event_hash, 2);
        ledger.append(&e2).unwrap();
        assert_eq!(ledger.next_sequence_number().unwrap(), 3);
    }

    #[test]
    fn sequence_number_roundtrips_through_db() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event_seq("evt-1", "tool_a", "ALLOW", "", 42);
        ledger.append(&e1).unwrap();

        let events = ledger.query_events(None, None).unwrap();
        assert_eq!(events[0].sequence_number, 42);
    }

    #[test]
    fn sync_chain_state_tracks_sequence_and_hash() {
        let (ledger, _dir) = open_temp_ledger();

        let e1 = make_signed_event_seq("evt-1", "tool_a", "ALLOW", "", 1);
        ledger.append(&e1).unwrap();

        let (seq, hash) = ledger.get_sync_chain_state().unwrap();
        assert_eq!(seq, 0);
        assert_eq!(hash, "");

        let max_rowid = ledger.max_rowid().unwrap();
        ledger
            .update_sync_cursor(max_rowid, 1, &e1.event_hash)
            .unwrap();

        let (seq, hash) = ledger.get_sync_chain_state().unwrap();
        assert_eq!(seq, 1);
        assert_eq!(hash, e1.event_hash);
    }

    #[test]
    fn reset_sync_cursor_to_sequence() {
        let (ledger, _dir) = open_temp_ledger();

        // Insert 5 events with sequence 1-5.
        let e1 = make_signed_event_seq("evt-1", "tool_a", "ALLOW", "", 1);
        ledger.append(&e1).unwrap();
        let e2 = make_signed_event_seq("evt-2", "tool_a", "ALLOW", &e1.event_hash, 2);
        ledger.append(&e2).unwrap();
        let e3 = make_signed_event_seq("evt-3", "tool_a", "ALLOW", &e2.event_hash, 3);
        ledger.append(&e3).unwrap();
        let e4 = make_signed_event_seq("evt-4", "tool_a", "ALLOW", &e3.event_hash, 4);
        ledger.append(&e4).unwrap();
        let e5 = make_signed_event_seq("evt-5", "tool_a", "ALLOW", &e4.event_hash, 5);
        ledger.append(&e5).unwrap();

        // Sync all 5.
        let max_rowid = ledger.max_rowid().unwrap();
        ledger
            .update_sync_cursor(max_rowid, 5, &e5.event_hash)
            .unwrap();

        // Cloud says: "I only have up to seq 3, send me from seq 4."
        ledger.reset_sync_cursor_to_sequence(4).unwrap();

        // Now unsynced_events should return events 4 and 5.
        let (events, _) = ledger.unsynced_events(100).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence_number, 4);
        assert_eq!(events[1].sequence_number, 5);

        // Chain state should reflect seq 3.
        let (seq, hash) = ledger.get_sync_chain_state().unwrap();
        assert_eq!(seq, 3);
        assert_eq!(hash, e3.event_hash);
    }

    #[test]
    fn empty_db_stats() {
        let (ledger, _dir) = open_temp_ledger();

        let stats = ledger.summary_stats().unwrap();
        assert_eq!(stats.total_events, 0);

        let (total, broken) = ledger.verify_chain().unwrap();
        assert_eq!(total, 0);
        assert!(broken.is_empty());

        let latency = ledger.latency_percentiles().unwrap();
        assert_eq!(latency.p50, 0);
    }
}
