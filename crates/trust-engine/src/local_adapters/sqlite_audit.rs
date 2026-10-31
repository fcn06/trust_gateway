use crate::traits::{AuditSink, EngineError};
use async_trait::async_trait;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use trust_sdk::canonical::canonical_json;
use trust_sdk::model::AuditEvent;

pub struct SqliteAuditSink {
    #[allow(dead_code)]
    db_path: Option<PathBuf>,
    conn: Arc<Mutex<Connection>>,
}

impl SqliteAuditSink {
    pub fn in_memory() -> Result<Self, EngineError> {
        let conn = Connection::open_in_memory().map_err(|e| {
            EngineError::StorageError(format!("Failed to open in-memory SQLite: {e}"))
        })?;
        Self::init(conn, None)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, EngineError> {
        let p = path.as_ref().to_path_buf();
        let conn = Connection::open(&p).map_err(|e| {
            EngineError::StorageError(format!("Failed to open SQLite audit db: {e}"))
        })?;
        Self::init(conn, Some(p))
    }

    fn init(conn: Connection, path: Option<PathBuf>) -> Result<Self, EngineError> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                action_id TEXT,
                details TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );",
            [],
        )
        .map_err(|e| EngineError::StorageError(format!("Failed to create audit table: {e}")))?;

        Ok(Self {
            db_path: path,
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn get_last_hash(conn: &Connection) -> Result<String, EngineError> {
        let mut stmt = conn
            .prepare("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1;")
            .map_err(|e| EngineError::StorageError(e.to_string()))?;

        let mut rows = stmt
            .query([])
            .map_err(|e| EngineError::StorageError(e.to_string()))?;

        if let Some(row) = rows
            .next()
            .map_err(|e| EngineError::StorageError(e.to_string()))?
        {
            let h: String = row
                .get(0)
                .map_err(|e| EngineError::StorageError(e.to_string()))?;
            Ok(h)
        } else {
            Ok("0".repeat(64))
        }
    }

    pub fn compute_event_hash(ev: &AuditEvent, prev_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(ev.event_id.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(ev.timestamp.to_string().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(ev.event_type.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(ev.tenant_id.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(ev.trace_id.as_bytes());
        hasher.update(b"\x1f");
        if let Some(ref act) = ev.action_id {
            hasher.update(act.as_bytes());
        }
        hasher.update(b"\x1f");
        hasher.update(canonical_json(&ev.details).as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn get_events_by_trace(&self, trace_id: &str) -> Result<Vec<AuditEvent>, EngineError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT event_id, timestamp, event_type, tenant_id, trace_id, action_id, details, prev_hash, hash FROM audit_events WHERE trace_id = ? ORDER BY id ASC;")
            .map_err(|e| EngineError::StorageError(e.to_string()))?;

        let rows = stmt
            .query_map([trace_id], |row| {
                let event_id: String = row.get(0)?;
                let timestamp: i64 = row.get(1)?;
                let event_type: String = row.get(2)?;
                let tenant_id: String = row.get(3)?;
                let trace_id: String = row.get(4)?;
                let action_id: Option<String> = row.get(5)?;
                let details_str: String = row.get(6)?;
                let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or_default();
                let prev_hash: Option<String> = row.get(7).ok();
                let hash: Option<String> = row.get(8).ok();

                Ok(AuditEvent {
                    event_id,
                    timestamp,
                    event_type,
                    tenant_id,
                    trace_id,
                    action_id,
                    details,
                    prev_hash,
                    hash,
                })
            })
            .map_err(|e| EngineError::StorageError(e.to_string()))?;

        let mut events = Vec::new();
        for r in rows {
            events.push(r.map_err(|e| EngineError::StorageError(e.to_string()))?);
        }
        Ok(events)
    }

    pub fn verify_chain(&self) -> Result<usize, EngineError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, event_id, timestamp, event_type, tenant_id, trace_id, action_id, details, prev_hash, hash FROM audit_events ORDER BY id ASC;")
            .map_err(|e| EngineError::StorageError(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })
            .map_err(|e| EngineError::StorageError(e.to_string()))?;

        let mut expected_prev = "0".repeat(64);
        let mut count = 0;

        for r in rows {
            let (
                id,
                event_id,
                timestamp,
                event_type,
                tenant_id,
                trace_id,
                action_id,
                details_str,
                prev_hash,
                stored_hash,
            ) = r.map_err(|e| EngineError::StorageError(e.to_string()))?;

            if prev_hash != expected_prev {
                return Err(EngineError::StorageError(format!(
                    "Audit chain broken at row {id}: expected prev_hash '{expected_prev}', found '{prev_hash}'"
                )));
            }

            let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or_default();
            let ev = AuditEvent {
                event_id,
                timestamp,
                event_type,
                tenant_id,
                trace_id,
                action_id,
                details,
                prev_hash: Some(prev_hash),
                hash: Some(stored_hash.clone()),
            };

            let computed = Self::compute_event_hash(&ev, &expected_prev);
            if computed != stored_hash {
                return Err(EngineError::StorageError(format!(
                    "Audit hash mismatch at row {id}: computed '{computed}', stored '{stored_hash}'"
                )));
            }

            expected_prev = stored_hash;
            count += 1;
        }

        Ok(count)
    }
}

#[async_trait]
impl AuditSink for SqliteAuditSink {
    async fn append(&self, mut ev: AuditEvent) -> Result<(), EngineError> {
        let conn = self.conn.lock().unwrap();
        let prev_hash = Self::get_last_hash(&conn)?;
        let hash = Self::compute_event_hash(&ev, &prev_hash);

        ev.prev_hash = Some(prev_hash.clone());
        ev.hash = Some(hash.clone());

        let details_str = serde_json::to_string(&ev.details).unwrap_or_default();

        conn.execute(
            "INSERT INTO audit_events (event_id, timestamp, event_type, tenant_id, trace_id, action_id, details, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);",
            rusqlite::params![
                ev.event_id,
                ev.timestamp,
                ev.event_type,
                ev.tenant_id,
                ev.trace_id,
                ev.action_id,
                details_str,
                prev_hash,
                hash,
            ],
        )
        .map_err(|e| EngineError::StorageError(format!("Failed to insert audit event: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_hash_chain() {
        let sink = SqliteAuditSink::in_memory().unwrap();
        let ev1 = AuditEvent {
            event_id: "ev_1".to_string(),
            timestamp: 1000,
            event_type: "grant_issued".to_string(),
            tenant_id: "default".to_string(),
            trace_id: "tr_1".to_string(),
            action_id: Some("act_1".to_string()),
            details: serde_json::json!({"tool": "weather"}),
            prev_hash: None,
            hash: None,
        };
        sink.append(ev1).await.unwrap();

        let ev2 = AuditEvent {
            event_id: "ev_2".to_string(),
            timestamp: 1001,
            event_type: "executed".to_string(),
            tenant_id: "default".to_string(),
            trace_id: "tr_1".to_string(),
            action_id: Some("act_1".to_string()),
            details: serde_json::json!({"status": "success"}),
            prev_hash: None,
            hash: None,
        };
        sink.append(ev2).await.unwrap();

        let verified_count = sink.verify_chain().expect("chain should verify");
        assert_eq!(verified_count, 2);

        // Test trace_id query (OB-INV-11)
        let trace_events = sink.get_events_by_trace("tr_1").expect("Query must succeed");
        assert_eq!(trace_events.len(), 2);
        assert_eq!(trace_events[0].event_id, "ev_1");
        assert_eq!(trace_events[1].event_id, "ev_2");

        let empty_events = sink.get_events_by_trace("nonexistent_trace").expect("Query must succeed");
        assert!(empty_events.is_empty());
    }
}
