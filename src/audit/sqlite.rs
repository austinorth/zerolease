//! SQLite-backed audit log for persistent, queryable event storage.
//!
//! Stores audit events in a separate SQLite database file from secrets.
//! Events are stored with denormalized `secret_name` and `lease_id`
//! columns for efficient querying by the `AuditLog` trait methods.

use std::path::Path;

use chrono::Utc;
use serde_json;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::audit::{AuditEntry, AuditEvent, AuditLog, AuditOutcome};
use crate::error::{Error, Result};
use crate::types::{AgentId, LeaseId, SecretName};

/// A persistent audit log backed by SQLite.
///
/// Each event is stored with denormalized `secret_name` and `lease_id`
/// columns extracted from the event variant, enabling efficient
/// `query_by_secret` and `query_by_lease` without JSON parsing.
pub struct SqliteAuditLog {
    pool: SqlitePool,
}

impl SqliteAuditLog {
    /// Create a new SQLite audit log at the given path.
    /// Creates the file, schema, and indexes if they don't exist.
    /// Uses WAL mode for concurrent read/write performance.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path.as_ref())
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|e| Error::Storage(format!("failed to open audit database: {e}")))?;

        sqlx::query(include_str!("../../sql/sqlite_audit_table.sql"))
            .execute(&pool)
            .await
            .map_err(|e| Error::Storage(format!("failed to create audit_events table: {e}")))?;

        // Create indexes for query methods
        for idx in [
            "CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent)",
            "CREATE INDEX IF NOT EXISTS idx_audit_secret ON audit_events(secret_name)",
            "CREATE INDEX IF NOT EXISTS idx_audit_lease ON audit_events(lease_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)",
        ] {
            sqlx::query(idx)
                .execute(&pool)
                .await
                .map_err(|e| Error::Storage(format!("failed to create index: {e}")))?;
        }

        Ok(Self { pool })
    }
}

/// Extract denormalized `secret_name` and `lease_id` fields from an audit
/// event.
fn extract_event_fields(event: &AuditEvent) -> (Option<String>, Option<String>) {
    match event {
        AuditEvent::LeaseGranted {
            secret_name, lease_id, ..
        } => (
            Some(secret_name.as_str().to_string()),
            Some(lease_id.as_uuid().to_string()),
        ),
        AuditEvent::SecretAccessed {
            secret_name, lease_id, ..
        } => (
            Some(secret_name.as_str().to_string()),
            Some(lease_id.as_uuid().to_string()),
        ),
        AuditEvent::LeaseRevoked { lease_id, .. } => (None, Some(lease_id.as_uuid().to_string())),
        AuditEvent::LeaseRenewed { lease_id, .. } => (None, Some(lease_id.as_uuid().to_string())),
        AuditEvent::AccessDenied { secret_name, .. } => (Some(secret_name.as_str().to_string()), None),
        AuditEvent::SecretStored { secret_name } => (Some(secret_name.as_str().to_string()), None),
        AuditEvent::SecretRotated { secret_name, .. } => (Some(secret_name.as_str().to_string()), None),
        AuditEvent::SecretDeleted { secret_name } => (Some(secret_name.as_str().to_string()), None),
        AuditEvent::DekRotated => (None, None),
        AuditEvent::PolicyReloaded { .. } => (None, None),
    }
}

/// Deserialize a SQLite row into an `AuditEntry`.
fn row_to_audit_entry(row: &sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
    let event_id_str: String = row.try_get("event_id").map_err(|e| Error::Storage(e.to_string()))?;
    let event_id = Uuid::parse_str(&event_id_str).map_err(|e| Error::Storage(format!("invalid event_id: {e}")))?;

    let timestamp_str: String = row.try_get("timestamp").map_err(|e| Error::Storage(e.to_string()))?;
    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
        .map_err(|e| Error::Storage(format!("invalid timestamp: {e}")))?
        .with_timezone(&Utc);

    let event_str: String = row.try_get("event").map_err(|e| Error::Storage(e.to_string()))?;
    let event: AuditEvent =
        serde_json::from_str(&event_str).map_err(|e| Error::Storage(format!("invalid event JSON: {e}")))?;

    let agent_str: String = row.try_get("agent").map_err(|e| Error::Storage(e.to_string()))?;
    let peer_identity: String = row
        .try_get("peer_identity")
        .map_err(|e| Error::Storage(e.to_string()))?;

    let outcome_str: String = row.try_get("outcome").map_err(|e| Error::Storage(e.to_string()))?;
    let outcome: AuditOutcome =
        serde_json::from_str(&outcome_str).map_err(|e| Error::Storage(format!("invalid outcome JSON: {e}")))?;

    Ok(AuditEntry {
        event_id,
        timestamp,
        event,
        agent: AgentId::new(agent_str),
        peer_identity,
        outcome,
    })
}

#[async_trait::async_trait]
impl AuditLog for SqliteAuditLog {
    async fn record(&self, entry: AuditEntry) -> Result<()> {
        let (secret_name, lease_id) = extract_event_fields(&entry.event);
        let event_id_str = entry.event_id.to_string();
        let timestamp_str = entry.timestamp.to_rfc3339();
        let event_str = serde_json::to_string(&entry.event)
            .map_err(|e| Error::Storage(format!("failed to serialize event: {e}")))?;
        let agent_str = entry.agent.as_str().to_string();
        let outcome_str = serde_json::to_string(&entry.outcome)
            .map_err(|e| Error::Storage(format!("failed to serialize outcome: {e}")))?;

        sqlx::query(
            "INSERT INTO audit_events (event_id, timestamp, event, agent, peer_identity, outcome, secret_name, lease_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&event_id_str)
        .bind(&timestamp_str)
        .bind(&event_str)
        .bind(&agent_str)
        .bind(&entry.peer_identity)
        .bind(&outcome_str)
        .bind(&secret_name)
        .bind(&lease_id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("failed to insert audit event: {e}")))?;

        Ok(())
    }

    async fn query_by_agent(&self, agent: &AgentId, limit: usize) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query("SELECT * FROM audit_events WHERE agent = ? ORDER BY timestamp DESC LIMIT ?")
            .bind(agent.as_str())
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("query_by_agent failed: {e}")))?;

        rows.iter().map(row_to_audit_entry).collect()
    }

    async fn query_by_secret(&self, secret: &SecretName, limit: usize) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query("SELECT * FROM audit_events WHERE secret_name = ? ORDER BY timestamp DESC LIMIT ?")
            .bind(secret.as_str())
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("query_by_secret failed: {e}")))?;

        rows.iter().map(row_to_audit_entry).collect()
    }

    async fn query_by_lease(&self, lease: &LeaseId) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query("SELECT * FROM audit_events WHERE lease_id = ? ORDER BY timestamp DESC")
            .bind(lease.as_uuid().to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("query_by_lease failed: {e}")))?;

        rows.iter().map(row_to_audit_entry).collect()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;
    use crate::audit::AuditOutcome;
    use crate::transport::PeerIdentity;
    use crate::types::DomainScope;

    async fn test_audit_log() -> (SqliteAuditLog, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap();
        let log = SqliteAuditLog::new(tmp.path()).await.unwrap();
        (log, tmp)
    }

    fn make_entry(agent: &str, event: AuditEvent) -> AuditEntry {
        AuditEntry::new(
            event,
            AgentId::new(agent),
            &PeerIdentity::Anonymous,
            AuditOutcome::Success,
        )
    }

    fn lease_granted_event(secret: &str, lease_id: LeaseId) -> AuditEvent {
        AuditEvent::LeaseGranted {
            lease_id,
            secret_name: SecretName::new(secret),
            domains: vec![DomainScope::new("api.example.com")],
            ttl_seconds: 900,
        }
    }

    #[tokio::test]
    async fn record_and_query_by_agent() {
        let (log, _tmp) = test_audit_log().await;

        // Record 3 events for alice, 1 for bob
        for _ in 0..3 {
            let entry = make_entry("alice", AuditEvent::DekRotated);
            log.record(entry).await.unwrap();
        }
        log.record(make_entry("bob", AuditEvent::DekRotated)).await.unwrap();

        let results = log.query_by_agent(&AgentId::new("alice"), 10).await.unwrap();
        assert_eq!(results.len(), 3);

        // Most recent first
        assert!(results[0].timestamp >= results[1].timestamp);
        assert!(results[1].timestamp >= results[2].timestamp);

        // Bob has 1
        let bob_results = log.query_by_agent(&AgentId::new("bob"), 10).await.unwrap();
        assert_eq!(bob_results.len(), 1);
    }

    #[tokio::test]
    async fn query_by_secret() {
        let (log, _tmp) = test_audit_log().await;

        let lease1 = LeaseId::new();
        let lease2 = LeaseId::new();
        log.record(make_entry("agent", lease_granted_event("secret-a", lease1)))
            .await
            .unwrap();
        log.record(make_entry("agent", lease_granted_event("secret-b", lease2)))
            .await
            .unwrap();

        let results = log.query_by_secret(&SecretName::new("secret-a"), 10).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn query_by_lease() {
        let (log, _tmp) = test_audit_log().await;

        let lease1 = LeaseId::new();
        let lease2 = LeaseId::new();
        log.record(make_entry("agent", lease_granted_event("secret", lease1)))
            .await
            .unwrap();
        log.record(make_entry("agent", lease_granted_event("secret", lease2)))
            .await
            .unwrap();

        let results = log.query_by_lease(&lease1).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn limit_respected() {
        let (log, _tmp) = test_audit_log().await;

        for _ in 0..5 {
            log.record(make_entry("agent", AuditEvent::DekRotated)).await.unwrap();
        }

        let results = log.query_by_agent(&AgentId::new("agent"), 2).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn events_without_secret_or_lease() {
        let (log, _tmp) = test_audit_log().await;

        log.record(make_entry("agent", AuditEvent::DekRotated)).await.unwrap();

        // Should appear in query_by_agent
        let by_agent = log.query_by_agent(&AgentId::new("agent"), 10).await.unwrap();
        assert_eq!(by_agent.len(), 1);

        // Should NOT appear in query_by_secret (no secret_name)
        let by_secret = log.query_by_secret(&SecretName::new("anything"), 10).await.unwrap();
        assert!(by_secret.is_empty());
    }

    #[tokio::test]
    async fn round_trip_fidelity() {
        let (log, _tmp) = test_audit_log().await;

        let lease_id = LeaseId::new();
        let original = make_entry(
            "test-agent",
            AuditEvent::LeaseGranted {
                lease_id,
                secret_name: SecretName::new("my-secret"),
                domains: vec![DomainScope::new("api.example.com")],
                ttl_seconds: 900,
            },
        );

        let original_event_id = original.event_id;
        let original_agent = original.agent.as_str().to_string();
        let original_peer = original.peer_identity.clone();

        log.record(original).await.unwrap();

        let results = log.query_by_agent(&AgentId::new("test-agent"), 1).await.unwrap();
        assert_eq!(results.len(), 1);

        let entry = &results[0];
        assert_eq!(entry.event_id, original_event_id);
        assert_eq!(entry.agent.as_str(), original_agent);
        assert_eq!(entry.peer_identity, original_peer);
        assert!(matches!(entry.outcome, AuditOutcome::Success));
        assert!(
            matches!(&entry.event, AuditEvent::LeaseGranted { secret_name, .. } if secret_name.as_str() == "my-secret")
        );
    }

    #[tokio::test]
    async fn empty_result() {
        let (log, _tmp) = test_audit_log().await;

        let by_agent = log.query_by_agent(&AgentId::new("nobody"), 10).await.unwrap();
        assert!(by_agent.is_empty());

        let by_secret = log.query_by_secret(&SecretName::new("nothing"), 10).await.unwrap();
        assert!(by_secret.is_empty());

        let by_lease = log.query_by_lease(&LeaseId::new()).await.unwrap();
        assert!(by_lease.is_empty());
    }
}
