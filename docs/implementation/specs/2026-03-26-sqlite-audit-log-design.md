# SQLite Audit Log Design

**Date:** 2026-03-26
**Status:** Draft
**Scope:** New `src/audit/sqlite.rs` implementing `AuditLog` trait with SQLite persistence

## Problem

Every audit event flows through `tracing` (as of the recent vault change), but there is no persistent, queryable audit store. The `AuditLog` trait's `query_by_agent`, `query_by_secret`, and `query_by_lease` methods are unimplemented — only `NoopAuditLog` exists. For incident investigation and compliance, audit events need to be stored and queryable.

## Design

### File structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/audit/sqlite.rs` | `SqliteAuditLog` struct, `AuditLog` impl, schema migration, unit tests |
| Modify | `src/audit/mod.rs` | Add `#[cfg(feature = "sqlite")] pub mod sqlite;` |

### Database file

The audit log uses a **separate SQLite file** from the secrets database. Audit events grow much faster than secrets (every access is a row), and separating them allows independent rotation, archival, and backup.

### Schema

```sql
CREATE TABLE IF NOT EXISTS audit_events (
    event_id      TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    event         TEXT NOT NULL,
    agent         TEXT NOT NULL,
    peer_identity TEXT NOT NULL,
    outcome       TEXT NOT NULL,
    secret_name   TEXT,
    lease_id      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent);
CREATE INDEX IF NOT EXISTS idx_audit_secret ON audit_events(secret_name);
CREATE INDEX IF NOT EXISTS idx_audit_lease ON audit_events(lease_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
```

- `event_id`: UUID v7 as text (`entry.event_id.to_string()`)
- `timestamp`: RFC 3339 text via `entry.timestamp.to_rfc3339()`. `chrono::Utc` always produces a consistent fixed-width UTC format, so lexicographic ordering matches chronological ordering.
- `event`: JSON-serialized `AuditEvent` via `serde_json::to_string`
- `agent`: the inner string from `entry.agent.as_str()` (NOT the `Display` format which prefixes `"agent:"`). Reconstructed with `AgentId::new(s)`. Query binds use `agent.as_str()`.
- `peer_identity`: the `Display` string from `entry.peer_identity` (which is already a `String` on `AuditEntry`)
- `outcome`: JSON-serialized `AuditOutcome` via `serde_json::to_string`
- `secret_name`: denormalized, extracted from the `AuditEvent` variant at insert time using `SecretName::as_str()` for the value. NULL for events without a secret (e.g., `DekRotated`, `PolicyReloaded`, `LeaseRevoked`).
- `lease_id`: denormalized, extracted from the `AuditEvent` variant at insert time using `lease_id.as_uuid().to_string()` for the value. Reconstructed with `LeaseId::from_uuid(Uuid::parse_str(s))`. NULL for events without a lease (e.g., `SecretStored`, `SecretDeleted`).

**Known schema limitation:** `LeaseRevoked` events do not carry a `secret_name`, so they cannot be found by `query_by_secret` even if the revocation was triggered by a secret deletion. The `SecretDeleted` event itself is recorded separately and will appear in `query_by_secret` results.

The denormalized columns avoid `json_extract` queries — the three query methods become simple `WHERE` clauses on indexed columns.

### `SqliteAuditLog`

```rust
pub struct SqliteAuditLog {
    pool: SqlitePool,
}
```

**Constructor:** `SqliteAuditLog::new(path: impl AsRef<Path>) -> Result<Self>`

Same pattern as `SqliteStore`: creates file with `SqliteConnectOptions::new().filename(path).create_if_missing(true).journal_mode(SqliteJournalMode::Wal)`, opens pool via `SqlitePoolOptions`, runs `CREATE TABLE IF NOT EXISTS` + `CREATE INDEX IF NOT EXISTS`. WAL mode is enabled for better concurrent read/write performance (SQLite allows concurrent reads while a single write is in progress).

### Trait method implementations

**`record`:**
1. Extract `secret_name` and `lease_id` from the `AuditEvent` variant via a helper function `extract_event_fields(event: &AuditEvent) -> (Option<String>, Option<String>)`. This matches on the event variant and extracts the relevant fields:
   - `LeaseGranted { secret_name, lease_id, .. }` → `(Some(name), Some(lease_id))`
   - `SecretAccessed { secret_name, lease_id, .. }` → `(Some(name), Some(lease_id))`
   - `LeaseRevoked { lease_id, .. }` → `(None, Some(lease_id))`
   - `LeaseRenewed { lease_id, .. }` → `(None, Some(lease_id))`
   - `AccessDenied { secret_name, .. }` → `(Some(name), None)`
   - `SecretStored { secret_name }` → `(Some(name), None)`
   - `SecretRotated { secret_name, .. }` → `(Some(name), None)`
   - `SecretDeleted { secret_name }` → `(Some(name), None)`
   - `DekRotated` → `(None, None)`
   - `PolicyReloaded { .. }` → `(None, None)`
2. Serialize `event` and `outcome` to JSON via `serde_json::to_string`.
3. INSERT into `audit_events`.

**`query_by_agent`:**
```sql
SELECT * FROM audit_events WHERE agent = ? ORDER BY timestamp DESC LIMIT ?
```
Deserialize each row back into `AuditEntry` via `row_to_audit_entry` helper.

**`query_by_secret`:**
```sql
SELECT * FROM audit_events WHERE secret_name = ? ORDER BY timestamp DESC LIMIT ?
```

**`query_by_lease`:**
```sql
SELECT * FROM audit_events WHERE lease_id = ? ORDER BY timestamp DESC
```
No limit parameter — the trait signature takes only `&LeaseId`.

All queries order by `timestamp DESC` (most recent first).

### Row deserialization

A `row_to_audit_entry` helper function (same pattern as `row_to_stored_secret` in `SqliteStore`). All parsing errors map to `Error::Storage(...)`:
- `event_id`: `Uuid::parse_str(&s).map_err(|e| Error::Storage(...))`
- `timestamp`: `DateTime::parse_from_rfc3339(&s)...with_timezone(&Utc)` mapped to `Error::Storage`
- `event`: `serde_json::from_str::<AuditEvent>(&s)` mapped to `Error::Storage`
- `agent`: `AgentId::new(agent_string)` (infallible — stores the inner string, not the Display prefix)
- `peer_identity`: stored and retrieved as a plain `String` (the `AuditEntry.peer_identity` field is `String`)
- `outcome`: `serde_json::from_str::<AuditOutcome>(&s)` mapped to `Error::Storage`

### Retention

No built-in retention policy. The audit log appends forever. Retention is an operational concern — the caller can prune old rows externally (`DELETE FROM audit_events WHERE timestamp < ?`) or rotate the database file. A built-in retention mechanism can be added later if needed.

## Testing

### Unit tests in `src/audit/sqlite.rs`

Each test uses `tempfile::NamedTempFile` for an isolated database.

1. **Record and query by agent** — record 3 events for agent "alice" and 1 for "bob", query by "alice" with limit 10, verify 3 returned, most recent first.
2. **Query by secret** — record events referencing different secrets, query by one secret name, verify only matching events returned.
3. **Query by lease** — record events with different lease IDs, query by one, verify only matching events returned.
4. **Limit respected** — record 5 events for one agent, query with limit 2, verify only 2 returned.
5. **Events without secret/lease still queryable** — record a `DekRotated` event (no secret_name, no lease_id), verify it's returned by `query_by_agent` but not by `query_by_secret`.
6. **Round-trip fidelity** — record an event, query it back, verify all fields match (event, agent, peer_identity, outcome, timestamp within tolerance).
7. **Empty result** — query by an agent/secret/lease that has no matching rows, verify empty `Vec` returned (not an error).

## Dependencies

No new dependencies. `sqlx` with `sqlite` feature and `tempfile` are already present.

## Out of scope

- Retention policy / pruning
- Audit log rotation
- External audit sink (CloudWatch, Splunk, etc.)
- Vault integration test with `SqliteAuditLog` (existing tests use `NoopAuditLog` + tracing)
