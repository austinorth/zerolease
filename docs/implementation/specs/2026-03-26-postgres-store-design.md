# PostgreSQL SecretStore Design

**Date:** 2026-03-26
**Status:** Draft
**Scope:** New `src/store/postgres.rs`, gated on `postgres` feature

## Problem

The vault has a SQLite store for single-host deployments but no shared storage for multi-instance deployments. PostgreSQL enables multiple vault instances to share a common secret store, and integrates with existing database infrastructure, backup tooling, and monitoring.

## Design

### File structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/store/postgres.rs` | `PostgresStore` implementing `SecretStore` |
| Modify | `src/store/mod.rs` | Add `#[cfg(feature = "postgres")] pub mod postgres;` |

No Cargo.toml changes needed — `postgres = ["sqlx"]` already exists, and sqlx already has the `postgres` feature in its feature list.

### Schema

```sql
CREATE TABLE IF NOT EXISTS secrets (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    ciphertext  BYTEA NOT NULL,
    nonce       BYTEA NOT NULL,
    algorithm   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1
);
```

Differences from SQLite:
- `BYTEA` instead of `BLOB` for binary data
- `TIMESTAMPTZ` instead of `TEXT` for timestamps — sqlx can bind/extract `DateTime<Utc>` directly with PostgreSQL, no RFC 3339 string conversion needed
- Same column names and semantics

### `PostgresStore`

```rust
pub struct PostgresStore {
    pool: PgPool,
}
```

**Constructor:** `PostgresStore::new(url: &str) -> Result<Self>` — connects to the given PostgreSQL URL (e.g., `postgres://user:pass@host/dbname`), runs `CREATE TABLE IF NOT EXISTS`. Uses `PgPoolOptions`.

**Trait methods:** Same logic as `SqliteStore` with PostgreSQL query syntax:
- `$1, $2, $3` parameter placeholders instead of `?`
- `BYTEA` columns bind/extract `Vec<u8>` directly
- `TIMESTAMPTZ` columns bind/extract `DateTime<Utc>` directly (no string conversion)
- UNIQUE constraint violation detection uses PostgreSQL error code `23505`
- `rows_affected()` works the same way

### Row deserialization

A `row_to_stored_secret` helper, same pattern as SQLite but simpler — timestamps extract directly as `DateTime<Utc>`, no RFC 3339 parsing.

## Testing

PostgreSQL tests require a running PostgreSQL instance. All tests are `#[ignore]` by default.

1. **Put and get round-trip** (`#[ignore]`)
2. **Constructor compiles** (not `#[ignore]`) — verify types work

Tests use the `DATABASE_URL` environment variable for the connection string.

## Dependencies

No new dependencies. `sqlx` with `postgres` feature is already configured.
