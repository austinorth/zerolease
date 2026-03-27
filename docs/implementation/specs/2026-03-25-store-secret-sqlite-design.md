# store_secret + SQLite SecretStore Design

**Date:** 2026-03-25
**Status:** Draft
**Scope:** New `src/store/sqlite.rs`, new `Vault::store_secret` method, vault integration test

## Problem

The vault has working encryption (`Cipher`), key management (`EnvVarSource`, `KeychainSource`), leasing, and policy, but no way to actually store or retrieve secrets. The `SecretStore` trait is defined but has no implementation, and the vault has no `store_secret` method. Without these, the vault cannot function end-to-end.

## Design

### File structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/store/sqlite.rs` | `SqliteStore` struct, `SecretStore` impl, schema migration, unit tests |
| Modify | `src/store/mod.rs` | Add `#[cfg(feature = "sqlite")] pub mod sqlite;` and `From<&StoredSecret> for SecretMetadata` |
| Modify | `src/vault.rs` | Add `store_secret` public method, vault integration test with `NoopAuditLog` |

### SQLite schema

```sql
CREATE TABLE IF NOT EXISTS secrets (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    ciphertext  BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    algorithm   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    description TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1
);
```

- `id`: `SecretId` UUID as text.
- `algorithm`: serde-serialized enum variant name (`"Aes256Gcm"` or `"XChaCha20Poly1305"`).
- `kind`: full JSON blob from `serde_json::to_string(&kind)` (e.g., `"\"Pat\""` or `{"OAuth2":{"refresh_ciphertext":...}}`).
- Timestamps: ISO 8601 text (SQLite has no native datetime; text is most portable).

### `SqliteStore`

```rust
pub struct SqliteStore {
    pool: SqlitePool,
}
```

**Constructor:** `SqliteStore::new(path: impl AsRef<Path>) -> Result<Self>`

Creates the SQLite file if needed using `SqliteConnectOptions::new().filename(path).create_if_missing(true)`, opens a connection pool via `SqlitePoolOptions`, and runs `CREATE TABLE IF NOT EXISTS`. The constructor is async (it performs I/O).

**Trait method implementations:**

- **`put`:** Generates `SecretId::new()`, `Utc::now()` for timestamps inside the method (the caller only provides `StoreSecretParams` which has no id/timestamps). Runs `INSERT INTO secrets (id, name, ciphertext, nonce, algorithm, kind, description, created_at, updated_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`. On UNIQUE constraint violation (`sqlx::Error::Database` with SQLite error code), return `Error::SecretAlreadyExists(name)`. On success, return the `StoredSecret`.

- **`get`:** `SELECT * FROM secrets WHERE name = ?`. If no row returned, return `Error::SecretNotFound(name)`. Deserialize `algorithm` and `kind` from their text representations using `serde_json::from_str`. Map deserialization errors to `Error::Storage`.

- **`update`:** `UPDATE secrets SET ciphertext = ?, nonce = ?, algorithm = ?, updated_at = ?, version = version + 1 WHERE name = ?`. If rows affected is 0, return `Error::SecretNotFound(name)`. Then `SELECT` the updated row to return the full `StoredSecret`. Note: `update` only rotates the ciphertext/nonce/algorithm — it does not change `description` or `kind`. This is by design: `update` is for key rotation, not metadata editing.

- **`delete`:** `DELETE FROM secrets WHERE name = ?`. If rows affected is 0, return `Error::SecretNotFound(name)`.

- **`list`:** `SELECT id, name, kind, description, created_at, updated_at, version FROM secrets`. Returns `Vec<SecretMetadata>`. Never selects ciphertext or nonce.

**Serialization/deserialization:** `algorithm` and `kind` are stored as their `serde_json::to_string` output (e.g., `"\"Aes256Gcm\""` becomes the TEXT value `"Aes256Gcm"` in SQLite, `serde_json` on `SecretKind::Pat` produces `"\"Pat\""` → stored as `"Pat"`). Deserialized back with `serde_json::from_str`. Both types derive `Serialize`/`Deserialize`. Deserialization errors map to `Error::Storage`.

### `From<&StoredSecret> for SecretMetadata`

Added to `src/store/mod.rs`:

```rust
impl From<&StoredSecret> for SecretMetadata {
    fn from(s: &StoredSecret) -> Self {
        Self {
            id: s.id,       // SecretId is Copy
            name: s.name.clone(),
            kind: s.kind.clone(),
            description: s.description.clone(),
            created_at: s.created_at,  // DateTime<Utc> is Copy
            updated_at: s.updated_at,
            version: s.version,
        }
    }
}
```

`SecretId` derives `Copy` (in `types.rs`). `DateTime<Utc>` is `Copy` (from chrono). So `id`, `created_at`, `updated_at`, and `version` are all copied by value.

### `Vault::store_secret`

```rust
pub async fn store_secret(
    &self,
    name: &SecretName,
    plaintext: &[u8],
    kind: SecretKind,
    description: Option<String>,
    peer: &PeerIdentity,
) -> Result<SecretMetadata>
```

Flow:
1. `let sealed = self.encrypt(plaintext).await?` — fails with `Error::KeySourceUnavailable` if vault is not initialized (DEK is `None`)
2. Build `StoreSecretParams { name: name.clone(), ciphertext: sealed.ciphertext, nonce: sealed.nonce, algorithm: sealed.algorithm, kind, description }`
3. `let stored = self.store.put(params).await?` — fails with `Error::SecretAlreadyExists` if duplicate name
4. Audit: `self.audit.record(AuditEntry::new(AuditEvent::SecretStored { secret_name: name.clone() }, AgentId::new("admin"), peer, AuditOutcome::Success)).await?`
5. Return `SecretMetadata::from(&stored)`

`AgentId::new(impl Into<String>)` exists in `types.rs`. Uses `"admin"` as a placeholder since secret storage is an admin operation, not agent-initiated. The `self.encrypt` helper (added in the AEAD spec) is used here for the first time.

### Runtime SQL queries (no compile-time checking)

All queries use `sqlx::query` / `sqlx::query_as` with runtime string SQL (not the `sqlx::query!` macro). No `DATABASE_URL` or offline query cache needed. SQL correctness is verified by the test suite.

## Testing

### `SqliteStore` tests (unit tests in `sqlite.rs`)

Each test uses `tempfile::NamedTempFile` for an isolated database. New dev-dependency: `tempfile`.

1. **Put and get round-trip:** Store a secret, retrieve by name, verify all fields match.
2. **Put duplicate name errors:** Store, store same name → `SecretAlreadyExists`.
3. **Get missing errors:** Get nonexistent name → `SecretNotFound`.
4. **Update increments version:** Store (version 1), update, verify version 2 and new ciphertext.
5. **Update missing errors:** Update nonexistent → `SecretNotFound`.
6. **Delete removes secret:** Store, delete, get → `SecretNotFound`.
7. **Delete missing errors:** Delete nonexistent → `SecretNotFound`.
8. **List returns metadata:** Store two secrets, list, verify both returned with correct metadata.

### Vault integration test (in `src/vault.rs` test module)

A `NoopAuditLog` test helper that implements all 4 `AuditLog` trait methods:
- `record` → `Ok(())`
- `query_by_agent` → `Ok(vec![])`
- `query_by_secret` → `Ok(vec![])`
- `query_by_lease` → `Ok(vec![])`

Combined with `EnvVarSource` and `SqliteStore`, this enables the first end-to-end vault test:

1. Set env var with a hex-encoded test key
2. Create vault with `EnvVarSource` + `SqliteStore` (tempfile) + `NoopAuditLog` + a `PolicyEngine` configured with a grant for `AgentId::new("test-agent")` allowing access to the test secret on `DomainScope::new("api.example.com")`
3. Initialize vault (`vault.initialize().await`)
4. `store_secret` — store a plaintext secret (e.g., `b"my-api-token"`)
5. `request_lease` — request a lease as `"test-agent"` for the stored secret name and domain
6. `access_secret` — use the lease to decrypt, verify the plaintext matches the original `b"my-api-token"`

This test validates the complete flow: encrypt → store → lease → decrypt.

## Dependencies

- **New dev-dependency:** `tempfile` — add to `Cargo.toml`:
  ```toml
  [dev-dependencies]
  tempfile = "3"
  ```
- **Existing:** `sqlx` with `sqlite` feature (already in Cargo.toml, gated on `sqlite` feature flag)

## Out of scope

- PostgreSQL `SecretStore` implementation
- Secret rotation via `update` (the method exists but no vault-level orchestration)
- Concrete `AuditLog` implementations (the `NoopAuditLog` is test-only)
- Agent-based authorization for secret management
