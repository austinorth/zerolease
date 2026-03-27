# async_trait Migration Design

**Date:** 2026-03-26
**Status:** Draft
**Scope:** Replace all `Pin<Box<dyn Future>>` trait methods with `#[async_trait]` across 5 traits and 11 implementations

## Problem

All backend traits (`KeySource`, `SecretStore`, `AuditLog`, `VaultListener`, `VaultConnector`) use hand-written `Pin<Box<dyn Future<...> + Send + '_>>` return types. This is verbose and produces the same code that `async_trait` generates. The `async_trait` macro provides the same behavior with cleaner syntax.

## Design

Add `async-trait = "0.1"` as a dependency. Apply `#[async_trait]` to all 5 trait definitions and all 11 implementations. Remove the manual `Pin<Box<...>>` return types and replace with `async fn`.

### Traits to migrate

| Trait | File | Methods |
|-------|------|---------|
| `KeySource` | `src/keysource/mod.rs` | `load_or_create_dek`, `rotate_dek` |
| `SecretStore` | `src/store/mod.rs` | `put`, `get`, `update`, `delete`, `list` |
| `AuditLog` | `src/audit/mod.rs` | `record`, `query_by_agent`, `query_by_secret`, `query_by_lease` |
| `VaultListener` | `src/transport/mod.rs` | `accept` |
| `VaultConnector` | `src/transport/mod.rs` | `connect` |

### Implementations to migrate

| Impl | File |
|------|------|
| `EnvVarSource` | `src/keysource/env.rs` |
| `KeychainSource` | `src/keysource/keychain.rs` |
| `SqliteStore` | `src/store/sqlite.rs` |
| `SqliteAuditLog` | `src/audit/sqlite.rs` |
| `NoopAuditLog` (vault tests) | `src/vault.rs` |
| `NoopAuditLog` (server tests) | `src/server.rs` |
| `NoopAuditLog` (client tests) | `src/client.rs` |
| `UdsListener` | `src/transport/uds.rs` |
| `UdsConnector` | `src/transport/uds.rs` |
| `VsockListener` | `src/transport/vsock.rs` |
| `VsockConnector` | `src/transport/vsock.rs` |

### Transformation pattern

**Before (trait definition):**
```rust
pub trait SecretStore: Send + Sync + 'static {
    fn get(&self, name: &SecretName) -> Pin<Box<dyn Future<Output = Result<StoredSecret>> + Send + '_>>;
}
```

**After:**
```rust
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync + 'static {
    async fn get(&self, name: &SecretName) -> Result<StoredSecret>;
}
```

**Before (implementation):**
```rust
impl SecretStore for SqliteStore {
    fn get(&self, name: &SecretName) -> Pin<Box<dyn Future<Output = Result<StoredSecret>> + Send + '_>> {
        let name = name.clone();
        Box::pin(async move {
            // ...
        })
    }
}
```

**After:**
```rust
#[async_trait::async_trait]
impl SecretStore for SqliteStore {
    async fn get(&self, name: &SecretName) -> Result<StoredSecret> {
        // ... (body of the async block, no Box::pin, no clone-before-pin)
    }
}
```

### What changes

- `Pin<Box<dyn Future<...> + Send + '_>>` return types → `async fn`
- `Box::pin(async move { ... })` wrappers → bare function body
- Pre-`Box::pin` parameter cloning (e.g., `let name = name.clone();` before `Box::pin`) → removed (async_trait handles lifetimes)
- `use std::future::Future; use std::pin::Pin;` → removed from files that only used them for traits
- `#[allow(clippy::type_complexity)]` on `VaultListener::accept` → removed

### What doesn't change

- Trait bounds (`Send + Sync + 'static`) — kept
- Method signatures (parameter types, return types inside the Future) — kept
- Method bodies (the actual logic) — kept
- All existing tests — no behavior change

## Testing

No new tests. All 92 existing tests must continue to pass. This is a purely mechanical refactor with no behavior change.

## Dependencies

- Add `async-trait = "0.1"` to `[dependencies]` in `Cargo.toml`
