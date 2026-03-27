# KeySource Implementations Design

**Date:** 2026-03-25
**Status:** Draft
**Scope:** New `src/keysource/env.rs` and `src/keysource/keychain.rs`

## Problem

The `KeySource` trait is defined but has no concrete implementations. Without one, the vault cannot initialize its DEK, so nothing downstream (storing secrets, issuing leases, integration tests) can work. Two implementations are needed for the two primary deployment targets: developer laptops (OS keychain) and CI/testing (environment variable).

## Design

### File structure

```
src/keysource/
  mod.rs          — existing trait + types (add module declarations)
  env.rs          — EnvVarSource
  keychain.rs     — KeychainSource (cfg(unix) only)
```

`mod.rs` gains:

```rust
pub mod env;
#[cfg(unix)]
pub mod keychain;
```

`keychain` is `cfg(unix)` because the `keyring` dependency is gated with `[target.'cfg(unix)'.dependencies]` in `Cargo.toml`.

### `EnvVarSource`

```rust
pub struct EnvVarSource {
    var_name: String,
}
```

**Constructor:** `EnvVarSource::new(var_name: impl Into<String>)` — stores the variable name. Does not read the environment at construction time.

**`load_or_create_dek`:** Reads the env var, hex-decodes it (64 hex chars → 32 bytes), returns `DataEncryptionKey::from_bytes`. There is no "create" path — an env var source is read-only. If the variable is not set, that's an error, not a prompt to generate a key.

Hex decoding uses a manual implementation (no `hex` crate). For a fixed 64-char input, this is a few lines of code.

Errors:
- Variable not set → `Error::KeySourceUnavailable("env var <name> not set")`
- Not valid hex → `Error::InvalidConfig("env var <name> is not valid hex")`
- Wrong length (not 64 hex chars / 32 bytes) → `Error::InvalidConfig("env var <name> must be 64 hex characters (32 bytes)")`

**`rotate_dek`:** Accepts the `new_dek: &DataEncryptionKey` parameter (as required by the trait) but ignores it. Returns `Error::KeySourceUnavailable("cannot rotate an env-var key source; set a new value and restart")`.

**`description`:** Returns `"env:<var_name>"`. Never includes the key value.

### `KeychainSource`

```rust
pub struct KeychainSource {
    service: String,
    account: String,
}
```

**Constructor:** `KeychainSource::new(service: impl Into<String>, account: impl Into<String>)` — stores the keychain entry coordinates.

**`load_or_create_dek`:** The implementation clones `self.service` and `self.account` into the closure, then wraps all keyring calls in `tokio::task::spawn_blocking` to avoid blocking the async runtime. A `JoinError` (panic in the blocking task) maps to `Error::KeySourceUnavailable`.

Inside the blocking closure:

1. Call `keyring::Entry::new(&service, &account)`. This is fallible in keyring 3.6 — map errors to `Error::KeySourceUnavailable`.
2. Call `entry.get_secret()`:
   - **Ok, 32 bytes:** return `DataEncryptionKey::from_bytes`.
   - **Ok, wrong length:** return `Error::InvalidConfig("keychain entry has wrong key length (expected 32 bytes)")`.
   - **Err, `keyring::Error::NoEntry`:** generate 32 random bytes via `OsRng` (re-exported from `aes_gcm::aead::OsRng`, already a transitive dependency), call `entry.set_secret(&bytes)`. If `set_secret` fails (keychain locked, permission denied), return `Error::KeySourceUnavailable` with the keyring error message. Otherwise return the new DEK.
   - **Err, other:** return `Error::KeySourceUnavailable` with the keyring error message.

**`rotate_dek`:** Accepts the `new_dek: &DataEncryptionKey` parameter but ignores it. Returns `Error::KeySourceUnavailable("DEK rotation not yet supported for keychain source")`.

**`description`:** Returns `"keychain:<service>/<account>"`.

### Why `KeySourceUnavailable` for rotation errors

Both implementations use `Error::KeySourceUnavailable` (not `InvalidConfig`) for rotation failures. The source is correctly configured — it simply doesn't support this operation. `InvalidConfig` is reserved for actual configuration problems (wrong hex, missing var, bad key length).

### `EncryptedDek` return from `rotate_dek`

Both implementations return an error from `rotate_dek`, so the `EncryptedDek` return type is never constructed. Rotation is a heavyweight operation requiring re-encryption of all secrets via the `SecretStore`, which has no concrete implementation yet. This will be revisited when the SQLite store lands.

## Testing

### `EnvVarSource` tests (unit tests in `env.rs`)

Tests use unique variable names per test (e.g., `ZEROLEASE_TEST_ENV_1`, `_2`, etc.) to avoid collisions. Since `std::env::set_var` is process-global and not thread-safe, env tests must run sequentially. Run with `cargo test keysource::env -- --test-threads=1`.

Note: as of Rust edition 2024, `std::env::set_var` is `unsafe` because it is not thread-safe. Tests that call it must use an `unsafe` block.

1. **Valid hex key loads:** Set env var to a known 64-char hex string, verify `load_or_create_dek` returns the expected bytes.
2. **Missing env var errors:** Use an unset var name → `KeySourceUnavailable`.
3. **Bad hex errors:** Set var to `"not-hex-at-all"` → `InvalidConfig`.
4. **Wrong length errors:** Set var to valid hex but only 20 chars → `InvalidConfig`.
5. **Rotate returns error:** Verify `rotate_dek` returns `KeySourceUnavailable`.
6. **Description format:** Verify `description()` contains the var name, not the key value.

### `KeychainSource` tests (integration tests in `keychain.rs`, `#[ignore]`)

These require a real OS keychain, which is not available in CI or headless environments. All keychain tests are marked `#[ignore]` so they don't run in the default test suite. Run manually with `cargo test keysource::keychain -- --ignored`.

1. **Create then load round-trip:** Create a `KeychainSource` with a unique test service/account (e.g., `"zerolease-test"` / `"test-dek-roundtrip"`), call `load_or_create_dek` (creates new), call again (loads existing), verify both return the same key bytes. Clean up the keychain entry after the test using `keyring::Entry::new(...).unwrap().delete_credential()`.
2. **Description format:** Verify `description()` returns `"keychain:<service>/<account>"`.

## Dependencies

No new crate dependencies:
- `keyring 3.6` is already in `[target.'cfg(unix)'.dependencies]`
- `OsRng` is re-exported through `aes_gcm::aead::OsRng` (transitive, already used in `src/crypto.rs`)
- Hex decoding is manual (no `hex` crate)
- `tokio::task::spawn_blocking` is available from `tokio` with `features = ["full"]`

## Out of scope

- `KmsSource` (AWS KMS envelope encryption)
- DEK rotation implementation (deferred until SecretStore exists)
- `KeySourceConfig` → concrete source construction (runtime config dispatch)
