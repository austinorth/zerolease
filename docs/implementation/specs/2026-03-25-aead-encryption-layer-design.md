# AEAD Encryption Layer Design

**Date:** 2026-03-25
**Status:** Draft
**Scope:** New `src/crypto.rs` module + vault integration

## Problem

The vault stores secrets encrypted at rest, but the actual AEAD encryption and decryption are not implemented. `Vault::decrypt` is a placeholder that always returns `Error::DecryptionFailed`, and no `encrypt` path exists. Without this layer, nothing downstream (secret storage, key rotation, integration tests) can work with real encrypted data.

## Design

### New module: `src/crypto.rs`

A standalone module that owns all AEAD operations. The vault never touches `aes_gcm` or `chacha20poly1305` directly.

### Types

```rust
/// Output of an AEAD encryption operation.
/// Maps 1:1 to the ciphertext/nonce/algorithm fields on StoredSecret.
///
/// Not Clone — this is the transient in-memory crypto output, distinct from
/// StoredSecret (which is Clone because the store backend needs to copy it
/// for database round-trips). Sealed lives only between encrypt/decrypt calls.
///
/// Not Zeroize — ciphertext is not secret (the key is). Zeroizing ciphertext
/// would add overhead with no security benefit.
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: CipherAlgorithm,
}

/// AEAD cipher dispatcher. Holds a default algorithm for encryption;
/// decryption reads the algorithm from the Sealed value.
pub struct Cipher {
    default_algorithm: CipherAlgorithm,
}
```

### API

```rust
impl Cipher {
    pub fn new(default_algorithm: CipherAlgorithm) -> Self;

    /// Encrypt plaintext using the default algorithm.
    /// Generates a fresh random nonce via OsRng.
    pub fn encrypt(&self, plaintext: &[u8], key: &DataEncryptionKey) -> Result<Sealed>;

    /// Decrypt a Sealed value. Dispatches on sealed.algorithm,
    /// NOT on self.default_algorithm.
    pub fn decrypt(&self, sealed: &Sealed, key: &DataEncryptionKey) -> Result<Vec<u8>>;
}
```

### Internal dispatch

Private helper functions per algorithm. The `Cipher` public methods call `key.as_bytes()` on the `DataEncryptionKey` to obtain `&[u8; 32]` before passing to these helpers:

```rust
fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)>;
fn decrypt_aes_gcm(ciphertext: &[u8], nonce: &[u8], key: &[u8; 32]) -> Result<Vec<u8>>;
fn encrypt_xchacha(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)>;
fn decrypt_xchacha(ciphertext: &[u8], nonce: &[u8], key: &[u8; 32]) -> Result<Vec<u8>>;
```

### Nonce generation

- AES-256-GCM: 12-byte nonce via `Aes256Gcm::generate_nonce(&mut OsRng)`
- XChaCha20-Poly1305: 24-byte nonce via `XChaCha20Poly1305::generate_nonce(&mut OsRng)`

Both use the `aead` crate's `AeadCore` trait, which delegates to `OsRng`. No manual nonce construction.

### Error mapping

Both crates return `aead::Error` (an opaque unit struct). Mapped to:

- Encryption failure → `Error::EncryptionFailed`
- Decryption failure → `Error::DecryptionFailed`

No wrapping of the inner error since it carries no information.

### Return type

`decrypt` returns `Vec<u8>`, not `String`. The crypto layer is byte-oriented so it works for binary secrets (SSH keys, client certs). UTF-8 conversion happens at the vault layer.

## Vault integration

### New field

`Vault<K, S, A>` gains `cipher: Cipher`. The `Vault::new` signature changes from:

```rust
pub fn new(key_source: K, store: S, audit: A, policy: PolicyEngine) -> Self
```

to:

```rust
pub fn new(key_source: K, store: S, audit: A, policy: PolicyEngine, default_algorithm: CipherAlgorithm) -> Self
```

The `Cipher` is constructed internally: `cipher: Cipher::new(default_algorithm)`.

### Updated `decrypt` method

```rust
async fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], algorithm: CipherAlgorithm) -> Result<String> {
    let dek = self.dek.read().await;
    let dek = dek.as_ref().ok_or(Error::KeySourceUnavailable("vault not initialized (no DEK)".into()))?;
    let sealed = Sealed { ciphertext: ciphertext.to_vec(), nonce: nonce.to_vec(), algorithm };
    let bytes = self.cipher.decrypt(&sealed, dek)?;
    String::from_utf8(bytes).map_err(|_| Error::DecryptionFailed)
}
```

The signature gains `algorithm`. The existing call site in `access_secret` (vault.rs line 214) must be updated from:

```rust
let plaintext = self.decrypt(&stored.ciphertext, &stored.nonce).await?;
```

to:

```rust
let plaintext = self.decrypt(&stored.ciphertext, &stored.nonce, stored.algorithm).await?;
```

### UTF-8 assumption

The vault-level `decrypt` returns `String` because `LeaseGuard` wraps `SecretString`, and all current `SecretKind` variants are text-based (PATs, API keys, OAuth tokens, JSON-serialized basic auth). Binary secrets (SSH keys, client certs) are a future concern — when supported, the vault will need a `decrypt_bytes` variant or `LeaseGuard` will need to support `SecretVec<u8>`. For now, UTF-8 failure maps to `Error::DecryptionFailed`, which is acceptable since non-UTF-8 data reaching this path would indicate corruption or a bug, not a legitimate binary secret.

### New `encrypt` helper

```rust
async fn encrypt(&self, plaintext: &[u8]) -> Result<Sealed> {
    let dek = self.dek.read().await;
    let dek = dek.as_ref().ok_or(Error::KeySourceUnavailable("vault not initialized (no DEK)".into()))?;
    self.cipher.encrypt(plaintext, dek)
}
```

Used by a future `store_secret` method (out of scope for this spec).

### No new public vault API

This spec wires up internal helpers. No new public `store_secret` method — that depends on a concrete `SecretStore` implementation and is separate work.

## Algorithm selection strategy

- **Encrypt** always uses `self.default_algorithm` (configured at vault construction).
- **Decrypt** always dispatches on `sealed.algorithm` (stored with the ciphertext).
- This enables algorithm migration: change the default, and new secrets use the new algorithm while old secrets still decrypt correctly.
- Default recommendation: `Aes256Gcm` (hardware-accelerated on x86_64 via AES-NI).

## Testing

All tests are unit tests in `src/crypto.rs`. No async, no vault, pure crypto.

1. **Round-trip per algorithm:** Encrypt then decrypt with same key, verify plaintext matches. One test for AES-256-GCM, one for XChaCha20-Poly1305.
2. **Wrong key:** Encrypt with key A, decrypt with key B → `Error::DecryptionFailed`.
3. **Tampered ciphertext:** Flip a byte in ciphertext → `Error::DecryptionFailed`.
4. **Tampered nonce:** Alter nonce → `Error::DecryptionFailed`.
5. **Cross-algorithm mismatch:** Encrypt with AES-GCM, then manually construct a `Sealed` with the same ciphertext/nonce but `algorithm: XChaCha20Poly1305`. Decrypt should fail → `Error::DecryptionFailed`. (Must manually construct because `encrypt` always sets the correct algorithm.)
6. **Empty plaintext:** Verify AEAD handles zero-length input correctly.
7. **Algorithm stored correctly:** Encrypt with AES-GCM default, verify `sealed.algorithm == Aes256Gcm`. Same for XChaCha20.

No vault integration tests in this scope — the vault wiring is thin enough that crypto unit tests plus existing vault tests cover the risk.

## Out of scope

- Concrete `KeySource` implementations (keychain, KMS, env var)
- Concrete `SecretStore` implementations (SQLite, PostgreSQL)
- Public `store_secret` method on `Vault`
- `async_trait` migration (separate cleanup)
- Wire protocol
