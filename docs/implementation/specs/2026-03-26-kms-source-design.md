# AWS KMS Key Source Design

**Date:** 2026-03-26
**Status:** Draft
**Scope:** New `src/keysource/kms.rs`, update `kms` feature flag

## Problem

The vault has key sources for developer machines (OS keychain) and CI (env var), but no production-grade key management backed by hardware security. AWS KMS provides hardware-backed encryption keys where the master key never leaves the HSM, and we use envelope encryption to avoid KMS round-trips per secret operation.

## Design

### File structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/keysource/kms.rs` | `KmsSource` implementing `KeySource` |
| Modify | `src/keysource/mod.rs` | Add `#[cfg(feature = "kms")] pub mod kms;` |
| Modify | `Cargo.toml` | Update `kms` feature flag, add optional deps |

### Dependencies

```toml
[dependencies]
aws-sdk-kms = { version = "1", optional = true }
aws-config = { version = "1", optional = true }

[features]
kms = ["aws-sdk-kms", "aws-config"]
```

Both dependencies are optional. The `aws-config` crate provides `aws_config::load_defaults()` for credential/region resolution. The KMS module is gated with `#[cfg(feature = "kms")]`.

### `KmsSource`

```rust
pub struct KmsSource {
    client: aws_sdk_kms::Client,
    key_id: String,
    encrypted_dek_path: PathBuf,
    description: String,
}
```

**Constructor:** `KmsSource::new(key_id: impl Into<String>, region: impl Into<String>, encrypted_dek_path: impl Into<PathBuf>) -> Result<Self>`

1. Build AWS config with the specified region: `aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region)).load().await`
2. Create `aws_sdk_kms::Client::new(&config)`
3. Store `key_id`, `encrypted_dek_path`, build `description`

The constructor is async because loading AWS config resolves credentials.

### `load_or_create_dek`

1. Check if `self.encrypted_dek_path` exists
2. **If exists:** Read the file contents, call KMS `Decrypt` with the blob, extract the 32-byte plaintext, return `DataEncryptionKey::from_bytes`
3. **If not exists:** Generate 32 random bytes via `OsRng`, call KMS `Encrypt` with the plaintext, save the ciphertext blob to `encrypted_dek_path`, return the DEK

KMS API calls:
- `Decrypt`: `client.decrypt().ciphertext_blob(Blob::new(bytes)).key_id(&self.key_id).send().await`
- `Encrypt`: `client.encrypt().plaintext(Blob::new(dek_bytes)).key_id(&self.key_id).send().await`

Error mapping: KMS SDK errors → `Error::KeySourceUnavailable(msg)`. File I/O errors → `Error::KeySourceUnavailable(msg)`.

### `rotate_dek`

1. Call KMS `Encrypt` on `new_dek.as_bytes()`
2. Save the new encrypted blob to `encrypted_dek_path` (overwrite)
3. Return `EncryptedDek { ciphertext, key_id }`

Unlike EnvVar and Keychain, rotation IS supported for KMS — it just re-encrypts the DEK.

### `description`

Returns `"kms:<key_id>"` (pre-formatted string stored in struct, same pattern as other sources).

### File format for encrypted DEK

The encrypted DEK blob file is a raw binary file containing the KMS ciphertext blob. No JSON wrapper, no encoding — just the raw bytes as returned by KMS `Encrypt`. This keeps the format simple and compatible with the AWS CLI (`aws kms decrypt --ciphertext-blob fileb://dek.enc`).

## Testing

KMS tests require AWS credentials and a KMS key. All tests are `#[ignore]` by default.

1. **Encrypt and decrypt round-trip** (`#[ignore]`) — create a KmsSource, generate a DEK, verify it can be loaded back.
2. **Constructor compiles** (not `#[ignore]`) — verify the types work without calling AWS.

For CI: the module compiles when the `kms` feature is enabled but tests don't run without `--ignored` and valid AWS credentials.

## Out of scope

- KMS key creation / management
- KMS key rotation (rotating the KMS key itself, vs rotating our DEK)
- Multi-region KMS
- KMS grants / key policies
