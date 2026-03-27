# Client Library Design

**Date:** 2026-03-26
**Status:** Draft
**Scope:** `src/client.rs` (VaultClient), `src/transport/uds.rs` (UdsConnector), new `Error::Remote` variant

## Problem

The vault server accepts connections and dispatches requests, but there is no typed Rust client to talk to it. Consumers would have to manually construct JSON, handle framing, base64 encode/decode, and parse responses. A typed client hides all wire protocol details behind ergonomic Rust methods.

## Design

### File structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/client.rs` | `VaultClient<C>`, typed methods, handshake, internal request helper |
| Modify | `src/transport/uds.rs` | Add `UdsConnector` implementing `VaultConnector` |
| Modify | `src/error.rs` | Add `Error::Remote { code, message }` variant |
| Modify | `src/lib.rs` | Add `pub mod client;` |

### `VaultClient<C: VaultConnector>`

```rust
pub struct VaultClient<C: VaultConnector> {
    reader: ReadHalf<C::Stream>,
    writer: WriteHalf<C::Stream>,
}
```

Uses `tokio::io::split` to hold the two halves of the stream. These are `tokio::io::ReadHalf<C::Stream>` and `tokio::io::WriteHalf<C::Stream>` from `tokio::io::split` (not the borrowing `ReadHalf`/`WriteHalf` from `UnixStream::split`). Both implement `Unpin` regardless of the inner stream type, so they work with `read_frame`/`write_frame`.

All methods take `&mut self` — the client is not shareable across tasks without external synchronization.

**Constructor:** `VaultClient::connect(connector: &C) -> Result<Self>`

1. `connector.connect().await?` — get the stream
2. `tokio::io::split(stream)` — split into reader/writer
3. Serialize `ClientHello::new()` → `write_frame`
4. `read_frame` → deserialize `ServerHello` — if `ok: false`, return `Error::Transport` with the rejection message
5. Return the client

After `connect` succeeds, the handshake is done and the client is ready for requests.

**Internal request helper:**

```rust
async fn request(&mut self, method: &str, params: serde_json::Value) -> Result<serde_json::Value>
```

1. Generate `Uuid::now_v7()` as the request ID
2. Build `Request { id, method, params }`
3. `serde_json::to_vec(&request)` → `write_frame(&mut self.writer, &bytes)`
4. `read_frame(&mut self.reader)` → `serde_json::from_slice::<Response>(&bytes)`
5. If `response.ok`: return `response.result.unwrap_or(serde_json::json!({}))`
6. If `!response.ok`: convert `response.error` to `Error::Remote` and return `Err`

### Typed methods

All 8 protocol methods, each calling `self.request()` internally:

| Method | Signature | Notes |
|--------|-----------|-------|
| `store_secret` | `(&mut self, name: &str, plaintext: &[u8], kind: SecretKind, description: Option<String>) -> Result<SecretMetadata>` | Base64-encodes plaintext, serializes kind |
| `request_lease` | `(&mut self, agent: &str, secret_name: &str, domain: &str) -> Result<LeaseGrant>` | |
| `access_secret` | `(&mut self, lease_id: Uuid, target_domain: &str) -> Result<Vec<u8>>` | Deserializes result as `AccessSecretResponse`, base64-decodes `.secret` field |
| `revoke_lease` | `(&mut self, lease_id: Uuid, reason: RevocationReason) -> Result<()>` | Serializes reason |
| `revoke_all_for_agent` | `(&mut self, agent: &str) -> Result<usize>` | Returns revoked_count |
| `list_secrets` | `(&mut self) -> Result<Vec<SecretMetadata>>` | Deserializes result as `ListSecretsResponse`, then deserializes each element in `.secrets` as `SecretMetadata` |
| `renew_lease` | `(&mut self, lease_id: Uuid, extension_secs: i64) -> Result<LeaseGrant>` | |
| `delete_secret` | `(&mut self, name: &str) -> Result<()>` | |

The caller works with Rust types throughout. No JSON, no base64, no request IDs.

### `UdsConnector`

```rust
pub struct UdsConnector {
    path: PathBuf,
}
```

**Constructor:** `UdsConnector::new(path: impl Into<PathBuf>)` — stores the path.

**`VaultConnector` impl:** `connect()` calls `tokio::net::UnixStream::connect(&self.path)`, maps `io::Error` to `Error::Transport`.

### `Error::Remote` variant

Add to `src/error.rs`:

```rust
    /// An error returned by the vault server over the wire.
    /// The code is the machine-readable error code (e.g., "access_denied").
    #[error("remote error ({code}): {message}")]
    Remote {
        code: String,
        message: String,
    },
```

The client maps `ErrorPayload { code, message }` from the wire to this variant. Callers can match on the `code` field for programmatic error handling:

```rust
match client.request_lease("agent", "secret", "domain").await {
    Err(Error::Remote { code, .. }) if code == "access_denied" => { /* handle */ }
    // ...
}
```

**Required:** This new variant must be added to the `error_to_code` match in `src/protocol/mod.rs` — map it to `"remote"`. Without this arm, the code will not compile (the match is exhaustive). The server should never produce this error; it is client-side only.

### Base64 encoding/decoding

The client uses `base64::engine::general_purpose::STANDARD` (same as the server dispatch) for:
- Encoding `&[u8]` plaintext → String in `store_secret`
- Decoding String → `Vec<u8>` in `access_secret`

Base64 decode errors map to `Error::Transport("invalid base64 in server response")`.

## Testing

### `UdsConnector` test (in `src/transport/uds.rs`)

1. **Connect to a listener** — bind `UdsListener`, create `UdsConnector` with same path, connect, verify stream is usable.

### `VaultClient` integration tests (in `src/client.rs`)

Each test spins up a full vault + server in the background:
- Set a unique env var (e.g., `ZEROLEASE_TEST_CLIENT_1`) with `unsafe { std::env::set_var(...) }` — unique names per test avoid collisions in parallel execution
- Create `EnvVarSource` + `SqliteStore` + `NoopAuditLog` + `PolicyEngine` → `Vault`
- Initialize the vault (`vault.initialize().await`)
- Bind `UdsListener` on a temp dir path
- Wrap vault in `Arc`, create `VaultServer`
- Move the `VaultServer` into a `tokio::spawn` task that calls `serve()`. Save the `JoinHandle`.
- Create `UdsConnector` with the socket path, `VaultClient::connect(&connector)`
- Exercise the client methods
- After the test: `handle.abort()` to stop the server task, then drop temp dir

2. **Connect and handshake** — verify `VaultClient::connect` succeeds.
3. **Store and list** — store a secret, list, verify it appears.
4. **Full lease cycle** — store → request_lease → access_secret → verify bytes match original plaintext.
5. **Revoke lease** — store → lease → revoke → access returns error.
6. **Revoke all for agent** — store → lease → revoke_all_for_agent → verify count >= 1.
7. **Delete secret** — store → delete → list returns empty.
8. **Renew lease** — store → lease (with `LeaseTerms::workflow()` policy grant for renewable=true) → renew → verify ok.
9. **Error mapping** — request lease for nonexistent secret → `Error::Remote { code: "secret_not_found", .. }`.

All tests gated with `#[cfg(feature = "sqlite")]`.

## Dependencies

No new dependencies. All used crates (`base64`, `serde_json`, `uuid`, `tokio`) are already present.

## Out of scope

- Connection pooling / reconnection
- Concurrent request pipelining (client is `&mut self`)
- vsock connector (trivial to add later, same pattern as UDS)
- Client-side caching of leases
