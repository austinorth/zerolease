# Server Dispatch + UDS Transport Design

**Date:** 2026-03-26
**Status:** Draft
**Scope:** `src/server.rs` (server loop + dispatch), `src/transport/uds.rs` (UDS listener), three new vault methods, new audit event

## Problem

The wire protocol (framing + types) is implemented, but nothing connects it to the vault. There is no server that accepts connections, runs the handshake, dispatches requests to vault methods, and sends responses. There is no concrete transport listener. The vault is also missing three methods the protocol requires: `list_secrets`, `renew_lease`, `delete_secret`.

## Design

### File structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/server.rs` | `VaultServer` struct, `serve()` loop, `handle_connection`, `dispatch` |
| Create | `src/transport/uds.rs` | `UdsListener` implementing `VaultListener` |
| Modify | `src/transport/mod.rs` | Add `pub mod uds;` |
| Modify | `src/vault.rs` | Add `list_secrets`, `renew_lease`, `delete_secret` methods |
| Modify | `src/audit/mod.rs` | Add `LeaseRenewed` variant to `AuditEvent` |
| Modify | `src/lib.rs` | Add `pub mod server;` |

### `VaultServer`

```rust
pub struct VaultServer<K, S, A, L>
where
    K: KeySource,
    S: SecretStore,
    A: AuditLog,
    L: VaultListener,
{
    vault: Arc<Vault<K, S, A>>,
    listener: L,
}
```

**Constructor:** `VaultServer::new(vault: Arc<Vault<K, S, A>>, listener: L) -> Self`

**`serve(&self)`** — the main accept loop:
1. Loop on `self.listener.accept()`
2. For each `(stream, peer)`, clone the `Arc<Vault>` and `tokio::spawn` a task calling `handle_connection`
3. Returns on listener error. Caller decides shutdown policy. Note: already-spawned connection tasks continue running after `serve` returns — they hold their own `Arc<Vault>` clone.

**`handle_connection(vault, stream, peer)`** — per-connection async function:
1. Split stream into reader/writer halves via `tokio::io::split`. Both halves are passed by `&mut` reference to the framing functions throughout the handshake and request loop.
2. Read first frame → deserialize as `ClientHello`
3. Validate: `protocol == PROTOCOL_NAME` and `version <= CURRENT_VERSION`
4. If handshake fails: write `ServerHello::reject(...)` frame, return (close connection)
5. If handshake succeeds: write `ServerHello::accept(version)` frame
6. Request loop:
   - `read_frame` → on EOF: return cleanly (client disconnected)
   - On framing error: write `Response::protocol_error(Uuid::nil(), CODE_PROTOCOL_ERROR, msg)`, return (close connection)
   - Deserialize bytes as `Request` → on failure: write `Response::protocol_error(Uuid::nil(), CODE_INVALID_REQUEST, msg)`, continue loop
   - Call `dispatch(vault, &request, &peer).await`
   - Serialize `Response` → `write_frame`

**Error behavior:**
- Handshake failure → close connection
- Framing error (`protocol_error`) → close connection (stream is likely desynchronized)
- Bad JSON / unknown method / malformed params (`invalid_request`) → send error response, keep connection open

### `dispatch` function

```rust
async fn dispatch<K, S, A>(
    vault: &Vault<K, S, A>,
    request: &Request,
    peer: &PeerIdentity,
) -> Response
where
    K: KeySource,
    S: SecretStore,
    A: AuditLog,
```

Matches on `request.method`:
- `"store_secret"` → deserialize `StoreSecretRequest` from params, base64-decode plaintext, call `vault.store_secret(...)`, serialize `SecretMetadata` as result
- `"request_lease"` → deserialize `RequestLeaseRequest`, call `vault.request_lease(...)`, serialize `LeaseGrant`
- `"access_secret"` → deserialize `AccessSecretRequest`, call `vault.access_secret(...)`, `guard.expose()` → base64-encode, serialize `AccessSecretResponse`
- `"revoke_lease"` → deserialize `RevokeLeaseRequest`, convert `reason` field from `serde_json::Value` to `RevocationReason` via `serde_json::from_value(request.reason)` (map failure to `invalid_request`), call `vault.revoke_lease(&lease_id, reason, peer)`, return empty result `{}`
- `"revoke_all_for_agent"` → deserialize `RevokeAllForAgentRequest`, call `vault.revoke_all_for_agent(...)`, serialize `RevokeAllForAgentResponse`
- `"list_secrets"` → call `vault.list_secrets()`, convert each `SecretMetadata` to `serde_json::Value` via `serde_json::to_value`, wrap in `ListSecretsResponse`, serialize
- `"renew_lease"` → deserialize `RenewLeaseRequest`, call `vault.renew_lease(...)`, serialize `LeaseGrant`
- `"delete_secret"` → deserialize `DeleteSecretRequest`, call `vault.delete_secret(...)`, return empty result `{}`
- Unknown method → `Response::protocol_error(request.id, CODE_INVALID_REQUEST, "unknown method: ...")`

If params deserialization fails → `Response::protocol_error(request.id, CODE_INVALID_REQUEST, "invalid params: ...")`.

If the vault method returns an `Err(e)` → `Response::from_error(request.id, &e)`.

All vault method calls pass `peer` from the connection context (not from the request).

### `UdsListener`

```rust
pub struct UdsListener {
    inner: tokio::net::UnixListener,
}
```

**Constructor:** `UdsListener::bind(path: impl AsRef<Path>) -> Result<Self>` — calls `tokio::net::UnixListener::bind(path)`, maps `io::Error` to `Error::Transport`.

**`VaultListener` impl:**
- `type Stream = tokio::net::UnixStream`
- `accept()` — calls `self.inner.accept()`, extracts peer credentials via `stream.peer_cred()`:
  - `tokio::net::UnixStream::peer_cred()` returns `io::Result<UCred>`. Tokio abstracts over `SO_PEERCRED` (Linux) and `LOCAL_PEERCRED` (macOS) behind this single API — it is available on both platforms.
  - UID: `cred.uid()` (always available)
  - PID: `cred.pid().unwrap_or(0) as u32` (may be `None` on some platforms)
  - Builds `PeerIdentity::Unix { uid, pid }`
  - If `peer_cred()` fails at runtime: use `PeerIdentity::Anonymous` (don't fail the connection)

**No socket file management.** The caller creates and removes the socket file. The listener just binds and accepts. Before binding, the caller should remove any stale socket file from a previous run.

### Three new vault methods

**`list_secrets(&self) -> Result<Vec<SecretMetadata>>`**

Delegates to `self.store.list()`. No policy check, no audit — listing metadata is an admin operation.

**`renew_lease(&self, lease_id: &LeaseId, extension_secs: i64, peer: &PeerIdentity) -> Result<LeaseGrant>`**

1. Lock `self.leases` for write
2. Find lease by ID → `Error::LeaseNotFound` if missing
3. Check if lease is expired (`Utc::now() > lease.expires_at`) → `Error::LeaseExpired` if so (prevents renewing already-expired leases that haven't been GC'd yet)
4. Call `lease.renew(TimeDelta::seconds(extension_secs))` → returns error if not renewable or revoked
5. Build `LeaseGrant::from(&lease)`, extract `lease.agent.clone()` for audit
6. Release lock
7. Audit log `AuditEntry::new(AuditEvent::LeaseRenewed { lease_id, extension_secs }, agent, peer, AuditOutcome::Success)`
8. Return the updated `LeaseGrant`

**`delete_secret(&self, name: &SecretName, peer: &PeerIdentity) -> Result<()>`**

1. Lock `self.leases` for write, iterate and revoke any whose `secret_name == name` and not already revoked (best-effort audit for each, same pattern as `revoke_all_for_agent`)
2. Release the lease lock before calling the store (avoid holding the lock across async I/O)
3. Call `self.store.delete(name)` → `Error::SecretNotFound` if missing
4. Audit log `AuditEntry::new(AuditEvent::SecretDeleted { secret_name }, AgentId::new("admin"), peer, AuditOutcome::Success)`
5. Return `()`

### New audit event

Add to the `AuditEvent` enum in `src/audit/mod.rs`:

```rust
    /// A lease was renewed.
    LeaseRenewed {
        lease_id: LeaseId,
        extension_secs: i64,
    },
```

## Testing

### Dispatch tests (unit tests in `src/server.rs`)

Using `EnvVarSource` + `SqliteStore` + `NoopAuditLog` (same pattern as the existing vault integration test):

1. **store_secret dispatches** — send store request, verify success response with metadata
2. **request_lease dispatches** — store a secret first, then request a lease, verify `LeaseGrant`
3. **access_secret dispatches** — full flow: store → lease → access, verify base64-encoded secret
4. **list_secrets dispatches** — store two secrets, list, verify count
5. **renew_lease dispatches** — request a renewable lease, renew, verify updated grant
6. **delete_secret dispatches** — store, delete, verify get fails
7. **revoke_lease dispatches** — request lease, revoke, verify
8. **revoke_all_for_agent dispatches** — request lease, revoke all, verify count
9. **Unknown method returns invalid_request**
10. **Malformed params returns invalid_request**

### Connection handler tests (integration tests in `src/server.rs`, using `tokio::io::duplex`)

11. **Full handshake + request/response** — duplex simulates client. Send ClientHello, receive ServerHello. Send store_secret, receive success.
12. **Bad handshake closes connection** — wrong protocol name → rejection + stream closes.
13. **Framing error closes connection** — write raw garbage bytes (not valid length-prefix), verify connection closes after error response.
14. **Invalid request keeps connection open** — send request with unknown method → error response, then send a valid request → still works.

### UDS listener tests (in `src/transport/uds.rs`, using temp directories)

15. **Bind and accept** — bind UDS in temp dir, connect with `tokio::net::UnixStream::connect`, verify listener yields a stream.
16. **Peer cred populated** — verify `PeerIdentity::Unix` with non-zero UID.

### Dependencies

- `tempfile` (existing dev-dep) for temp directories in UDS tests
- No new dependencies

## Out of scope

- vsock listener
- Client library
- TLS / authentication
- Graceful shutdown (signal handling)
- Connection limits / rate limiting
