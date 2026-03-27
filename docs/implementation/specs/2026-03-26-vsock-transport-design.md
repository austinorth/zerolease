# vsock Transport Design

**Date:** 2026-03-26
**Status:** Draft
**Scope:** New `src/transport/vsock.rs`, update `vsock` feature flag

## Problem

The vault supports UDS for local developer machines but has no transport for VM-isolated deployments. vsock (virtio-vsock) enables communication between a Firecracker/QEMU host and guest VMs without any network stack — the vault server runs on the host and agents inside VMs connect via CID + port.

## Design

### File structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/transport/vsock.rs` | `VsockListener`, `VsockConnector` |
| Modify | `src/transport/mod.rs` | Add `#[cfg(feature = "vsock")] pub mod vsock;` |
| Modify | `Cargo.toml` | Update `vsock = []` to `vsock = ["tokio-vsock"]` |

### `VsockListener`

```rust
pub struct VsockListener {
    inner: tokio_vsock::VsockListener,
}
```

**Constructor:** `VsockListener::bind(port: u32) -> Result<Self>` — binds to `VMADDR_CID_ANY` (accepts connections from any CID) on the given port. Maps errors to `Error::Transport`.

**`VaultListener` impl:**
- `type Stream = tokio_vsock::VsockStream`
- `accept()` — calls `self.inner.accept()`, extracts the peer CID from the remote address to build `PeerIdentity::Vsock { cid }`. `tokio_vsock::VsockStream` implements `AsyncRead + AsyncWrite + Send + Unpin`, satisfying `VaultStream` via the blanket impl.

### `VsockConnector`

```rust
pub struct VsockConnector {
    cid: u32,
    port: u32,
}
```

**Constructor:** `VsockConnector::new(cid: u32, port: u32)` — stores the target CID and port. CID 2 is conventionally the host.

**`VaultConnector` impl:** `connect()` calls `tokio_vsock::VsockStream::connect(self.cid, self.port)`, maps errors to `Error::Transport`.

### Feature flag

Update `Cargo.toml`:
```toml
vsock = ["tokio-vsock"]
```

This ties the `vsock` feature to the `tokio-vsock` dependency, which is already declared as optional and Linux-only. The module is gated with `#[cfg(feature = "vsock")]`.

### Platform gating

The `tokio-vsock` crate only compiles on Linux. The module declaration uses `#[cfg(feature = "vsock")]` — since the dependency is only available on Linux (`[target.'cfg(target_os = "linux")'.dependencies]`), enabling the feature on non-Linux platforms will fail at compile time. This is the correct behavior.

## Testing

vsock requires a hypervisor environment (Firecracker or QEMU with vsock configured). Tests are `#[ignore]` by default.

1. **Bind and accept** — `#[ignore]` — bind a VsockListener on a test port, connect with VsockConnector, verify stream and `PeerIdentity::Vsock` peer.

For development purposes, a basic smoke test that just verifies the types compile and the constructors work (without actually connecting) can run on Linux CI:

2. **Constructors compile** — (not `#[ignore]`) — just verify `VsockListener::bind` and `VsockConnector::new` are callable. This only runs when the `vsock` feature is enabled.

## Dependencies

No new dependencies — `tokio-vsock 0.7` is already in Cargo.toml as an optional dependency. The feature flag change just wires it up.

## Out of scope

- vsock device configuration on the host/guest
- CID management / discovery
- vsock proxy patterns
