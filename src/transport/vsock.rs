//! vsock transport for VM-isolated vault communication.
//!
//! Uses `tokio_vsock` for Firecracker and QEMU host-guest connections.
//! The vault server runs on the host and agents inside VMs connect
//! using a context ID (CID) and port number. No network stack involved.

use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener as TokioVsockListener, VsockStream};

use crate::error::{Error, Result};
use crate::transport::{PeerIdentity, VaultConnector, VaultListener};

/// A vault listener backed by a vsock socket.
///
/// Binds to `VMADDR_CID_ANY` on a given port, accepting connections
/// from any guest VM (or host). The peer's CID is extracted for
/// `PeerIdentity::Vsock`.
pub struct VsockListener {
    inner: TokioVsockListener,
}

impl VsockListener {
    /// Bind a vsock listener on the given port.
    ///
    /// Listens on `VMADDR_CID_ANY` (accepts from any CID).
    pub fn bind(port: u32) -> Result<Self> {
        let addr = VsockAddr::new(VMADDR_CID_ANY, port);
        let inner =
            TokioVsockListener::bind(addr).map_err(|e| Error::Transport(format!("failed to bind vsock: {e}")))?;
        Ok(Self { inner })
    }
}

#[async_trait::async_trait]
impl VaultListener for VsockListener {
    type Stream = VsockStream;

    async fn accept(&self) -> Result<(Self::Stream, PeerIdentity)> {
        let (stream, addr) = self
            .inner
            .accept()
            .await
            .map_err(|e| Error::Transport(format!("vsock accept failed: {e}")))?;

        let peer = PeerIdentity::Vsock { cid: addr.cid() };

        Ok((stream, peer))
    }
}

/// A connector for vsock transport.
///
/// Connects to a vault server at the given CID and port.
/// CID 2 is conventionally the host.
pub struct VsockConnector {
    cid: u32,
    port: u32,
}

impl VsockConnector {
    /// Create a new vsock connector for the given CID and port.
    pub fn new(cid: u32, port: u32) -> Self {
        Self { cid, port }
    }
}

#[async_trait::async_trait]
impl VaultConnector for VsockConnector {
    type Stream = VsockStream;

    async fn connect(&self) -> Result<Self::Stream> {
        let addr = VsockAddr::new(self.cid, self.port);
        VsockStream::connect(addr)
            .await
            .map_err(|e| Error::Transport(format!("vsock connect failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsock_addr_construction() {
        // Verify VsockAddr is built correctly from our parameters
        let addr = VsockAddr::new(VMADDR_CID_ANY, 5000);
        assert_eq!(addr.cid(), VMADDR_CID_ANY);
        assert_eq!(addr.port(), 5000);
    }

    #[test]
    fn connector_stores_parameters() {
        let connector = VsockConnector::new(2, 9001);
        assert_eq!(connector.cid, 2);
        assert_eq!(connector.port, 9001);
    }

    #[tokio::test]
    async fn listener_bind_fails_gracefully_without_vsock_device() {
        // On a regular Linux box (no hypervisor), binding vsock should
        // return an error, not panic. Needs a tokio runtime because
        // tokio_vsock registers with the reactor during bind.
        let result = VsockListener::bind(5000);
        // We don't assert Ok or Err — on a host with vsock support
        // this might succeed. We just verify it doesn't panic.
        match result {
            Ok(_) => {
                // vsock device is available (running in a VM or host with
                // vsock)
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("failed to bind vsock"),
                    "error should be wrapped in our Transport error: {msg}"
                );
            }
        }
    }

    #[tokio::test]
    async fn connector_fails_gracefully_without_vsock_device() {
        // Same as above but for the connect path
        let connector = VsockConnector::new(2, 5000);
        let result = connector.connect().await;
        match result {
            Ok(_) => {
                // vsock device is available
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("vsock connect failed"),
                    "error should be wrapped in our Transport error: {msg}"
                );
            }
        }
    }

    #[test]
    fn description_uses_vsock_peer_identity() {
        // Verify PeerIdentity::Vsock formats correctly
        let peer = PeerIdentity::Vsock { cid: 42 };
        let display = format!("{peer}");
        assert_eq!(display, "vsock(cid=42)");
    }
}
