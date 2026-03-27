//! Transport abstraction for vault client↔server communication.
//!
//! The vault server needs to accept connections over different transports
//! depending on the deployment environment:
//!
//! - **Unix domain socket**: developer laptops, local development
//! - **vsock**: Firecracker and QEMU VMs communicating with the host
//!
//! Both transports provide a bidirectional byte stream. We abstract over
//! them so the vault protocol (request/response framing, serialization)
//! is transport-agnostic.
//!
//! ## vsock note
//!
//! vsock (virtio-vsock) works on both QEMU and Firecracker. The guest
//! connects to the host using a context ID (CID) and port number.
//! CID 2 is always the host. This means the vault server runs on the
//! host and agents inside VMs connect to it without any network stack
//! involvement—no IP addresses, no firewall rules, no exposure to the
//! network.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Result;

pub mod uds;
#[cfg(feature = "vsock")]
pub mod vsock;

/// A bidirectional async byte stream. Both Unix sockets and vsock
/// connections implement AsyncRead + AsyncWrite, so we can treat
/// them uniformly.
pub trait VaultStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

// Blanket impl: anything that's AsyncRead + AsyncWrite + Send + Unpin is a
// VaultStream.
impl<T> VaultStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// Server-side transport listener. Accepts incoming connections from
/// agents and yields streams.
#[async_trait::async_trait]
pub trait VaultListener: Send + Sync + 'static {
    /// The concrete stream type this listener produces.
    type Stream: VaultStream;

    /// Accept the next incoming connection.
    async fn accept(&self) -> Result<(Self::Stream, PeerIdentity)>;
}

/// Identity of the connecting peer, derived from the transport layer.
///
/// For vsock, this is the guest CID (which maps to a specific VM).
/// For Unix sockets, this is the peer's UID/PID via SO_PEERCRED.
/// This provides a transport-level identity that can be cross-referenced
/// with the agent's presented AgentId for defense-in-depth.
#[derive(Debug, Clone)]
pub enum PeerIdentity {
    /// Unix socket peer: UID and PID from SO_PEERCRED.
    Unix { uid: u32, pid: u32 },

    /// vsock peer: the guest's context ID.
    Vsock { cid: u32 },

    /// Unknown or unauthenticated peer (e.g., during testing).
    Anonymous,
}

impl std::fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerIdentity::Unix { uid, pid } => write!(f, "unix(uid={uid}, pid={pid})"),
            PeerIdentity::Vsock { cid } => write!(f, "vsock(cid={cid})"),
            PeerIdentity::Anonymous => write!(f, "anonymous"),
        }
    }
}

/// Client-side transport connector. Used by agents to connect to the vault.
#[async_trait::async_trait]
pub trait VaultConnector: Send + Sync + 'static {
    /// The concrete stream type this connector produces.
    type Stream: VaultStream;

    /// Connect to the vault server.
    async fn connect(&self) -> Result<Self::Stream>;
}
