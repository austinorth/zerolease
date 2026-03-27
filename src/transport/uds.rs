//! Unix domain socket transport for local vault communication.
//!
//! Uses `tokio::net::UnixListener` with `peer_cred()` to extract the
//! connecting process's UID and PID for `PeerIdentity::Unix`.

use std::path::Path;

use tokio::net::{UnixListener, UnixStream};

use crate::error::Result;
use crate::transport::{PeerIdentity, VaultConnector, VaultListener};

/// A [`VaultListener`] backed by a Unix domain socket.
///
/// The caller is responsible for managing the socket file lifecycle
/// (creation path, cleanup on shutdown).
pub struct UdsListener {
    inner: UnixListener,
}

impl UdsListener {
    /// Bind to the given filesystem path.
    ///
    /// The path must not already exist; the caller should remove any
    /// stale socket file before calling this.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self> {
        let inner = UnixListener::bind(path).map_err(|e| crate::error::Error::Transport(e.to_string()))?;
        Ok(Self { inner })
    }
}

#[async_trait::async_trait]
impl VaultListener for UdsListener {
    type Stream = UnixStream;

    async fn accept(&self) -> Result<(Self::Stream, PeerIdentity)> {
        let (stream, _addr) = self
            .inner
            .accept()
            .await
            .map_err(|e| crate::error::Error::Transport(e.to_string()))?;

        let peer = match stream.peer_cred() {
            Ok(cred) => PeerIdentity::Unix {
                uid: cred.uid(),
                pid: cred.pid().unwrap_or(0) as u32,
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to get peer credentials, using Anonymous");
                PeerIdentity::Anonymous
            }
        };

        Ok((stream, peer))
    }
}

/// A connector for Unix domain socket transport.
pub struct UdsConnector {
    path: std::path::PathBuf,
}

impl UdsConnector {
    /// Create a new connector for the given socket path.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait::async_trait]
impl VaultConnector for UdsConnector {
    type Stream = UnixStream;

    async fn connect(&self) -> Result<Self::Stream> {
        UnixStream::connect(&self.path)
            .await
            .map_err(|e| crate::error::Error::Transport(format!("failed to connect to UDS: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::UnixStream;

    use super::*;

    #[tokio::test]
    async fn bind_and_accept() {
        let dir = tempfile::TempDir::new().expect("failed to create temp directory");
        let sock_path = dir.path().join("test.sock");

        let listener = UdsListener::bind(&sock_path).expect("failed to bind UDS listener");

        let client = tokio::spawn({
            let path = sock_path.clone();
            async move {
                UnixStream::connect(path)
                    .await
                    .expect("client failed to connect to UDS")
            }
        });

        let (stream, peer) = listener.accept().await.expect("listener failed to accept connection");
        // Stream should be usable (not dropped).
        drop(stream);
        // Client connected successfully.
        let _ = client.await.expect("client task should not panic");

        // Peer identity should be extracted.
        assert!(
            matches!(peer, PeerIdentity::Unix { .. } | PeerIdentity::Anonymous),
            "expected Unix or Anonymous peer, got {peer:?}"
        );
    }

    #[tokio::test]
    async fn connector_connects_to_listener() {
        let dir = tempfile::TempDir::new().expect("failed to create temp directory");
        let sock_path = dir.path().join("connect.sock");

        let listener = UdsListener::bind(&sock_path).expect("failed to bind UDS listener");
        let connector = UdsConnector::new(&sock_path);

        let accept_task =
            tokio::spawn(async move { listener.accept().await.expect("listener failed to accept connection") });

        let client_stream = connector.connect().await.expect("connector failed to connect");
        let (server_stream, _peer) = accept_task.await.expect("accept task should not panic");

        drop(client_stream);
        drop(server_stream);
    }

    #[tokio::test]
    async fn peer_cred_populated() {
        let dir = tempfile::TempDir::new().expect("failed to create temp directory");
        let sock_path = dir.path().join("cred.sock");

        let listener = UdsListener::bind(&sock_path).expect("failed to bind UDS listener");

        let client = tokio::spawn({
            let path = sock_path.clone();
            async move {
                UnixStream::connect(path)
                    .await
                    .expect("client failed to connect to UDS")
            }
        });

        let (_stream, peer) = listener.accept().await.expect("listener failed to accept connection");
        let _ = client.await.expect("client task should not panic");

        assert!(
            matches!(peer, PeerIdentity::Unix { .. }),
            "expected PeerIdentity::Unix, got {peer:?}"
        );
    }
}
