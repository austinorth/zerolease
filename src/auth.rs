//! Connection authentication and role-based access control.
//!
//! The `Authenticator` trait determines what a connection is allowed to do
//! based on the transport-level `PeerIdentity`. Three roles exist:
//!
//! - **Admin**: full access to all operations (store, delete, list, rotate)
//! - **Agent**: bound to a single agent identity, can only
//!   request/access/revoke leases
//! - **Orchestrator**: trusted to assert agent identity per request (for
//!   systems acting on behalf of multiple users, like the zeroclaw
//!   orchestrator)

use crate::transport::PeerIdentity;
use crate::types::AgentId;

/// The role assigned to an authenticated connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// Full access to all operations.
    Admin,
    /// Bound to a single agent identity. Cannot call admin operations.
    /// The agent field in requests is ignored — the server substitutes
    /// the bound identity.
    Agent,
    /// Trusted to assert any agent identity per request. Cannot call
    /// admin operations. Used by orchestrators that act on behalf of
    /// multiple users (e.g., a Slack bot, CI system).
    Orchestrator,
}

/// The authenticated identity of a connection.
#[derive(Debug, Clone)]
pub struct ConnectionIdentity {
    /// What this connection is allowed to do.
    pub role: Role,
    /// For Agent connections: the bound agent identity.
    /// For Orchestrator/Admin: None.
    pub agent_id: Option<AgentId>,
    /// Human-readable label for audit logs.
    pub label: String,
}

/// Determines the identity and role of a connection.
///
/// Implementations decide how to map transport-level peer identity
/// to application-level roles. This is where deployment-specific
/// authentication logic lives (e.g., checking Tailscale identity,
/// mapping vsock CIDs to agents, trusting the orchestrator process).
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync + 'static {
    /// Authenticate a connection based on its transport-level identity.
    ///
    /// Returns `Some(identity)` to accept the connection with the given
    /// role and identity, or `None` to reject it entirely.
    async fn authenticate(&self, peer: &PeerIdentity) -> Option<ConnectionIdentity>;
}

/// An authenticator that grants admin access to all connections.
///
/// **For development and testing only.** This is the default behavior
/// if no authenticator is configured, preserving backward compatibility.
pub struct AllowAllAdmin;

#[async_trait::async_trait]
impl Authenticator for AllowAllAdmin {
    async fn authenticate(&self, _peer: &PeerIdentity) -> Option<ConnectionIdentity> {
        Some(ConnectionIdentity {
            role: Role::Admin,
            agent_id: None,
            label: "allow-all-admin".to_string(),
        })
    }
}
