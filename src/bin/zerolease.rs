//! zerolease standalone vault server.
//!
//! Starts a vault server on a Unix domain socket with SQLite storage
//! and environment variable key management. Handles ctrl-c for
//! graceful shutdown.
//!
//! Usage:
//!   ZEROLEASE_KEY=$(openssl rand -hex 32) cargo run -- \
//!     --socket /tmp/zerolease.sock \
//!     --db /tmp/zerolease-secrets.db \
//!     --audit-db /tmp/zerolease-audit.db
//!
//! Connect with a client or test with:
//!   echo '{"protocol":"zerolease","version":1}' | socat -
//! UNIX-CONNECT:/tmp/zerolease.sock

use std::path::PathBuf;
use std::sync::Arc;

use zerolease::audit::sqlite::SqliteAuditLog;
use zerolease::auth::AllowAllAdmin;
use zerolease::keysource::env::EnvVarSource;
use zerolease::server::VaultServer;
use zerolease::store::CipherAlgorithm;
use zerolease::store::sqlite::SqliteStore;
use zerolease::transport::uds::UdsListener;
use zerolease::vault::Vault;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse args (minimal — no clap dependency)
    let args: Vec<String> = std::env::args().collect();
    let socket_path = get_arg(&args, "--socket").unwrap_or_else(|| "/tmp/zerolease.sock".into());
    let db_path = get_arg(&args, "--db").unwrap_or_else(|| "/tmp/zerolease-secrets.db".into());
    let audit_path = get_arg(&args, "--audit-db").unwrap_or_else(|| "/tmp/zerolease-audit.db".into());
    let key_var = get_arg(&args, "--key-var").unwrap_or_else(|| "ZEROLEASE_KEY".into());

    // Initialize tracing (structured JSON to stderr)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    // Run the async server
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(socket_path, db_path, audit_path, key_var))
}

async fn run(
    socket_path: String,
    db_path: String,
    audit_path: String,
    key_var: String,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(
        socket = %socket_path,
        db = %db_path,
        audit = %audit_path,
        key_var = %key_var,
        "starting zerolease vault"
    );

    // Set up components
    let key_source = EnvVarSource::new(&key_var);
    let store = SqliteStore::new(&db_path).await?;
    let audit = SqliteAuditLog::new(&audit_path).await?;

    let policy = zerolease::policy::PolicyEngine::new(zerolease::policy::PolicyConfig {
        default_lease_terms: zerolease::lease::LeaseTerms::default_short(),
        grants: vec![],
    });

    let vault = Arc::new(Vault::new(key_source, store, audit, policy, CipherAlgorithm::Aes256Gcm));

    vault.initialize().await?;
    tracing::info!("vault initialized, DEK loaded");

    // Remove stale socket file if it exists
    let sock = PathBuf::from(&socket_path);
    if sock.exists() {
        std::fs::remove_file(&sock)?;
        tracing::info!("removed stale socket file");
    }

    let listener = UdsListener::bind(&sock)?;
    tracing::info!(socket = %socket_path, "listening for connections");

    let server = VaultServer::new(vault, listener, Arc::new(AllowAllAdmin));

    // Run until ctrl-c
    server
        .serve_with_shutdown(async {
            tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
        })
        .await?;

    // Clean up socket
    std::fs::remove_file(&sock).ok();
    tracing::info!("server stopped");

    Ok(())
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}
