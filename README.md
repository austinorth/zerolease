# zerolease

A credential vault for AI agent environments. Stores secrets encrypted at rest and grants access through leases: time-bounded, scope-restricted handles that expire automatically and can be revoked at any time.

[![Tests](https://github.com/ceejbot/zerolease/actions/workflows/test.yaml/badge.svg)](https://github.com/ceejbot/zerolease/actions/workflows/test.yaml) [![audit-dependencies](https://github.com/ceejbot/zerolease/actions/workflows/audit.yaml/badge.svg)](https://github.com/ceejbot/zerolease/actions/workflows/audit.yaml) [![codecov](https://codecov.io/github/ceejbot/zerolease/graph/badge.svg?token=XGD9GA2H66)](https://codecov.io/github/ceejbot/zerolease)

## Why

When AI agents use tools that need credentials — API tokens, SSH keys, database passwords — giving the agent direct access to the credential is dangerous. An agent with a raw GitHub PAT can use it against any endpoint, keep it indefinitely, and leak it to any tool it invokes.

`zerolease` sits between agents and credentials. Instead of handing out a token, the vault issues a _lease_: a handle that grants access to a specific credential, for a specific domain, for a limited time. A Jira PAT can only be injected into requests to `*.atlassian.net`. A GitHub token expires after 15 minutes. Every access is logged.

## Design

The vault is a single Rust process that agents connect to over Unix domain sockets (on developer machines) or vsock (in Firecracker/QEMU VMs). Credentials never leave the vault as plaintext over a network — the transport is local to the host or hypervisor.

**Encryption.** Secrets are encrypted at rest using `AES-256-GCM` or `XChaCha20-Poly1305` (configurable per secret, with algorithm migration support). The data encryption key is managed by a pluggable key source: OS keychain for developer machines, AWS KMS for production, or an environment variable for CI.

**Policy.** Access is deny-by-default. A flat list of grant rules specifies which agents can access which secrets for which domains. First match wins. The policy format is intentionally simple — easier to audit than a policy language.

**Leases.** Every credential access goes through a lease. Leases have a TTL, an optional use count, and a list of allowed target domains. The vault tracks active leases in memory, enforces per-agent caps, and garbage-collects expired ones. Secret values are zeroized from memory when the lease guard is dropped.

**Authentication.** Connections are authenticated via a pluggable `Authenticator` trait that maps transport-level peer identity to roles. Three roles exist: Admin (full access), Agent (bound to a single identity, can only use leases), and Orchestrator (trusted to assert agent identity per request, for systems like Slack bots acting on behalf of multiple users).

**Audit.** Every lease grant, secret access, revocation, and policy denial is emitted as a structured `tracing` event (observable via any tracing subscriber) and optionally persisted to a queryable SQLite audit log.

## Quick start

```bash
# Generate a data encryption key
export ZEROLEASE_KEY=$(openssl rand -hex 32)

# Run the example (direct vault API, no server)
cargo run --example basic_vault

# Or start the standalone server
cargo run -- --socket /tmp/zerolease.sock --db secrets.db --audit-db audit.db
```

The example stores a secret, requests a lease, accesses the credential through the lease, and demonstrates domain restriction.

## Feature flags

| Flag       | Default | What it enables                                       |
| ---------- | ------- | ----------------------------------------------------- |
| `sqlite`   | Yes     | SQLite secret store and audit log                     |
| `postgres` | No      | PostgreSQL secret store                               |
| `kms`      | No      | AWS KMS envelope encryption key source                |
| `vsock`    | No      | vsock transport for Firecracker/QEMU VMs (Linux only) |

## Building

Requires Rust edition 2024.

```
cargo build                              # default features (SQLite)
cargo build --features postgres          # with PostgreSQL support
cargo build --features kms               # with AWS KMS support
cargo build --features vsock             # with vsock transport (Linux only)
cargo test                               # run tests (116 default)
cargo doc --open                         # browse API documentation
```

## Testing

The test suite covers unit tests, integration tests, security tests, and fuzz targets.

```bash
# Default test suite (116 tests)
cargo test

# PostgreSQL integration tests (requires a running Postgres)
createdb zerolease_test
cargo test --features postgres store::postgres::tests -- --ignored --test-threads=1

# AWS KMS integration tests (requires AWS credentials)
cargo test --features kms keysource::kms::tests -- --ignored

# OS keychain integration test (requires macOS Keychain or Linux secret-service)
cargo test keysource::keychain -- --ignored

# Fuzz targets (requires nightly)
cargo +nightly fuzz run fuzz_read_frame -- -max_total_time=60
cargo +nightly fuzz run fuzz_protocol_deser -- -max_total_time=60
cargo +nightly fuzz run fuzz_domain_scope -- -max_total_time=60
```

## Wire protocol

The protocol is JSON over length-prefixed frames (4-byte big-endian length + payload). Each connection begins with a version handshake. Requests carry a UUID v7 identifier for correlation. Eight methods are supported: `store_secret`, `request_lease`, `access_secret`, `revoke_lease`, `revoke_all_for_agent`, `list_secrets`, `renew_lease`, `delete_secret`.

See the module documentation (`cargo doc --open`) for protocol details and type definitions.

## Security

The vault has been through an adversarial security audit with all findings resolved:

- Secret material is zeroized on drop (`Zeroize`, `SecretString`, `Zeroizing<Vec<u8>>`)
- Decryption errors are generic (no information leakage about failure cause)
- Domain scope matching rejects edge cases (empty subdomains, path traversal)
- Policy engine is deny-by-default; empty prefix patterns are warned
- Lease renewal is capped at 24 hours; per-agent lease count is capped
- DEK rotation is atomic (database transaction)
- SQL injection is prevented by parameterized queries (tested explicitly)
- Debug impls redact secret material
- Role-based access control prevents agents from calling admin operations
- Agent identity is bound at the transport level, not self-asserted
- Wire protocol fuzz-tested (~3.5 million executions, zero crashes)

## License

Apache-2.0
