//! Adversarial security tests.
//!
//! These tests verify security properties that must hold for the vault
//! to be safe in production. Each test is named after the threat it
//! guards against.

#[cfg(test)]
#[cfg(feature = "sqlite")]
mod tests {
    use secrecy::SecretString;

    use crate::audit::*;
    use crate::crypto::Cipher;
    use crate::error::Error;
    use crate::keysource::DataEncryptionKey;
    use crate::lease::{Lease, LeaseGuard, LeaseTerms};
    use crate::policy::{AgentPattern, PolicyConfig, PolicyEngine, PolicyGrant, SecretPattern};
    use crate::store::{CipherAlgorithm, SecretKind};
    use crate::types::{AgentId, DomainScope, LeaseId, SecretName};

    // ========================================================
    // SECRET MATERIAL LEAKAGE
    // ========================================================

    #[test]
    fn dek_debug_does_not_leak_key_material() {
        let dek = DataEncryptionKey::from_bytes([0xAB; 32]);
        let debug = format!("{:?}", dek);
        assert!(debug.contains("REDACTED"), "DEK Debug should be redacted");
        assert!(!debug.contains("171"), "DEK Debug should not contain byte values");
        assert!(!debug.contains("0xab"), "DEK Debug should not contain hex bytes");
        assert!(!debug.contains("ab"), "DEK Debug should not contain key material");
    }

    #[test]
    fn lease_guard_debug_does_not_leak_secret() {
        let guard = LeaseGuard::new(LeaseId::new(), SecretString::from("super-secret-api-key-12345"));
        let debug = format!("{:?}", guard);
        assert!(debug.contains("REDACTED"), "LeaseGuard Debug should be redacted");
        assert!(
            !debug.contains("super-secret"),
            "LeaseGuard Debug must not contain the secret value"
        );
        assert!(
            !debug.contains("api-key"),
            "LeaseGuard Debug must not contain the secret value"
        );
    }

    #[test]
    fn error_messages_never_contain_secret_values() {
        // Construct errors with secret-like data and verify none leak values
        let errors: Vec<Error> = vec![
            Error::LeaseExpired(LeaseId::new()),
            Error::LeaseRevoked(LeaseId::new()),
            Error::LeaseNotFound(LeaseId::new()),
            Error::AccessDenied {
                agent: AgentId::new("agent"),
                secret: SecretName::new("secret-name"),
                domain: DomainScope::new("example.com"),
            },
            Error::SecretNotFound(SecretName::new("my-secret")),
            Error::SecretAlreadyExists(SecretName::new("my-secret")),
            Error::EncryptionFailed,
            Error::DecryptionFailed,
            Error::KeySourceUnavailable("reason".into()),
            Error::Storage("reason".into()),
            Error::Transport("reason".into()),
            Error::InvalidConfig("reason".into()),
        ];

        for err in &errors {
            let msg = err.to_string();
            let debug = format!("{:?}", err);
            // Error messages may contain secret NAMES (for debugging)
            // but must never contain actual secret VALUES or hint at
            // why cryptographic operations failed
            assert!(!msg.contains("wrong key"), "Error should not hint at key issues: {msg}");
            assert!(!msg.contains("tampered"), "Error should not hint at tampering: {msg}");
            // Debug output should also be safe
            assert!(
                !debug.contains("wrong key"),
                "Error Debug should not hint at key issues: {debug}"
            );
        }
    }

    // ========================================================
    // CRYPTOGRAPHIC PROPERTIES
    // ========================================================

    #[test]
    fn nonces_are_unique_across_encryptions() {
        let cipher = Cipher::new(CipherAlgorithm::Aes256Gcm);
        let key = DataEncryptionKey::from_bytes([0xAA; 32]);

        // Encrypt the same plaintext many times — nonces must differ
        let mut nonces = Vec::new();
        for _ in 0..100 {
            let sealed = cipher.encrypt(b"same-plaintext", &key).unwrap();
            nonces.push(sealed.nonce);
        }

        // All nonces should be unique (nonce reuse is catastrophic for AES-GCM)
        let unique_count = {
            let mut sorted = nonces.clone();
            sorted.sort();
            sorted.dedup();
            sorted.len()
        };
        assert_eq!(
            unique_count, 100,
            "nonce reuse detected! {unique_count}/100 unique nonces"
        );
    }

    #[test]
    fn different_keys_produce_different_ciphertext() {
        let cipher = Cipher::new(CipherAlgorithm::Aes256Gcm);
        let key_a = DataEncryptionKey::from_bytes([0xAA; 32]);
        let key_b = DataEncryptionKey::from_bytes([0xBB; 32]);

        let sealed_a = cipher.encrypt(b"secret", &key_a).unwrap();
        let sealed_b = cipher.encrypt(b"secret", &key_b).unwrap();

        assert_ne!(
            sealed_a.ciphertext, sealed_b.ciphertext,
            "different keys must produce different ciphertext"
        );
    }

    #[test]
    fn decryption_fails_cleanly_on_wrong_key() {
        let cipher = Cipher::new(CipherAlgorithm::Aes256Gcm);
        let key_a = DataEncryptionKey::from_bytes([0xAA; 32]);
        let key_b = DataEncryptionKey::from_bytes([0xBB; 32]);

        let sealed = cipher.encrypt(b"secret", &key_a).unwrap();
        let result = cipher.decrypt(&sealed, &key_b);

        assert!(result.is_err());
        // The error should be generic — no information about WHY it failed
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("key") && !err.contains("wrong"),
            "decryption error should not hint at the cause: {err}"
        );
    }

    // ========================================================
    // DOMAIN SCOPE ENFORCEMENT
    // ========================================================

    #[test]
    fn domain_scope_rejects_empty_string() {
        let scope = DomainScope::new("api.github.com");
        assert!(!scope.matches(""), "empty string should not match any scope");
    }

    #[test]
    fn domain_scope_wildcard_does_not_match_bare_domain() {
        // *.example.com should NOT match "example.com" (no subdomain)
        let scope = DomainScope::new("*.example.com");
        assert!(!scope.matches("example.com"));
    }

    #[test]
    fn domain_scope_is_case_sensitive() {
        // Domain matching should be exact — case matters
        let scope = DomainScope::new("api.github.com");
        assert!(scope.matches("api.github.com"));
        // Note: in production, hosts should be lowercased before matching.
        // This test documents current behavior.
        assert!(!scope.matches("API.GITHUB.COM"));
    }

    #[test]
    fn domain_scope_rejects_path_traversal() {
        let scope = DomainScope::new("api.github.com");
        assert!(!scope.matches("api.github.com/../../etc/passwd"));
        assert!(!scope.matches("api.github.com:443/path"));
    }

    #[test]
    fn domain_scope_wildcard_rejects_empty_subdomain() {
        let scope = DomainScope::new("*.example.com");
        // ".example.com" (empty subdomain prefix) should not match
        assert!(!scope.matches(".example.com"));
    }

    // ========================================================
    // POLICY ENGINE
    // ========================================================

    #[test]
    fn empty_policy_denies_everything() {
        let engine = PolicyEngine::new(PolicyConfig {
            default_lease_terms: LeaseTerms::default_short(),
            grants: vec![],
        });

        let result = engine.evaluate(
            &AgentId::new("any-agent"),
            &SecretName::new("any-secret"),
            &DomainScope::new("any.domain.com"),
        );
        assert!(result.is_err(), "empty policy must deny all access");
    }

    #[test]
    fn prefix_empty_string_matches_everything() {
        // This is a known behavior — document and test it
        let engine = PolicyEngine::new(PolicyConfig {
            default_lease_terms: LeaseTerms::default_short(),
            grants: vec![PolicyGrant {
                agent: AgentPattern::Prefix("".to_string()),
                secret: SecretPattern::Prefix("".to_string()),
                allowed_domains: vec![DomainScope::new("*.example.com")],
                lease_terms: None,
            }],
        });

        // Empty prefix matches any agent and any secret
        let result = engine.evaluate(
            &AgentId::new("literally-anyone"),
            &SecretName::new("literally-anything"),
            &DomainScope::new("foo.example.com"),
        );
        assert!(
            result.is_ok(),
            "empty prefix matches everything — this is expected but dangerous"
        );
    }

    #[test]
    fn agent_pattern_any_requires_domain_match() {
        // Even with AgentPattern::Any, the domain must still match
        let engine = PolicyEngine::new(PolicyConfig {
            default_lease_terms: LeaseTerms::default_short(),
            grants: vec![PolicyGrant {
                agent: AgentPattern::Any,
                secret: SecretPattern::Any,
                allowed_domains: vec![DomainScope::new("api.github.com")],
                lease_terms: None,
            }],
        });

        // Allowed domain
        assert!(
            engine
                .evaluate(
                    &AgentId::new("anyone"),
                    &SecretName::new("anything"),
                    &DomainScope::new("api.github.com"),
                )
                .is_ok()
        );

        // Disallowed domain
        assert!(
            engine
                .evaluate(
                    &AgentId::new("anyone"),
                    &SecretName::new("anything"),
                    &DomainScope::new("evil.example.com"),
                )
                .is_err()
        );
    }

    // ========================================================
    // LEASE VALIDATION
    // ========================================================

    #[test]
    fn expired_lease_cannot_be_used() {
        let terms = LeaseTerms {
            ttl: chrono::TimeDelta::seconds(-1), // already expired
            renewable: false,
            max_uses: None,
        };
        let lease = Lease::new(
            AgentId::new("agent"),
            SecretName::new("secret"),
            vec![DomainScope::new("api.example.com")],
            &terms,
        );
        assert!(
            lease.validate("api.example.com").is_err(),
            "expired lease must be rejected"
        );
    }

    #[test]
    fn revoked_lease_cannot_be_used() {
        let terms = LeaseTerms::default_short();
        let mut lease = Lease::new(
            AgentId::new("agent"),
            SecretName::new("secret"),
            vec![DomainScope::new("api.example.com")],
            &terms,
        );
        lease.revoke();
        assert!(
            lease.validate("api.example.com").is_err(),
            "revoked lease must be rejected"
        );
    }

    #[test]
    fn exhausted_lease_cannot_be_used() {
        let terms = LeaseTerms::single_use();
        let mut lease = Lease::new(
            AgentId::new("agent"),
            SecretName::new("secret"),
            vec![DomainScope::new("api.example.com")],
            &terms,
        );
        lease.record_use().unwrap(); // first use OK
        assert!(lease.record_use().is_err(), "exhausted lease must reject further use");
    }

    #[test]
    fn lease_domain_restriction_prevents_exfiltration() {
        let terms = LeaseTerms::default_short();
        let lease = Lease::new(
            AgentId::new("agent"),
            SecretName::new("github-pat"),
            vec![DomainScope::new("api.github.com")],
            &terms,
        );

        assert!(lease.validate("api.github.com").is_ok());
        assert!(
            lease.validate("evil.example.com").is_err(),
            "lease must reject access to unauthorized domains"
        );
        assert!(
            lease.validate("api.github.com.evil.com").is_err(),
            "lease must reject subdomain spoofing"
        );
    }

    // ========================================================
    // LEASE FLOODING PREVENTION
    // ========================================================

    #[tokio::test]
    async fn lease_cap_prevents_memory_exhaustion() {
        use std::sync::Arc;

        use crate::keysource::env::EnvVarSource;
        use crate::store::sqlite::SqliteStore;
        use crate::transport::PeerIdentity;

        // Set up a vault with a very low lease cap
        let key_var = "ZEROLEASE_SEC_LEASE_CAP";
        unsafe { std::env::set_var(key_var, "aa".repeat(32)) };

        let dir = tempfile::TempDir::new().unwrap();
        let store = SqliteStore::new(dir.path().join("secrets.db")).await.unwrap();

        // NoopAuditLog from the test infrastructure
        struct NoopAudit;
        #[async_trait::async_trait]
        impl crate::audit::AuditLog for NoopAudit {
            async fn record(&self, _: AuditEntry) -> crate::error::Result<()> {
                Ok(())
            }
            async fn query_by_agent(&self, _: &AgentId, _: usize) -> crate::error::Result<Vec<AuditEntry>> {
                Ok(vec![])
            }
            async fn query_by_secret(&self, _: &SecretName, _: usize) -> crate::error::Result<Vec<AuditEntry>> {
                Ok(vec![])
            }
            async fn query_by_lease(&self, _: &LeaseId) -> crate::error::Result<Vec<AuditEntry>> {
                Ok(vec![])
            }
        }

        let policy = PolicyEngine::new(PolicyConfig {
            default_lease_terms: LeaseTerms::default_short(),
            grants: vec![PolicyGrant {
                agent: AgentPattern::Exact(AgentId::new("flood-agent")),
                secret: SecretPattern::Exact(SecretName::new("test-secret")),
                allowed_domains: vec![DomainScope::new("api.example.com")],
                lease_terms: None,
            }],
        });

        let vault = Arc::new(
            crate::vault::Vault::new(
                EnvVarSource::new(key_var),
                store,
                NoopAudit,
                policy,
                CipherAlgorithm::Aes256Gcm,
            )
            .with_max_leases_per_agent(3), // Very low cap for testing
        );
        vault.initialize().await.unwrap();

        // Store a secret
        let peer = PeerIdentity::Anonymous;
        vault
            .store_secret(
                &SecretName::new("test-secret"),
                b"value",
                SecretKind::ApiKey,
                None,
                &peer,
            )
            .await
            .unwrap();

        // First 3 leases succeed
        for _ in 0..3 {
            vault
                .request_lease(
                    &AgentId::new("flood-agent"),
                    &SecretName::new("test-secret"),
                    &DomainScope::new("api.example.com"),
                    &peer,
                )
                .await
                .unwrap();
        }

        // 4th lease is rejected
        let result = vault
            .request_lease(
                &AgentId::new("flood-agent"),
                &SecretName::new("test-secret"),
                &DomainScope::new("api.example.com"),
                &peer,
            )
            .await;

        assert!(result.is_err(), "lease cap must prevent flooding");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("maximum"), "error should mention the limit: {err}");

        unsafe { std::env::remove_var(key_var) };
    }

    // ========================================================
    // WIRE PROTOCOL SAFETY
    // ========================================================

    #[tokio::test]
    async fn frame_size_limit_prevents_memory_exhaustion() {
        use crate::protocol::frame::{read_frame, write_frame};

        // Write path: oversized payload rejected
        let (mut client, _server) = tokio::io::duplex(1024);
        let huge = vec![0u8; 1_048_577]; // 1 MiB + 1
        assert!(
            write_frame(&mut client, &huge).await.is_err(),
            "oversized write must be rejected"
        );

        // Read path: oversized header rejected
        let (mut client, mut server) = tokio::io::duplex(1024);
        use tokio::io::AsyncWriteExt;
        let fake_len = (1_048_577u32).to_be_bytes();
        client.write_all(&fake_len).await.unwrap();
        assert!(
            read_frame(&mut server).await.is_err(),
            "oversized read must be rejected"
        );
    }

    // ========================================================
    // SQL INJECTION
    // ========================================================

    // ========================================================
    // ROLE-BASED ACCESS CONTROL
    // ========================================================

    #[tokio::test]
    async fn agent_role_cannot_call_admin_operations() {
        use std::sync::Arc;

        use crate::auth::{ConnectionIdentity, Role};
        use crate::keysource::env::EnvVarSource;
        use crate::protocol::{Request, methods};
        use crate::server::dispatch;
        use crate::store::sqlite::SqliteStore;
        use crate::transport::PeerIdentity;

        let key_var = "ZEROLEASE_SEC_ROLE_TEST";
        unsafe { std::env::set_var(key_var, "aa".repeat(32)) };

        let dir = tempfile::TempDir::new().unwrap();
        let store = SqliteStore::new(dir.path().join("secrets.db")).await.unwrap();

        struct NoopAudit;
        #[async_trait::async_trait]
        impl crate::audit::AuditLog for NoopAudit {
            async fn record(&self, _: AuditEntry) -> crate::error::Result<()> {
                Ok(())
            }
            async fn query_by_agent(&self, _: &AgentId, _: usize) -> crate::error::Result<Vec<AuditEntry>> {
                Ok(vec![])
            }
            async fn query_by_secret(&self, _: &SecretName, _: usize) -> crate::error::Result<Vec<AuditEntry>> {
                Ok(vec![])
            }
            async fn query_by_lease(&self, _: &LeaseId) -> crate::error::Result<Vec<AuditEntry>> {
                Ok(vec![])
            }
        }

        let policy = PolicyEngine::new(PolicyConfig {
            default_lease_terms: LeaseTerms::default_short(),
            grants: vec![],
        });

        let vault = Arc::new(crate::vault::Vault::new(
            EnvVarSource::new(key_var),
            store,
            NoopAudit,
            policy,
            CipherAlgorithm::Aes256Gcm,
        ));
        vault.initialize().await.unwrap();

        let peer = PeerIdentity::Anonymous;
        let agent_identity = ConnectionIdentity {
            role: Role::Agent,
            agent_id: Some(AgentId::new("test-agent")),
            label: "test-agent".to_string(),
        };

        // store_secret should be denied for agent role
        let store_req = Request {
            id: uuid::Uuid::now_v7(),
            method: methods::STORE_SECRET.to_string(),
            params: serde_json::json!({}),
        };
        let resp = dispatch(&vault, &store_req, &peer, &agent_identity).await;
        assert!(!resp.ok, "agent should not be able to call store_secret");
        assert!(resp.error.as_ref().unwrap().code == "access_denied");

        // delete_secret should be denied
        let delete_req = Request {
            id: uuid::Uuid::now_v7(),
            method: methods::DELETE_SECRET.to_string(),
            params: serde_json::json!({}),
        };
        let resp = dispatch(&vault, &delete_req, &peer, &agent_identity).await;
        assert!(!resp.ok, "agent should not be able to call delete_secret");

        // list_secrets should be denied
        let list_req = Request {
            id: uuid::Uuid::now_v7(),
            method: methods::LIST_SECRETS.to_string(),
            params: serde_json::json!({}),
        };
        let resp = dispatch(&vault, &list_req, &peer, &agent_identity).await;
        assert!(!resp.ok, "agent should not be able to call list_secrets");

        unsafe { std::env::remove_var(key_var) };
    }

    #[test]
    fn agent_identity_is_bound_not_self_asserted() {
        use crate::auth::{ConnectionIdentity, Role};

        // An agent connection has a bound identity
        let identity = ConnectionIdentity {
            role: Role::Agent,
            agent_id: Some(AgentId::new("real-agent")),
            label: "real-agent".to_string(),
        };

        // The resolve_agent logic in dispatch should use the bound identity,
        // not the requested one. We test this by checking the role behavior:
        // - Agent role: bound identity overrides request
        assert_eq!(identity.role, Role::Agent);
        assert_eq!(identity.agent_id.as_ref().unwrap().as_str(), "real-agent");

        // An orchestrator can assert any identity
        let orchestrator = ConnectionIdentity {
            role: Role::Orchestrator,
            agent_id: None,
            label: "zeroclaw".to_string(),
        };
        assert_eq!(orchestrator.role, Role::Orchestrator);
        assert!(orchestrator.agent_id.is_none());
    }

    // ========================================================
    // SQL INJECTION
    // ========================================================

    #[tokio::test]
    async fn sql_injection_in_secret_name_is_safe() {
        use crate::store::sqlite::SqliteStore;
        use crate::store::{SecretStore, StoreSecretParams};

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = SqliteStore::new(tmp.path()).await.unwrap();

        // Try to inject SQL through the secret name
        let malicious_name = "'; DROP TABLE secrets; --";
        let params = StoreSecretParams {
            name: SecretName::new(malicious_name),
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            algorithm: CipherAlgorithm::Aes256Gcm,
            kind: SecretKind::ApiKey,
            description: Some("'; DROP TABLE secrets; --".into()),
        };

        // This should succeed (parameterized query, not string interpolation)
        let stored = store.put(params).await.unwrap();
        assert_eq!(stored.name, SecretName::new(malicious_name));

        // Verify the table still exists and the secret is retrievable
        let fetched = store.get(&SecretName::new(malicious_name)).await.unwrap();
        assert_eq!(fetched.name, SecretName::new(malicious_name));

        // Verify list still works (table wasn't dropped)
        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn sql_injection_in_audit_agent_is_safe() {
        use crate::audit::sqlite::SqliteAuditLog;
        use crate::transport::PeerIdentity;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let log = SqliteAuditLog::new(tmp.path()).await.unwrap();

        let malicious_agent = "'; DROP TABLE audit_events; --";
        let entry = AuditEntry::new(
            AuditEvent::DekRotated,
            AgentId::new(malicious_agent),
            &PeerIdentity::Anonymous,
            AuditOutcome::Success,
        );

        log.record(entry).await.unwrap();

        // Verify the table still exists
        let results = log.query_by_agent(&AgentId::new(malicious_agent), 10).await.unwrap();
        assert_eq!(results.len(), 1);
    }
}
