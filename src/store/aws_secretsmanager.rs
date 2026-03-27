//! AWS Secrets Manager secret store backend.
//!
//! Stores encrypted secrets as individual AWS Secrets Manager secrets.
//! Each zerolease secret maps to one Secrets Manager secret, with the
//! encrypted payload and metadata serialized as a JSON blob in the
//! secret value.
//!
//! This backend is suitable for cloud-native deployments where you want
//! to leverage AWS Secrets Manager's built-in encryption, replication,
//! access control (IAM), and audit logging (CloudTrail) alongside
//! zerolease's own encryption layer (defense in depth).
//!
//! ## Naming convention
//!
//! Secrets Manager secrets are stored under the prefix
//! `{prefix}/{secret_name}`, where `prefix` defaults to `zerolease`
//! but can be configured. This avoids collisions with other Secrets
//! Manager users in the same AWS account.
//!
//! ## Atomicity
//!
//! AWS Secrets Manager does not support multi-secret transactions.
//! `batch_update` performs updates sequentially and will return an error
//! on the first failure. Callers should be aware that partial updates
//! are possible—unlike the SQL-backed stores, there is no rollback.
//! In practice, batch updates are only used for DEK rotation, which
//! can be safely retried.

use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::error::SdkError;
use aws_sdk_secretsmanager::types::Filter;
use aws_sdk_secretsmanager::types::FilterNameStringType;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::store::{
    BatchUpdateItem, CipherAlgorithm, SecretKind, SecretMetadata, SecretStore,
    StoreSecretParams, StoredSecret,
};
use crate::types::{SecretId, SecretName};

/// AWS Secrets Manager-backed implementation of [`SecretStore`].
///
/// Each zerolease secret is stored as an individual Secrets Manager secret
/// with a JSON payload containing the encrypted data and metadata.
pub struct AwsSecretsManagerStore {
    client: Client,
    /// Prefix for Secrets Manager secret names (e.g., "zerolease").
    prefix: String,
}

/// Internal representation of the JSON payload stored in Secrets Manager.
#[derive(Debug, Serialize, Deserialize)]
struct SecretPayload {
    id: String,
    name: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    algorithm: CipherAlgorithm,
    kind: SecretKind,
    description: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: u32,
}

impl From<&StoredSecret> for SecretPayload {
    fn from(s: &StoredSecret) -> Self {
        Self {
            id: s.id.as_uuid().to_string(),
            name: s.name.as_str().to_string(),
            ciphertext: s.ciphertext.clone(),
            nonce: s.nonce.clone(),
            algorithm: s.algorithm,
            kind: s.kind.clone(),
            description: s.description.clone(),
            created_at: s.created_at,
            updated_at: s.updated_at,
            version: s.version,
        }
    }
}

impl SecretPayload {
    fn into_stored_secret(self) -> Result<StoredSecret> {
        let id_uuid =
            Uuid::parse_str(&self.id).map_err(|e| Error::Storage(format!("invalid UUID: {e}")))?;
        Ok(StoredSecret {
            id: SecretId::from_uuid(id_uuid),
            name: SecretName::new(self.name),
            ciphertext: self.ciphertext,
            nonce: self.nonce,
            algorithm: self.algorithm,
            kind: self.kind,
            description: self.description,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

impl AwsSecretsManagerStore {
    /// Create a new Secrets Manager store with the given AWS SDK client
    /// and prefix.
    ///
    /// The `prefix` is prepended to secret names (e.g., `zerolease/my-secret`).
    /// Use different prefixes to isolate multiple vault instances in the
    /// same AWS account.
    pub fn new(client: Client, prefix: impl Into<String>) -> Self {
        Self {
            client,
            prefix: prefix.into(),
        }
    }

    /// Create a new store using default AWS SDK configuration from the
    /// environment (credentials, region, etc.).
    pub async fn from_env(prefix: impl Into<String>) -> Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);
        Ok(Self::new(client, prefix))
    }

    /// Build the Secrets Manager name for a zerolease secret.
    fn sm_name(&self, name: &SecretName) -> String {
        format!("{}/{}", self.prefix, name.as_str())
    }

    /// Serialize a payload to a JSON string for storage.
    fn serialize_payload(payload: &SecretPayload) -> Result<String> {
        serde_json::to_string(payload)
            .map_err(|e| Error::Storage(format!("payload serialization failed: {e}")))
    }

    /// Deserialize a JSON string from Secrets Manager into a payload.
    fn deserialize_payload(s: &str) -> Result<SecretPayload> {
        serde_json::from_str(s)
            .map_err(|e| Error::Storage(format!("payload deserialization failed: {e}")))
    }

    /// Check if a Secrets Manager error indicates the secret doesn't exist.
    fn is_not_found_error<E: std::fmt::Debug>(err: &SdkError<E>) -> bool {
        matches!(err, SdkError::ServiceError(se) if {
            let msg = format!("{:?}", se.err());
            msg.contains("ResourceNotFoundException")
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for AwsSecretsManagerStore {
    async fn put(&self, params: StoreSecretParams) -> Result<StoredSecret> {
        let sm_name = self.sm_name(&params.name);
        let id = SecretId::new();
        let now = Utc::now();

        let stored = StoredSecret {
            id,
            name: params.name.clone(),
            ciphertext: params.ciphertext,
            nonce: params.nonce,
            algorithm: params.algorithm,
            kind: params.kind,
            description: params.description,
            created_at: now,
            updated_at: now,
            version: 1,
        };

        let payload = SecretPayload::from(&stored);
        let payload_str = Self::serialize_payload(&payload)?;

        // Try to create a new secret in Secrets Manager.
        let result = self
            .client
            .create_secret()
            .name(&sm_name)
            .secret_string(&payload_str)
            .description(format!("zerolease secret: {}", params.name.as_str()))
            .send()
            .await;

        match result {
            Ok(_) => Ok(stored),
            Err(err) => {
                let err_msg = format!("{err:?}");
                if err_msg.contains("ResourceExistsException") {
                    Err(Error::SecretAlreadyExists(params.name))
                } else {
                    Err(Error::Storage(format!(
                        "Secrets Manager create failed: {err}"
                    )))
                }
            }
        }
    }

    async fn get(&self, name: &SecretName) -> Result<StoredSecret> {
        let sm_name = self.sm_name(name);

        let result = self
            .client
            .get_secret_value()
            .secret_id(&sm_name)
            .send()
            .await;

        match result {
            Ok(output) => {
                let secret_string = output.secret_string().ok_or_else(|| {
                    Error::Storage("secret has no string value (binary secrets not supported)".into())
                })?;
                let payload = Self::deserialize_payload(secret_string)?;
                payload.into_stored_secret()
            }
            Err(err) => {
                if Self::is_not_found_error(&err) {
                    Err(Error::SecretNotFound(name.clone()))
                } else {
                    Err(Error::Storage(format!(
                        "Secrets Manager get failed: {err}"
                    )))
                }
            }
        }
    }

    async fn update(
        &self,
        name: &SecretName,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        algorithm: CipherAlgorithm,
    ) -> Result<StoredSecret> {
        // Fetch the existing secret to preserve metadata and increment version.
        let existing = self.get(name).await?;
        let now = Utc::now();

        let updated = StoredSecret {
            id: existing.id,
            name: existing.name,
            ciphertext,
            nonce,
            algorithm,
            kind: existing.kind,
            description: existing.description,
            created_at: existing.created_at,
            updated_at: now,
            version: existing.version + 1,
        };

        let payload = SecretPayload::from(&updated);
        let payload_str = Self::serialize_payload(&payload)?;
        let sm_name = self.sm_name(name);

        self.client
            .put_secret_value()
            .secret_id(&sm_name)
            .secret_string(&payload_str)
            .send()
            .await
            .map_err(|err| {
                if Self::is_not_found_error(&err) {
                    Error::SecretNotFound(name.clone())
                } else {
                    Error::Storage(format!("Secrets Manager update failed: {err}"))
                }
            })?;

        Ok(updated)
    }

    async fn batch_update(&self, updates: Vec<BatchUpdateItem>) -> Result<()> {
        // AWS Secrets Manager has no transaction support, so we perform
        // sequential updates. On failure, already-applied updates are NOT
        // rolled back. This is acceptable because batch_update is only used
        // for DEK rotation, which is idempotent and can be retried.
        for item in &updates {
            self.update(&item.name, item.ciphertext.clone(), item.nonce.clone(), item.algorithm)
                .await?;
        }
        Ok(())
    }

    async fn delete(&self, name: &SecretName) -> Result<()> {
        let sm_name = self.sm_name(name);

        // Force delete without recovery window to match the behavior of
        // the SQL-backed stores (immediate removal).
        let result = self
            .client
            .delete_secret()
            .secret_id(&sm_name)
            .force_delete_without_recovery(true)
            .send()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(err) => {
                if Self::is_not_found_error(&err) {
                    Err(Error::SecretNotFound(name.clone()))
                } else {
                    Err(Error::Storage(format!(
                        "Secrets Manager delete failed: {err}"
                    )))
                }
            }
        }
    }

    async fn list(&self) -> Result<Vec<SecretMetadata>> {
        let prefix_filter = format!("{}/", self.prefix);
        let mut secrets = Vec::new();
        let mut next_token: Option<String> = None;

        // Paginate through all secrets matching our prefix.
        loop {
            let mut request = self
                .client
                .list_secrets()
                .filters(
                    Filter::builder()
                        .key(FilterNameStringType::Name)
                        .values(&prefix_filter)
                        .build(),
                );

            if let Some(token) = &next_token {
                request = request.next_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| Error::Storage(format!("Secrets Manager list failed: {e}")))?;

            for secret in response.secret_list() {
                let sm_name = match secret.name() {
                    Some(n) => n.to_string(),
                    None => continue,
                };

                // Fetch the actual value to get our metadata payload.
                let value_result = self
                    .client
                    .get_secret_value()
                    .secret_id(&sm_name)
                    .send()
                    .await;

                match value_result {
                    Ok(output) => {
                        if let Some(secret_string) = output.secret_string() {
                            match Self::deserialize_payload(secret_string) {
                                Ok(payload) => match payload.into_stored_secret() {
                                    Ok(stored) => {
                                        secrets.push(SecretMetadata::from(&stored));
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            name = sm_name,
                                            error = %e,
                                            "skipping secret with invalid payload"
                                        );
                                    }
                                },
                                Err(e) => {
                                    tracing::warn!(
                                        name = sm_name,
                                        error = %e,
                                        "skipping secret with unparseable payload"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            name = sm_name,
                            error = %e,
                            "skipping secret that could not be fetched"
                        );
                    }
                }
            }

            next_token = response.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(secrets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::CipherAlgorithm;

    fn test_params(name: &str) -> StoreSecretParams {
        StoreSecretParams {
            name: SecretName::new(name),
            ciphertext: vec![1, 2, 3, 4],
            nonce: vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            algorithm: CipherAlgorithm::Aes256Gcm,
            kind: SecretKind::Pat,
            description: Some("test secret".into()),
        }
    }

    /// Create a test store pointed at real AWS Secrets Manager.
    /// Requires AWS credentials in the environment.
    async fn test_store() -> AwsSecretsManagerStore {
        let prefix = format!(
            "zerolease-test/{}",
            Uuid::now_v7().to_string().split('-').next().expect("uuid has parts")
        );
        AwsSecretsManagerStore::from_env(prefix)
            .await
            .expect("should create store")
    }

    /// Clean up test secrets by deleting them.
    async fn cleanup(store: &AwsSecretsManagerStore, names: &[&str]) {
        for name in names {
            let _ = store.delete(&SecretName::new(*name)).await;
        }
    }

    #[tokio::test]
    #[ignore] // requires AWS credentials and Secrets Manager access
    async fn put_and_get_round_trip() {
        let store = test_store().await;
        let params = test_params("sm-secret");

        let stored = store.put(params).await.expect("should put secret");
        assert_eq!(stored.name, SecretName::new("sm-secret"));
        assert_eq!(stored.ciphertext, vec![1, 2, 3, 4]);
        assert_eq!(stored.algorithm, CipherAlgorithm::Aes256Gcm);
        assert_eq!(stored.version, 1);

        let fetched = store
            .get(&SecretName::new("sm-secret"))
            .await
            .expect("should get secret");
        assert_eq!(fetched.name, stored.name);
        assert_eq!(fetched.ciphertext, stored.ciphertext);
        assert_eq!(fetched.nonce, stored.nonce);

        cleanup(&store, &["sm-secret"]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn put_duplicate_name_errors() {
        let store = test_store().await;
        store
            .put(test_params("sm-dup"))
            .await
            .expect("should put first secret");

        let result = store.put(test_params("sm-dup")).await;
        assert!(result.is_err());
        let err = result.expect_err("should error").to_string();
        assert!(err.contains("already exists"), "error was: {err}");

        cleanup(&store, &["sm-dup"]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn get_missing_errors() {
        let store = test_store().await;
        let result = store.get(&SecretName::new("sm-nonexistent")).await;
        assert!(result.is_err());
        let err = result.expect_err("should error").to_string();
        assert!(err.contains("not found"), "error was: {err}");
    }

    #[tokio::test]
    #[ignore]
    async fn update_increments_version() {
        let store = test_store().await;
        store
            .put(test_params("sm-versioned"))
            .await
            .expect("should put secret");

        let updated = store
            .update(
                &SecretName::new("sm-versioned"),
                vec![10, 20, 30],
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                CipherAlgorithm::Aes256Gcm,
            )
            .await
            .expect("should update secret");

        assert_eq!(updated.version, 2);
        assert_eq!(updated.ciphertext, vec![10, 20, 30]);

        cleanup(&store, &["sm-versioned"]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn delete_removes_secret() {
        let store = test_store().await;
        store
            .put(test_params("sm-doomed"))
            .await
            .expect("should put secret");

        store
            .delete(&SecretName::new("sm-doomed"))
            .await
            .expect("should delete secret");

        let result = store.get(&SecretName::new("sm-doomed")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn delete_missing_errors() {
        let store = test_store().await;
        let result = store.delete(&SecretName::new("sm-nope")).await;
        assert!(result.is_err());
        let err = result.expect_err("should error").to_string();
        assert!(err.contains("not found"), "error was: {err}");
    }

    #[tokio::test]
    #[ignore]
    async fn list_returns_metadata() {
        let store = test_store().await;
        store
            .put(test_params("sm-first"))
            .await
            .expect("should put first secret");
        store
            .put(test_params("sm-second"))
            .await
            .expect("should put second secret");

        let list = store.list().await.expect("should list secrets");
        assert!(list.len() >= 2);

        let names: Vec<String> = list.iter().map(|m| m.name.as_str().to_string()).collect();
        assert!(names.contains(&"sm-first".to_string()));
        assert!(names.contains(&"sm-second".to_string()));

        cleanup(&store, &["sm-first", "sm-second"]).await;
    }
}
