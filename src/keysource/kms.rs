//! AWS KMS key source for production deployments.
//!
//! Uses envelope encryption: the master key lives in AWS KMS (never
//! leaves the HSM). We generate a local 32-byte data encryption key
//! (DEK) and encrypt it with KMS. The encrypted DEK blob is stored
//! on disk. On startup, KMS decrypts the blob to recover the DEK.
//!
//! This gives hardware-backed key protection without a KMS round-trip
//! for every secret operation.

use std::path::PathBuf;

use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use aws_config::BehaviorVersion;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;

use crate::error::{Error, Result};
use crate::keysource::{DataEncryptionKey, EncryptedDek, KeySource};

/// A key source backed by AWS KMS using envelope encryption.
///
/// The KMS key (identified by ARN or alias) encrypts/decrypts the
/// local DEK. The encrypted DEK blob is stored at `encrypted_dek_path`.
pub struct KmsSource {
    client: KmsClient,
    key_id: String,
    encrypted_dek_path: PathBuf,
    description: String,
}

impl KmsSource {
    /// Create a new KMS key source.
    ///
    /// Loads AWS credentials and configuration for the given region.
    /// The `key_id` can be a KMS key ARN, alias ARN, or alias name.
    /// The `encrypted_dek_path` is where the encrypted DEK blob is stored.
    pub async fn new(
        key_id: impl Into<String>,
        region: impl Into<String>,
        encrypted_dek_path: impl Into<PathBuf>,
    ) -> Result<Self> {
        let key_id = key_id.into();
        let region = region.into();
        let encrypted_dek_path = encrypted_dek_path.into();
        let description = format!("kms:{key_id}");

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_sdk_kms::config::Region::new(region))
            .load()
            .await;

        let client = KmsClient::new(&config);

        Ok(Self {
            client,
            key_id,
            encrypted_dek_path,
            description,
        })
    }
}

#[async_trait::async_trait]
impl KeySource for KmsSource {
    async fn load_or_create_dek(&self) -> Result<DataEncryptionKey> {
        if self.encrypted_dek_path.exists() {
            // Decrypt existing DEK blob
            let ciphertext = tokio::fs::read(&self.encrypted_dek_path).await.map_err(|e| {
                Error::KeySourceUnavailable(format!(
                    "failed to read encrypted DEK from {}: {e}",
                    self.encrypted_dek_path.display()
                ))
            })?;

            let response = self
                .client
                .decrypt()
                .ciphertext_blob(Blob::new(ciphertext))
                .key_id(&self.key_id)
                .send()
                .await
                .map_err(|e| Error::KeySourceUnavailable(format!("KMS decrypt failed: {e}")))?;

            let plaintext = response
                .plaintext()
                .ok_or_else(|| Error::KeySourceUnavailable("KMS decrypt returned no plaintext".into()))?;

            let bytes = plaintext.as_ref();
            if bytes.len() != 32 {
                return Err(Error::InvalidConfig(format!(
                    "KMS decrypted DEK has wrong length (expected 32 bytes, got {})",
                    bytes.len()
                )));
            }

            let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
            key_bytes.copy_from_slice(bytes);

            tracing::info!("loaded existing DEK from KMS");
            Ok(DataEncryptionKey::from_bytes(*key_bytes))
        } else {
            // Generate new DEK and encrypt with KMS
            let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(key_bytes.as_mut());

            let response = self
                .client
                .encrypt()
                .plaintext(Blob::new(key_bytes.to_vec()))
                .key_id(&self.key_id)
                .send()
                .await
                .map_err(|e| Error::KeySourceUnavailable(format!("KMS encrypt failed: {e}")))?;

            let ciphertext = response
                .ciphertext_blob()
                .ok_or_else(|| Error::KeySourceUnavailable("KMS encrypt returned no ciphertext".into()))?;

            // Save encrypted blob to disk
            if let Some(parent) = self.encrypted_dek_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    Error::KeySourceUnavailable(format!("failed to create directory for DEK blob: {e}"))
                })?;
            }

            tokio::fs::write(&self.encrypted_dek_path, ciphertext.as_ref())
                .await
                .map_err(|e| {
                    Error::KeySourceUnavailable(format!(
                        "failed to write encrypted DEK to {}: {e}",
                        self.encrypted_dek_path.display()
                    ))
                })?;

            tracing::info!("generated and stored new DEK via KMS");
            Ok(DataEncryptionKey::from_bytes(*key_bytes))
        }
    }

    async fn rotate_dek(&self, new_dek: &DataEncryptionKey) -> Result<EncryptedDek> {
        let response = self
            .client
            .encrypt()
            .plaintext(Blob::new(new_dek.as_bytes().to_vec()))
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(|e| Error::KeySourceUnavailable(format!("KMS encrypt failed during rotation: {e}")))?;

        let ciphertext = response
            .ciphertext_blob()
            .ok_or_else(|| Error::KeySourceUnavailable("KMS encrypt returned no ciphertext during rotation".into()))?;

        let ciphertext_bytes = ciphertext.as_ref().to_vec();

        // Overwrite the encrypted DEK file
        tokio::fs::write(&self.encrypted_dek_path, &ciphertext_bytes)
            .await
            .map_err(|e| {
                Error::KeySourceUnavailable(format!(
                    "failed to write rotated DEK to {}: {e}",
                    self.encrypted_dek_path.display()
                ))
            })?;

        tracing::info!("rotated DEK via KMS");
        Ok(EncryptedDek {
            ciphertext: ciphertext_bytes,
            key_id: self.key_id.clone(),
        })
    }

    fn description(&self) -> &str {
        &self.description
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::keysource::KeySource;

    /// KMS test key alias. Requires valid AWS credentials with
    /// encrypt/decrypt permissions on this key.
    /// Override with ZEROLEASE_KMS_TEST_KEY_ID env var.
    fn test_key_id() -> String {
        std::env::var("ZEROLEASE_KMS_TEST_KEY_ID").unwrap_or_else(|_| "alias/zerolease-test".to_string())
    }

    fn test_region() -> String {
        std::env::var("ZEROLEASE_KMS_TEST_REGION").unwrap_or_else(|_| "us-west-2".to_string())
    }

    #[tokio::test]
    #[ignore] // requires AWS credentials and a KMS key
    async fn create_and_load_dek_round_trip() {
        let dir = TempDir::new().unwrap();
        let dek_path = dir.path().join("test-dek.enc");

        let source = KmsSource::new(test_key_id(), test_region(), &dek_path).await.unwrap();

        // First call: creates a new DEK, encrypts with KMS, saves blob
        let dek1 = source.load_or_create_dek().await.unwrap();
        assert!(dek_path.exists(), "encrypted DEK blob should be written");

        // Second call: loads existing blob, decrypts with KMS
        let dek2 = source.load_or_create_dek().await.unwrap();
        assert_eq!(
            dek1.as_bytes(),
            dek2.as_bytes(),
            "loaded DEK must match the created DEK"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn rotate_dek_produces_new_encrypted_blob() {
        let dir = TempDir::new().unwrap();
        let dek_path = dir.path().join("rotate-dek.enc");

        let source = KmsSource::new(test_key_id(), test_region(), &dek_path).await.unwrap();

        // Create initial DEK
        let original_dek = source.load_or_create_dek().await.unwrap();
        let original_blob = std::fs::read(&dek_path).unwrap();

        // Generate a new DEK and rotate
        let new_dek = DataEncryptionKey::from_bytes([0xBB; 32]);
        let encrypted = source.rotate_dek(&new_dek).await.unwrap();

        // The encrypted blob should have changed
        let rotated_blob = std::fs::read(&dek_path).unwrap();
        assert_ne!(
            original_blob, rotated_blob,
            "rotated DEK blob should differ from original"
        );

        // The returned EncryptedDek should have the right key_id
        assert!(!encrypted.key_id.is_empty(), "EncryptedDek should have a key_id");
        assert!(!encrypted.ciphertext.is_empty(), "EncryptedDek should have ciphertext");

        // Load the rotated DEK — should get the new one, not the original
        let loaded = source.load_or_create_dek().await.unwrap();
        assert_eq!(
            loaded.as_bytes(),
            new_dek.as_bytes(),
            "loaded DEK after rotation should match the new DEK"
        );
        assert_ne!(
            loaded.as_bytes(),
            original_dek.as_bytes(),
            "loaded DEK should not match the original"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn description_contains_key_id() {
        let dir = TempDir::new().unwrap();
        let dek_path = dir.path().join("desc-dek.enc");

        let source = KmsSource::new(test_key_id(), test_region(), &dek_path).await.unwrap();

        let desc = source.description();
        assert!(desc.starts_with("kms:"), "description should start with 'kms:'");
        assert!(
            desc.contains("zerolease-test") || desc.contains("alias/"),
            "description should contain the key identifier: {desc}"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn wrong_ciphertext_fails_decryption() {
        let dir = TempDir::new().unwrap();
        let dek_path = dir.path().join("bad-dek.enc");

        // Write garbage to the DEK blob file
        std::fs::write(&dek_path, b"this is not a valid KMS ciphertext blob").unwrap();

        let source = KmsSource::new(test_key_id(), test_region(), &dek_path).await.unwrap();

        // Should fail to decrypt the garbage
        let result = source.load_or_create_dek().await;
        assert!(result.is_err(), "garbage DEK blob should fail to decrypt");
    }
}
