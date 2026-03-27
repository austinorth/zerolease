//! OS keychain key source for developer laptops.
//!
//! Uses the `keyring` crate to store and retrieve the DEK from the
//! platform's secret store (macOS Keychain, Linux secret-service).
//! On first use, generates a random 32-byte DEK and stores it.
//! On subsequent uses, retrieves the existing DEK.

use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::keysource::{DataEncryptionKey, EncryptedDek, KeySource};

/// A key source backed by the OS keychain.
///
/// Stores the raw 32-byte DEK in the keychain entry identified by
/// `service` and `account`. The keychain provides encryption at rest.
pub struct KeychainSource {
    service: String,
    account: String,
    description: String,
}

impl KeychainSource {
    /// Create a new keychain key source.
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        let service = service.into();
        let account = account.into();
        let description = format!("keychain:{service}/{account}");
        Self {
            service,
            account,
            description,
        }
    }
}

#[async_trait::async_trait]
impl KeySource for KeychainSource {
    async fn load_or_create_dek(&self) -> Result<DataEncryptionKey> {
        let service = self.service.clone();
        let account = self.account.clone();

        tokio::task::spawn_blocking(move || load_or_create_blocking(&service, &account))
            .await
            .map_err(|e| Error::KeySourceUnavailable(format!("keychain task panicked: {e}")))?
    }

    async fn rotate_dek(&self, _new_dek: &DataEncryptionKey) -> Result<EncryptedDek> {
        Err(Error::KeySourceUnavailable(
            "DEK rotation not yet supported for keychain source".into(),
        ))
    }

    fn description(&self) -> &str {
        &self.description
    }
}

/// Blocking implementation of load-or-create, called inside `spawn_blocking`.
fn load_or_create_blocking(service: &str, account: &str) -> Result<DataEncryptionKey> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| Error::KeySourceUnavailable(format!("keychain entry error: {e}")))?;

    match entry.get_secret() {
        Ok(mut bytes) => {
            if bytes.len() != 32 {
                bytes.zeroize();
                return Err(Error::InvalidConfig(format!(
                    "keychain entry has wrong key length (expected 32 bytes, got {})",
                    bytes.len()
                )));
            }
            let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
            key_bytes.copy_from_slice(&bytes);
            bytes.zeroize();
            Ok(DataEncryptionKey::from_bytes(*key_bytes))
        }
        Err(keyring::Error::NoEntry) => {
            // Generate a new random DEK
            let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(key_bytes.as_mut());

            entry
                .set_secret(key_bytes.as_ref())
                .map_err(|e| Error::KeySourceUnavailable(format!("failed to store DEK in keychain: {e}")))?;

            tracing::info!("generated and stored new DEK in keychain");
            Ok(DataEncryptionKey::from_bytes(*key_bytes))
        }
        Err(e) => Err(Error::KeySourceUnavailable(format!("keychain error: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require a real OS keychain (macOS Keychain or
    // Linux secret-service). They are #[ignore] by default.
    // Run with: cargo test keysource::keychain -- --ignored

    #[tokio::test]
    #[ignore]
    async fn create_then_load_round_trip() {
        let service = "zerolease-test";
        let account = "test-dek-roundtrip";

        // Clean up any leftover from a previous failed test run
        if let Ok(entry) = keyring::Entry::new(service, account) {
            let _ = entry.delete_credential();
        }

        let source = KeychainSource::new(service, account);

        // First call: creates a new DEK
        let dek1 = source
            .load_or_create_dek()
            .await
            .expect("first call should create a new DEK");

        // Second call: loads the existing DEK
        let dek2 = source
            .load_or_create_dek()
            .await
            .expect("second call should load the existing DEK");

        assert_eq!(dek1.as_bytes(), dek2.as_bytes());

        // Clean up
        keyring::Entry::new(service, account)
            .expect("failed to create keyring entry for cleanup")
            .delete_credential()
            .expect("failed to delete test credential from keychain");
    }

    #[test]
    fn description_format() {
        let source = KeychainSource::new("my-service", "my-account");
        assert_eq!(source.description(), "keychain:my-service/my-account");
    }
}
