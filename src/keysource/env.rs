//! Environment variable key source for CI/CD and testing.
//!
//! Reads a hex-encoded 32-byte DEK from an environment variable.
//! This is the least secure key source — the key is visible in the
//! process environment — but is useful for CI pipelines and tests
//! where an OS keychain is not available.

use crate::error::{Error, Result};
use crate::keysource::{DataEncryptionKey, EncryptedDek, KeySource};

/// A key source that reads the DEK from an environment variable.
///
/// The variable must contain exactly 64 hex characters (32 bytes).
/// This source is read-only: it cannot create or rotate keys.
pub struct EnvVarSource {
    var_name: String,
    description: String,
}

impl EnvVarSource {
    /// Create a new env var key source. Does not read the environment
    /// at construction time — the variable is read on `load_or_create_dek`.
    pub fn new(var_name: impl Into<String>) -> Self {
        let var_name = var_name.into();
        let description = format!("env:{var_name}");
        Self { var_name, description }
    }
}

#[async_trait::async_trait]
impl KeySource for EnvVarSource {
    async fn load_or_create_dek(&self) -> Result<DataEncryptionKey> {
        let mut hex = std::env::var(&self.var_name)
            .map_err(|_| Error::KeySourceUnavailable(format!("env var {} not set", self.var_name)))?;

        let bytes = decode_hex_32(&hex, &self.var_name)?;
        zeroize::Zeroize::zeroize(&mut hex);
        Ok(DataEncryptionKey::from_bytes(bytes))
    }

    async fn rotate_dek(&self, _new_dek: &DataEncryptionKey) -> Result<EncryptedDek> {
        Err(Error::KeySourceUnavailable(
            "cannot rotate an env-var key source; set a new value and restart".into(),
        ))
    }

    fn description(&self) -> &str {
        &self.description
    }
}

/// Decode a 64-character hex string into 32 bytes.
fn decode_hex_32(hex: &str, var_name: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        return Err(Error::InvalidConfig(format!(
            "env var {} must be 64 hex characters (32 bytes), got {}",
            var_name,
            hex.len()
        )));
    }

    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::InvalidConfig(format!("env var {} is not valid hex", var_name)))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // IMPORTANT: These tests use std::env::set_var which is unsafe in
    // Rust edition 2024 (not thread-safe). Each test uses a unique var
    // name. Run with: cargo test keysource::env -- --test-threads=1

    fn set_env(name: &str, value: &str) {
        // SAFETY: tests run single-threaded via --test-threads=1
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(name, value)
        };
    }

    fn remove_env(name: &str) {
        // SAFETY: tests run single-threaded via --test-threads=1
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(name)
        };
    }

    #[tokio::test]
    async fn valid_hex_key_loads() {
        let var = "ZEROLEASE_TEST_ENV_1";
        // 32 bytes of 0xAA
        set_env(var, &"aa".repeat(32));

        let source = EnvVarSource::new(var);
        let dek = source
            .load_or_create_dek()
            .await
            .expect("valid hex key should load successfully");
        assert_eq!(dek.as_bytes(), &[0xAA; 32]);

        remove_env(var);
    }

    #[tokio::test]
    async fn missing_env_var_errors() {
        let source = EnvVarSource::new("ZEROLEASE_TEST_ENV_MISSING");
        let result = source.load_or_create_dek().await;
        assert!(result.is_err());
        let err = result.expect_err("missing env var should produce an error").to_string();
        assert!(err.contains("not set"), "error was: {err}");
    }

    #[tokio::test]
    async fn bad_hex_errors() {
        let var = "ZEROLEASE_TEST_ENV_3";
        set_env(var, &"zz".repeat(32)); // 64 chars, but not valid hex

        let source = EnvVarSource::new(var);
        let result = source.load_or_create_dek().await;
        assert!(result.is_err());
        let err = result.expect_err("invalid hex should produce an error").to_string();
        assert!(err.contains("not valid hex"), "error was: {err}");

        remove_env(var);
    }

    #[tokio::test]
    async fn wrong_length_errors() {
        let var = "ZEROLEASE_TEST_ENV_4";
        set_env(var, "aabb"); // only 4 hex chars

        let source = EnvVarSource::new(var);
        let result = source.load_or_create_dek().await;
        assert!(result.is_err());
        let err = result
            .expect_err("wrong-length hex should produce an error")
            .to_string();
        assert!(err.contains("64 hex characters"), "error was: {err}");

        remove_env(var);
    }

    #[tokio::test]
    async fn rotate_returns_error() {
        let source = EnvVarSource::new("ZEROLEASE_TEST_ENV_5");
        let dek = DataEncryptionKey::from_bytes([0u8; 32]);
        let result = source.rotate_dek(&dek).await;
        assert!(result.is_err());
    }

    #[test]
    fn description_contains_var_name() {
        let source = EnvVarSource::new("MY_SECRET_KEY");
        assert_eq!(source.description(), "env:MY_SECRET_KEY");
    }
}
