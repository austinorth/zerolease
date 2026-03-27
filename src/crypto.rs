//! AEAD encryption and decryption for secrets at rest.
//!
//! This module owns all symmetric cryptography. The vault calls into
//! `Cipher` for encrypt/decrypt and never touches `aes_gcm` or
//! `chacha20poly1305` directly.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keysource::DataEncryptionKey;
use crate::store::CipherAlgorithm;

/// Output of an AEAD encryption operation.
///
/// Maps 1:1 to the ciphertext/nonce/algorithm fields on `StoredSecret`.
///
/// Not `Clone` — this is a transient in-memory crypto output, distinct from
/// `StoredSecret` (which is `Clone` for database round-trips). `Sealed` lives
/// only between encrypt/decrypt calls.
///
/// Not `Zeroize` — ciphertext is not secret (the key is).
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: CipherAlgorithm,
}

/// AEAD cipher dispatcher.
///
/// Holds a default algorithm for encryption. Decryption reads the algorithm
/// from the `Sealed` value, enabling transparent algorithm migration.
pub struct Cipher {
    default_algorithm: CipherAlgorithm,
}

impl Cipher {
    /// Create a new cipher with the given default encryption algorithm.
    pub fn new(default_algorithm: CipherAlgorithm) -> Self {
        Self { default_algorithm }
    }

    /// Encrypt plaintext using the default algorithm.
    /// Generates a fresh random nonce via `OsRng`.
    pub fn encrypt(&self, plaintext: &[u8], key: &DataEncryptionKey) -> Result<Sealed> {
        let key_bytes = key.as_bytes();
        let (ciphertext, nonce) = match self.default_algorithm {
            CipherAlgorithm::Aes256Gcm => encrypt_aes_gcm(plaintext, key_bytes)?,
            CipherAlgorithm::XChaCha20Poly1305 => encrypt_xchacha(plaintext, key_bytes)?,
        };
        Ok(Sealed {
            ciphertext,
            nonce,
            algorithm: self.default_algorithm,
        })
    }

    /// Decrypt a `Sealed` value. Dispatches on `sealed.algorithm`,
    /// NOT on `self.default_algorithm`.
    pub fn decrypt(&self, sealed: &Sealed, key: &DataEncryptionKey) -> Result<Zeroizing<Vec<u8>>> {
        let key_bytes = key.as_bytes();
        match sealed.algorithm {
            CipherAlgorithm::Aes256Gcm => decrypt_aes_gcm(&sealed.ciphertext, &sealed.nonce, key_bytes),
            CipherAlgorithm::XChaCha20Poly1305 => decrypt_xchacha(&sealed.ciphertext, &sealed.nonce, key_bytes),
        }
    }
}

// -- AES-256-GCM helpers --

fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::EncryptionFailed)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| Error::EncryptionFailed)?;
    Ok((ciphertext, nonce.to_vec()))
}

fn decrypt_aes_gcm(ciphertext: &[u8], nonce: &[u8], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != 12 {
        return Err(Error::DecryptionFailed);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::DecryptionFailed)?;
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| Error::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

// -- XChaCha20-Poly1305 helpers --

fn encrypt_xchacha(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::EncryptionFailed)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| Error::EncryptionFailed)?;
    Ok((ciphertext, nonce.to_vec()))
}

fn decrypt_xchacha(ciphertext: &[u8], nonce: &[u8], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != 24 {
        return Err(Error::DecryptionFailed);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::DecryptionFailed)?;
    let nonce = chacha20poly1305::XNonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| Error::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a deterministic test key. NOT for production use.
    fn test_key(seed: u8) -> DataEncryptionKey {
        DataEncryptionKey::from_bytes([seed; 32])
    }

    // -- Round-trip tests --

    #[test]
    fn round_trip_aes_gcm() {
        let cipher = Cipher::new(CipherAlgorithm::Aes256Gcm);
        let key = test_key(0xAA);
        let plaintext = b"secret-api-token-12345";

        let sealed = cipher.encrypt(plaintext, &key).unwrap();
        assert_eq!(sealed.algorithm, CipherAlgorithm::Aes256Gcm);
        assert_eq!(sealed.nonce.len(), 12); // AES-GCM nonce is 12 bytes

        let decrypted = cipher.decrypt(&sealed, &key).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn round_trip_xchacha20() {
        let cipher = Cipher::new(CipherAlgorithm::XChaCha20Poly1305);
        let key = test_key(0xBB);
        let plaintext = b"another-secret-value";

        let sealed = cipher.encrypt(plaintext, &key).unwrap();
        assert_eq!(sealed.algorithm, CipherAlgorithm::XChaCha20Poly1305);
        assert_eq!(sealed.nonce.len(), 24); // XChaCha20 nonce is 24 bytes

        let decrypted = cipher.decrypt(&sealed, &key).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn algorithm_stored_correctly_aes() {
        let cipher = Cipher::new(CipherAlgorithm::Aes256Gcm);
        let sealed = cipher.encrypt(b"data", &test_key(0x01)).unwrap();
        assert_eq!(sealed.algorithm, CipherAlgorithm::Aes256Gcm);
    }

    #[test]
    fn algorithm_stored_correctly_xchacha() {
        let cipher = Cipher::new(CipherAlgorithm::XChaCha20Poly1305);
        let sealed = cipher.encrypt(b"data", &test_key(0x02)).unwrap();
        assert_eq!(sealed.algorithm, CipherAlgorithm::XChaCha20Poly1305);
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let cipher = Cipher::new(CipherAlgorithm::Aes256Gcm);
        let key = test_key(0xCC);

        let sealed = cipher.encrypt(b"", &key).unwrap();
        let decrypted = cipher.decrypt(&sealed, &key).unwrap();
        assert!(decrypted.is_empty());
    }

    // -- Failure tests --

    #[test]
    fn wrong_key_fails_decryption() {
        let cipher = Cipher::new(CipherAlgorithm::Aes256Gcm);
        let key_a = test_key(0x01);
        let key_b = test_key(0x02);

        let sealed = cipher.encrypt(b"secret", &key_a).unwrap();
        let result = cipher.decrypt(&sealed, &key_b);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let cipher = Cipher::new(CipherAlgorithm::Aes256Gcm);
        let key = test_key(0xDD);

        let mut sealed = cipher.encrypt(b"secret", &key).unwrap();
        sealed.ciphertext[0] ^= 0xFF;

        let result = cipher.decrypt(&sealed, &key);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let cipher = Cipher::new(CipherAlgorithm::Aes256Gcm);
        let key = test_key(0xEE);

        let mut sealed = cipher.encrypt(b"secret", &key).unwrap();
        sealed.nonce[0] ^= 0xFF;

        let result = cipher.decrypt(&sealed, &key);
        assert!(result.is_err());
    }

    #[test]
    fn cross_algorithm_mismatch_fails() {
        let cipher = Cipher::new(CipherAlgorithm::Aes256Gcm);
        let key = test_key(0xFF);

        let sealed = cipher.encrypt(b"secret", &key).unwrap();
        // Manually construct a Sealed with the wrong algorithm tag.
        // The AES-GCM 12-byte nonce will fail the length check in
        // decrypt_xchacha (which expects 24 bytes), returning an error.
        let wrong_algo = Sealed {
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce,
            algorithm: CipherAlgorithm::XChaCha20Poly1305,
        };

        let result = cipher.decrypt(&wrong_algo, &key);
        assert!(result.is_err());
    }
}
