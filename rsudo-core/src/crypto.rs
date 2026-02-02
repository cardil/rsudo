//! Cryptographic operations for rsudo
//!
//! Provides Ed25519 key generation, signing, and verification.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;

/// Cryptographic errors
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Base64 decoding error
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// Signature error
    #[error("Signature error: {0}")]
    SignatureError(String),
}

/// Ed25519 keypair for signing and verification
#[derive(Debug)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a keypair from a private key (32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let signing_key = SigningKey::from_bytes(&key_bytes);
        Ok(Self { signing_key })
    }

    /// Create a keypair from a base64-encoded private key
    pub fn from_base64(encoded: &str) -> Result<Self, CryptoError> {
        let bytes = STANDARD.decode(encoded)?;
        Self::from_bytes(&bytes)
    }

    /// Get the private key as bytes
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the private key as base64
    pub fn private_key_base64(&self) -> String {
        STANDARD.encode(self.private_key_bytes())
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign data and return the signature
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }

    /// Sign data and return base64-encoded signature
    pub fn sign_base64(&self, data: &[u8]) -> String {
        STANDARD.encode(self.sign(data))
    }
}

/// Ed25519 public key for signature verification
#[derive(Debug, Clone)]
pub struct PublicKey {
    verifying_key: VerifyingKey,
}

impl PublicKey {
    /// Create a public key from bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

        Ok(Self { verifying_key })
    }

    /// Create a public key from base64-encoded bytes
    pub fn from_base64(encoded: &str) -> Result<Self, CryptoError> {
        let bytes = STANDARD.decode(encoded)?;
        Self::from_bytes(&bytes)
    }

    /// Get the public key as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get the public key as base64
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_bytes())
    }

    /// Verify a signature over data
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        if signature.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);

        let signature = Signature::from_bytes(&sig_bytes);

        self.verifying_key
            .verify(data, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Verify a base64-encoded signature over data
    pub fn verify_base64(&self, data: &[u8], signature_b64: &str) -> Result<(), CryptoError> {
        let signature = STANDARD.decode(signature_b64)?;
        self.verify(data, &signature)
    }
}

/// Helper function to compute SHA-256 hash of data
pub fn hash_data(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key();

        // Verify keys are 32 bytes
        assert_eq!(keypair.private_key_bytes().len(), 32);
        assert_eq!(public_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key();

        let message = b"Hello, rsudo!";
        let signature = keypair.sign(message);

        // Verification should succeed
        assert!(public_key.verify(message, &signature).is_ok());

        // Verification with wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(public_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_base64_encoding() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key();

        // Test private key encoding/decoding
        let private_b64 = keypair.private_key_base64();
        let restored_keypair = Keypair::from_base64(&private_b64).unwrap();
        assert_eq!(
            keypair.private_key_bytes(),
            restored_keypair.private_key_bytes()
        );

        // Test public key encoding/decoding
        let public_b64 = public_key.to_base64();
        let restored_public = PublicKey::from_base64(&public_b64).unwrap();
        assert_eq!(public_key.to_bytes(), restored_public.to_bytes());
    }

    #[test]
    fn test_sign_and_verify_base64() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key();

        let message = b"Test message";
        let signature_b64 = keypair.sign_base64(message);

        // Verification should succeed
        assert!(public_key.verify_base64(message, &signature_b64).is_ok());

        // Verification with wrong message should fail
        let wrong_message = b"Wrong";
        assert!(public_key
            .verify_base64(wrong_message, &signature_b64)
            .is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        // Too short
        let result = Keypair::from_bytes(&[0u8; 16]);
        assert!(result.is_err());

        // Too long
        let result = Keypair::from_bytes(&[0u8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_length() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key();

        let message = b"Test";
        let invalid_sig = vec![0u8; 32]; // Wrong length

        assert!(public_key.verify(message, &invalid_sig).is_err());
    }
}
