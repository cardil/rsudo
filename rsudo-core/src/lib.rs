//! Core library for rsudo
//!
//! Provides cryptographic primitives, types, and SSR (Sudo Sign Request) token handling.

#![warn(missing_docs)]

/// Configuration loading and merging
pub mod config;

/// Cryptographic operations (Ed25519)
pub mod crypto;

/// SSR (Sudo Sign Request) token format
pub mod ssr;

/// Core types and data structures
pub mod types;

// Re-export commonly used types
pub use config::{ConfigError, ConfigLoader};
pub use crypto::{CryptoError, Keypair, PublicKey};
pub use ssr::{SignRequestToken, SsrError};
pub use types::{
    AuditConfig, ClientConfig, Config, PolicyConfig, RequestConfig, ServerConfig, SignRequest,
    SignedApproval,
};
