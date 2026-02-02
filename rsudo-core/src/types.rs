//! Core types for rsudo
//!
//! Defines the data structures used throughout the rsudo system.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A request to execute a privileged command
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignRequest {
    /// The command to execute
    pub command: String,

    /// Command arguments
    pub args: Vec<String>,

    /// Hostname where command will execute
    pub hostname: String,

    /// Username requesting execution
    pub username: String,

    /// Working directory for command execution
    pub cwd: String,

    /// Environment variables
    pub env: HashMap<String, String>,

    /// Request timestamp (ISO 8601 UTC)
    pub timestamp: String,

    /// Expiration timestamp (ISO 8601 UTC)
    pub expires_at: String,

    /// Unique nonce for replay prevention and request tracking (UUID v4)
    pub nonce: String,

    /// Client identifier (public key fingerprint)
    pub client_id: String,
}

/// A signed approval for a command execution request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedApproval {
    /// Hash of the original request
    pub request_hash: String,

    /// Approver's signature over the request hash
    pub signature: String,

    /// Approver identifier (public key fingerprint)
    pub approver_id: String,

    /// Approval timestamp (ISO 8601 UTC)
    pub timestamp: String,
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientConfig {
    /// Path to client private key file
    pub key_file: Option<String>,

    /// Default request timeout in seconds
    pub default_timeout: Option<u64>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            key_file: None,
            default_timeout: Some(300),
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ServerConfig {
    /// Server URL
    pub url: Option<String>,

    /// Path to CA certificate file
    pub ca_cert: Option<String>,
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyConfig {
    /// List of allowed commands (glob patterns)
    pub allowed_commands: Option<Vec<String>>,

    /// Whether to require TTY for execution
    pub require_tty: Option<bool>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allowed_commands: Some(vec!["*".to_string()]),
            require_tty: Some(false),
        }
    }
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditConfig {
    /// Path to audit log file
    pub log_file: Option<String>,

    /// Whether to log to syslog
    pub syslog: Option<bool>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_file: Some("/var/log/rsudo/audit.log".to_string()),
            syslog: Some(true),
        }
    }
}

/// Request configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestConfig {
    /// Default timeout for requests in seconds
    pub default_timeout: Option<u64>,
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            default_timeout: Some(300),
        }
    }
}

/// Complete rsudo configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Config {
    /// Client configuration
    #[serde(default)]
    pub client: ClientConfig,

    /// Server configuration
    #[serde(default)]
    pub server: ServerConfig,

    /// Policy configuration
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Audit configuration
    #[serde(default)]
    pub audit: AuditConfig,

    /// Request configuration
    #[serde(default)]
    pub request: RequestConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_request_serialization() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());

        let request = SignRequest {
            command: "reboot".to_string(),
            args: vec![],
            hostname: "server-01".to_string(),
            username: "agent".to_string(),
            cwd: "/home/user".to_string(),
            env,
            timestamp: "2025-12-13T00:20:00Z".to_string(),
            expires_at: "2025-12-13T00:25:00Z".to_string(),
            nonce: "abc123".to_string(),
            client_id: "client-001".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SignRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request, deserialized);
    }

    #[test]
    fn test_signed_approval_serialization() {
        let approval = SignedApproval {
            request_hash: "hash123".to_string(),
            signature: "sig456".to_string(),
            approver_id: "approver-001".to_string(),
            timestamp: "2025-12-13T00:21:00Z".to_string(),
        };

        let json = serde_json::to_string(&approval).unwrap();
        let deserialized: SignedApproval = serde_json::from_str(&json).unwrap();

        assert_eq!(approval, deserialized);
    }

    #[test]
    fn test_config_defaults() {
        let config = Config::default();

        assert_eq!(config.client.default_timeout, Some(300));
        assert_eq!(config.policy.allowed_commands, Some(vec!["*".to_string()]));
        assert_eq!(config.policy.require_tty, Some(false));
        assert_eq!(config.audit.syslog, Some(true));
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();

        let toml_str = toml::to_string(&config).unwrap();
        let deserialized: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(config, deserialized);
    }
}
