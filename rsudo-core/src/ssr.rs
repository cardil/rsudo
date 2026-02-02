//! SSR (Sudo Sign Request) token format
//!
//! Provides encoding and decoding of sign request tokens for offline signing.
//! Uses PEM-style format with base64-encoded JSON payload.

use crate::types::{SignRequest, SignedApproval};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SSR (Sudo Sign Request) token errors
#[derive(Debug, Error)]
pub enum SsrError {
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Base64 encoding/decoding error
    #[error("Base64 error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// Invalid token format
    #[error("Invalid token format: {0}")]
    InvalidFormat(String),
}

/// A sign request token for offline signing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignRequestToken {
    /// The sign request
    pub request: SignRequest,

    /// Optional approval (present in signed tokens)
    pub approval: Option<SignedApproval>,
}

impl SignRequestToken {
    /// Create a new unsigned token
    pub fn new(request: SignRequest) -> Self {
        Self {
            request,
            approval: None,
        }
    }

    /// Create a signed token
    pub fn with_approval(request: SignRequest, approval: SignedApproval) -> Self {
        Self {
            request,
            approval: Some(approval),
        }
    }

    /// Check if the token is signed
    pub fn is_signed(&self) -> bool {
        self.approval.is_some()
    }

    /// Encode the token to PEM-style format
    ///
    /// Returns a PEM-style block with base64-encoded JSON payload:
    /// ```text
    /// -----BEGIN RSUDO SIGN REQUEST-----
    /// <base64-encoded JSON>
    /// -----END RSUDO SIGN REQUEST-----
    /// ```
    pub fn to_pem(&self) -> Result<String, SsrError> {
        let json = serde_json::to_string(self)?;
        let encoded = STANDARD.encode(json.as_bytes());

        let header = if self.is_signed() {
            "-----BEGIN RSUDO INVOCATION-----"
        } else {
            "-----BEGIN RSUDO SIGN REQUEST-----"
        };

        let footer = if self.is_signed() {
            "-----END RSUDO INVOCATION-----"
        } else {
            "-----END RSUDO SIGN REQUEST-----"
        };

        // Format base64 in 64-character lines (standard PEM format)
        let mut output = String::new();
        output.push_str(header);
        output.push('\n');

        for chunk in encoded.as_bytes().chunks(64) {
            output.push_str(std::str::from_utf8(chunk).unwrap());
            output.push('\n');
        }

        output.push_str(footer);
        output.push('\n');

        Ok(output)
    }

    /// Decode a token from PEM-style format
    pub fn from_pem(pem: &str) -> Result<Self, SsrError> {
        // Extract base64 content between BEGIN and END markers
        let lines: Vec<&str> = pem.lines().collect();

        // Find BEGIN and END markers and validate they match
        let begin_idx = lines
            .iter()
            .position(|line| {
                line.contains("BEGIN RSUDO SIGN REQUEST") || line.contains("BEGIN RSUDO INVOCATION")
            })
            .ok_or_else(|| SsrError::InvalidFormat("Missing BEGIN marker".to_string()))?;

        let is_invocation = lines[begin_idx].contains("INVOCATION");

        let end_idx = lines
            .iter()
            .position(|line| {
                line.contains("END RSUDO SIGN REQUEST") || line.contains("END RSUDO INVOCATION")
            })
            .ok_or_else(|| SsrError::InvalidFormat("Missing END marker".to_string()))?;

        // Validate that BEGIN and END markers match
        let end_is_invocation = lines[end_idx].contains("INVOCATION");
        if is_invocation != end_is_invocation {
            return Err(SsrError::InvalidFormat(
                "Mismatched BEGIN/END markers".to_string(),
            ));
        }

        if end_idx <= begin_idx {
            return Err(SsrError::InvalidFormat("Invalid PEM structure".to_string()));
        }

        // Concatenate base64 lines
        let base64_content: String = lines[begin_idx + 1..end_idx]
            .iter()
            .map(|line| line.trim())
            .collect();

        // Decode base64
        let json_bytes = STANDARD.decode(base64_content.as_bytes())?;
        let json = String::from_utf8(json_bytes)
            .map_err(|e| SsrError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;

        // Parse JSON
        let token = serde_json::from_str(&json)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_request() -> SignRequest {
        SignRequest {
            command: "reboot".to_string(),
            args: vec![],
            hostname: "test-host".to_string(),
            username: "test-user".to_string(),
            cwd: "/home/user".to_string(),
            env: HashMap::new(),
            timestamp: "2025-12-13T00:20:00Z".to_string(),
            expires_at: "2025-12-13T00:25:00Z".to_string(),
            nonce: "test-nonce-123".to_string(),
            client_id: "client-001".to_string(),
        }
    }

    fn create_test_approval() -> SignedApproval {
        SignedApproval {
            request_hash: "hash123".to_string(),
            signature: "sig456".to_string(),
            approver_id: "approver-001".to_string(),
            timestamp: "2025-12-13T00:21:00Z".to_string(),
        }
    }

    #[test]
    fn test_unsigned_token_pem() {
        let request = create_test_request();
        let token = SignRequestToken::new(request.clone());

        assert!(!token.is_signed());

        let pem = token.to_pem().unwrap();
        let decoded = SignRequestToken::from_pem(&pem).unwrap();

        assert_eq!(token, decoded);
        assert_eq!(decoded.request.command, "reboot");
    }

    #[test]
    fn test_signed_token_pem() {
        let request = create_test_request();
        let approval = create_test_approval();
        let token = SignRequestToken::with_approval(request, approval);

        assert!(token.is_signed());

        let pem = token.to_pem().unwrap();
        let decoded = SignRequestToken::from_pem(&pem).unwrap();

        assert_eq!(token, decoded);
        assert!(decoded.is_signed());
    }

    #[test]
    fn test_pem_format_unsigned() {
        let request = create_test_request();
        let token = SignRequestToken::new(request);

        let pem = token.to_pem().unwrap();

        assert!(pem.contains("-----BEGIN RSUDO SIGN REQUEST-----"));
        assert!(pem.contains("-----END RSUDO SIGN REQUEST-----"));
    }

    #[test]
    fn test_pem_format_signed() {
        let request = create_test_request();
        let approval = create_test_approval();
        let token = SignRequestToken::with_approval(request, approval);

        let pem = token.to_pem().unwrap();

        assert!(pem.contains("-----BEGIN RSUDO INVOCATION-----"));
        assert!(pem.contains("-----END RSUDO INVOCATION-----"));
    }

    #[test]
    fn test_pem_roundtrip() {
        let request = create_test_request();
        let token = SignRequestToken::new(request);

        let pem = token.to_pem().unwrap();
        let parsed = SignRequestToken::from_pem(&pem).unwrap();

        assert_eq!(token, parsed);
    }

    #[test]
    fn test_pem_with_args() {
        let mut request = create_test_request();
        request.command = "apt".to_string();
        request.args = vec!["install".to_string(), "nginx".to_string()];

        let token = SignRequestToken::new(request.clone());
        let pem = token.to_pem().unwrap();
        let parsed = SignRequestToken::from_pem(&pem).unwrap();

        assert_eq!(parsed.request.args, vec!["install", "nginx"]);
    }

    #[test]
    fn test_pem_preserves_arg_spaces() {
        let mut request = create_test_request();
        request.command = "echo".to_string();
        request.args = vec!["hello world".to_string(), "foo".to_string()];

        let token = SignRequestToken::new(request.clone());
        let pem = token.to_pem().unwrap();
        let parsed = SignRequestToken::from_pem(&pem).unwrap();

        // Should preserve the space in "hello world" as a single argument
        assert_eq!(parsed.request.args, vec!["hello world", "foo"]);
    }

    #[test]
    fn test_invalid_pem_no_markers() {
        let result = SignRequestToken::from_pem("not a valid PEM");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pem_bad_base64() {
        let pem =
            "-----BEGIN RSUDO SIGN REQUEST-----\n!!invalid!!\n-----END RSUDO SIGN REQUEST-----\n";
        let result = SignRequestToken::from_pem(pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pem_bad_json() {
        let invalid_json = STANDARD.encode(b"not json");
        let pem = format!(
            "-----BEGIN RSUDO SIGN REQUEST-----\n{}\n-----END RSUDO SIGN REQUEST-----\n",
            invalid_json
        );
        let result = SignRequestToken::from_pem(&pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pem_missing_fields() {
        // JSON with missing required fields
        let incomplete_json = r#"{"request":{"command":"test"}}"#;
        let encoded = STANDARD.encode(incomplete_json.as_bytes());
        let pem = format!(
            "-----BEGIN RSUDO SIGN REQUEST-----\n{}\n-----END RSUDO SIGN REQUEST-----\n",
            encoded
        );
        let result = SignRequestToken::from_pem(&pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pem_wrong_structure() {
        // Valid JSON but wrong structure
        let wrong_json = r#"{"foo":"bar"}"#;
        let encoded = STANDARD.encode(wrong_json.as_bytes());
        let pem = format!(
            "-----BEGIN RSUDO SIGN REQUEST-----\n{}\n-----END RSUDO SIGN REQUEST-----\n",
            encoded
        );
        let result = SignRequestToken::from_pem(&pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pem_mismatched_markers() {
        // BEGIN and END markers don't match
        let request = create_test_request();
        let token = SignRequestToken::new(request);
        let encoded = STANDARD.encode(serde_json::to_string(&token).unwrap().as_bytes());
        let pem = format!(
            "-----BEGIN RSUDO SIGN REQUEST-----\n{}\n-----END RSUDO INVOCATION-----\n",
            encoded
        );
        let result = SignRequestToken::from_pem(&pem);
        assert!(result.is_err());
    }
}
