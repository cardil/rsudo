//! Login and enrollment flow for rsudo
//!
//! Supports both OAuth Device Code Flow (interactive) and enrollment tokens (batch).

use crate::session::{save_session, Session};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Login errors
#[derive(Debug, Error)]
pub enum LoginError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// Session save failed
    #[error("Failed to save session: {0}")]
    SessionSave(#[from] crate::session::SessionError),

    /// OAuth device flow failed
    #[error("OAuth device flow failed: {0}")]
    OAuthFailed(String),

    /// Enrollment token invalid or expired
    #[error("Enrollment token invalid or expired: {0}")]
    TokenInvalid(String),

    /// Enrollment validation failed
    #[error("Enrollment validation failed: {0}")]
    ValidationFailed(String),

    /// Timeout waiting for approval
    #[error("Timeout waiting for device authorization")]
    Timeout,
}

/// OAuth device code response
#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

/// OAuth token response
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    refresh_expires_in: u64,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    machine_group: String,
    #[serde(default)]
    user_identity: String,
}

/// Enrollment token validation rules
#[derive(Debug, Deserialize)]
struct TokenRules {
    hostname_pattern: Option<String>,
    #[allow(dead_code)]
    ip_ranges: Option<Vec<String>>,
    required_env: Option<std::collections::HashMap<String, String>>,
}

/// Enrollment request
#[derive(Debug, Serialize)]
struct EnrollmentRequest {
    token: String,
    hostname: String,
    machine_id: String,
}

/// Perform interactive OAuth device code flow login
pub async fn login_interactive(server_url: &str) -> Result<Session, LoginError> {
    let client = Client::new();

    // Step 1: Request device code
    println!("🔐 Starting OAuth device code flow...");
    let device_response: DeviceCodeResponse = client
        .post(format!("{}/api/oauth/device", server_url))
        .send()
        .await?
        .json()
        .await?;

    // Step 2: Display code to user and open browser
    println!("\n🔑 Your verification code: {}", device_response.user_code);
    println!(
        "📱 Opening browser to: {}",
        device_response.verification_uri
    );

    // Try to open browser automatically
    if let Err(e) = webbrowser::open(&device_response.verification_uri) {
        println!("⚠️  Could not open browser automatically: {}", e);
        println!("   Please visit the URL manually.");
    }

    println!("\n⏳ Waiting for authorization...");

    // Step 3: Poll for token
    let token_response = poll_for_token(
        &client,
        server_url,
        &device_response.device_code,
        device_response.interval,
        device_response.expires_in,
    )
    .await?;

    // Step 4: Create and save session
    let session = create_session_from_token(token_response)?;
    save_session(&session)?;

    println!(
        "✅ Enrolled as: {} (group: {})",
        session.user_identity, session.machine_group
    );

    Ok(session)
}

/// Perform batch enrollment with token
pub async fn login_with_token(server_url: &str, token: &str) -> Result<Session, LoginError> {
    let client = Client::new();

    // Step 1: Fetch token validation rules
    let rules: TokenRules = client
        .get(format!("{}/api/tokens/{}/rules", server_url, token))
        .send()
        .await?
        .json()
        .await
        .map_err(|e| LoginError::TokenInvalid(e.to_string()))?;

    // Step 2: Validate local environment against rules
    validate_environment(&rules)?;

    // Step 3: Get hostname and machine ID
    let hostname = hostname::get()
        .map_err(|e| LoginError::ValidationFailed(format!("Failed to get hostname: {}", e)))?
        .to_string_lossy()
        .to_string();

    let machine_id = crate::session::load_or_generate_machine_id()
        .map_err(|e| LoginError::ValidationFailed(format!("Failed to get machine ID: {}", e)))?;

    // Step 4: Enroll with server
    let enrollment_req = EnrollmentRequest {
        token: token.to_string(),
        hostname,
        machine_id,
    };

    let token_response: TokenResponse = client
        .post(format!("{}/api/enroll", server_url))
        .json(&enrollment_req)
        .send()
        .await?
        .json()
        .await
        .map_err(|e| LoginError::TokenInvalid(e.to_string()))?;

    // Step 5: Create and save session
    let session = create_session_from_token(token_response)?;
    save_session(&session)?;

    println!(
        "✅ Enrolled as: {} (group: {})",
        session.user_identity, session.machine_group
    );

    Ok(session)
}

/// Poll for OAuth token
async fn poll_for_token(
    client: &Client,
    server_url: &str,
    device_code: &str,
    interval: u64,
    expires_in: u64,
) -> Result<TokenResponse, LoginError> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(expires_in);

    loop {
        if start.elapsed() > timeout {
            return Err(LoginError::Timeout);
        }

        tokio::time::sleep(Duration::from_secs(interval)).await;

        #[derive(Serialize)]
        struct TokenRequest {
            device_code: String,
        }

        let response = client
            .post(format!("{}/api/oauth/token", server_url))
            .json(&TokenRequest {
                device_code: device_code.to_string(),
            })
            .send()
            .await?;

        if response.status().is_success() {
            let token_response: TokenResponse = response.json().await?;
            return Ok(token_response);
        } else if response.status() == 400 {
            // Still pending, continue polling
            continue;
        } else {
            let error_text = response.text().await.unwrap_or_default();
            return Err(LoginError::OAuthFailed(error_text));
        }
    }
}

/// Validate local environment against token rules
fn validate_environment(rules: &TokenRules) -> Result<(), LoginError> {
    // Validate hostname pattern
    if let Some(pattern) = &rules.hostname_pattern {
        let hostname = hostname::get()
            .map_err(|e| LoginError::ValidationFailed(format!("Failed to get hostname: {}", e)))?
            .to_string_lossy()
            .to_string();

        if !glob_match(pattern, &hostname) {
            return Err(LoginError::ValidationFailed(format!(
                "Hostname '{}' does not match pattern '{}'",
                hostname, pattern
            )));
        }
    }

    // Validate required environment variables
    if let Some(required_env) = &rules.required_env {
        for (key, expected_value) in required_env {
            let actual_value = std::env::var(key).map_err(|_| {
                LoginError::ValidationFailed(format!(
                    "Required environment variable '{}' not set",
                    key
                ))
            })?;

            if &actual_value != expected_value {
                return Err(LoginError::ValidationFailed(format!(
                    "Environment variable '{}' has value '{}', expected '{}'",
                    key, actual_value, expected_value
                )));
            }
        }
    }

    // Note: IP range validation would require getting local IP and checking CIDR ranges
    // Skipping for MVP - server can validate this during enrollment

    Ok(())
}

/// Simple glob pattern matching (supports * wildcard)
fn glob_match(pattern: &str, text: &str) -> bool {
    // Simple implementation - just check if pattern contains * and do basic matching
    if pattern == "*" {
        return true;
    }

    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];
            // Ensure text is long enough to contain both prefix and suffix without overlap
            if text.len() < prefix.len() + suffix.len() {
                return false;
            }
            return text.starts_with(prefix) && text.ends_with(suffix);
        }
    }

    pattern == text
}

/// Create session from token response
fn create_session_from_token(token_response: TokenResponse) -> Result<Session, LoginError> {
    let now = chrono::Utc::now();
    let access_expires = now + chrono::Duration::seconds(token_response.expires_in as i64);
    let refresh_expires = now + chrono::Duration::seconds(token_response.refresh_expires_in as i64);

    Ok(Session {
        access_token: token_response.access_token,
        refresh_token: token_response.refresh_token,
        access_token_expires_at: access_expires.to_rfc3339(),
        refresh_token_expires_at: refresh_expires.to_rfc3339(),
        client_id: token_response.client_id,
        machine_group: token_response.machine_group,
        user_identity: token_response.user_identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("prod-*", "prod-server-01"));
        assert!(glob_match("*-prod", "server-prod"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("prod-*", "dev-server"));
        assert!(!glob_match("exact", "different"));

        // Test for overlapping prefix/suffix bug fix
        assert!(!glob_match("prod-*-east", "prod-east")); // Should not match - overlapping
        assert!(glob_match("prod-*-east", "prod-server-east")); // Should match
        assert!(glob_match("a*z", "az")); // Minimum length match (wildcard matches empty)
        assert!(glob_match("a*z", "abz")); // Should match with one char in middle
        assert!(glob_match("ab*yz", "abyz")); // Should match - wildcard matches empty
    }

    #[test]
    fn test_create_session_from_token() {
        let token_response = TokenResponse {
            access_token: "access123".to_string(),
            refresh_token: "refresh456".to_string(),
            expires_in: 3600,
            refresh_expires_in: 2592000,
            client_id: "client-001".to_string(),
            machine_group: "dev-boxes".to_string(),
            user_identity: "user@example.com".to_string(),
        };

        let session = create_session_from_token(token_response).unwrap();
        assert_eq!(session.access_token, "access123");
        assert_eq!(session.refresh_token, "refresh456");
        assert_eq!(session.client_id, "client-001");
        assert_eq!(session.machine_group, "dev-boxes");
        assert_eq!(session.user_identity, "user@example.com");
    }
}
