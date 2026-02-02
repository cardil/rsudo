//! Request flow for rsudo
//!
//! Handles building sign requests and submitting them to the server.

use crate::session::{load_session, Session};
use reqwest::Client;
use rsudo_core::Config;
use rsudo_core::{SignRequest, SignRequestToken};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

/// Request errors
#[derive(Debug, Error)]
pub enum RequestError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// Session error
    #[error("Session error: {0}")]
    Session(#[from] crate::session::SessionError),

    /// SSR token error
    #[error("SSR token error: {0}")]
    Ssr(#[from] rsudo_core::SsrError),

    /// Request denied
    #[error("Request denied: {0}")]
    Denied(String),

    /// Request timeout
    #[error("Request timeout - no approval received within {0}s")]
    Timeout(u64),

    /// Server error
    #[error("Server error: {0}")]
    ServerError(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid response
    #[error("Invalid response from server: {0}")]
    InvalidResponse(String),
}

/// Approval response from server
#[derive(Debug, Deserialize)]
struct ApprovalResponse {
    status: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    approver: Option<String>,
    #[serde(default)]
    signed_token: Option<String>,
}

/// Request submission response
#[derive(Debug, Deserialize)]
struct RequestSubmissionResponse {
    request_id: String,
    #[allow(dead_code)]
    status: String,
}

/// Build a sign request from command and environment
pub fn build_sign_request(
    command: &[String],
    timeout: u64,
    session: &Session,
    config: &Config,
    quiet: bool,
    verbose: bool,
) -> Result<SignRequest, RequestError> {
    if command.is_empty() {
        return Err(RequestError::InvalidResponse(
            "Command cannot be empty".to_string(),
        ));
    }

    let hostname = hostname::get()
        .map_err(|e| RequestError::InvalidResponse(format!("Failed to get hostname: {}", e)))?
        .to_string_lossy()
        .to_string();

    // Use system-level API instead of environment variables for security
    // (env vars can be spoofed, but getuid/getpwuid_r cannot)
    let username = users::get_current_username()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let cwd = std::env::current_dir()
        .map_err(|e| {
            RequestError::InvalidResponse(format!("Failed to get current directory: {}", e))
        })?
        .to_string_lossy()
        .to_string();

    // Get allowlist from config or environment
    let allowlist = get_env_allowlist(config);

    // Collect environment variables using allowlist
    let mut env = HashMap::new();
    let mut filtered_vars = Vec::new();

    for (key, value) in std::env::vars() {
        if is_allowed_env_var(&key, &allowlist) {
            env.insert(key, value);
        } else {
            filtered_vars.push(key);
        }
    }

    // Warn user if variables were filtered (security warning - on by default unless quiet or disabled)
    let warn_filtered = config.env.warn.unwrap_or(true);

    if !quiet && warn_filtered && !filtered_vars.is_empty() {
        eprintln!(
            "⚠️  Warning: {} environment variable(s) filtered:",
            filtered_vars.len()
        );
        if verbose {
            for var in &filtered_vars {
                eprintln!("   - {}", var);
            }
        }
        eprintln!("\n   To include these variables, add them to config:");
        eprintln!(
            "   rsudoctl config set env.allowlist \"{}\"",
            filtered_vars.join(",")
        );
        eprintln!(
            "   Or use: export RSUDO_ENV_ALLOWLIST=\"{}\"",
            filtered_vars.join(",")
        );
        eprintln!("\n   To disable this warning:");
        eprintln!("   rsudoctl config set env.warn false");
    }

    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(timeout as i64);

    let nonce = uuid::Uuid::new_v4().to_string();

    Ok(SignRequest {
        command: command[0].clone(),
        args: command[1..].to_vec(),
        hostname,
        username,
        cwd,
        env,
        timestamp: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        nonce,
        client_id: session.client_id.clone(),
    })
}

/// Get environment variable allowlist from config or environment
fn get_env_allowlist(config: &Config) -> Vec<String> {
    // Priority 1: RSUDO_ENV_ALLOWLIST environment variable (adhoc override)
    if let Ok(env_allowlist) = std::env::var("RSUDO_ENV_ALLOWLIST") {
        return env_allowlist
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    // Priority 2: Configuration file
    if let Some(ref allowlist) = config.env.allowlist {
        return allowlist.clone();
    }

    // Priority 3: Default allowlist of common safe variables
    vec![
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "TERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PWD",
        "OLDPWD",
        "EDITOR",
        "VISUAL",
        "PAGER",
        "DISPLAY",
        "COLORTERM",
        "RSUDO_*", // Wildcard for all RSUDO_ variables
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Check if an environment variable is allowed to be sent to server
fn is_allowed_env_var(key: &str, allowlist: &[String]) -> bool {
    for pattern in allowlist {
        if pattern.ends_with('*') {
            // Wildcard matching
            let prefix = &pattern[..pattern.len() - 1];
            if key.starts_with(prefix) {
                return true;
            }
        } else if pattern == key {
            // Exact match
            return true;
        }
    }
    false
}

/// Submit request in hanging mode (wait for approval)
pub async fn submit_hanging_request(
    server_url: &str,
    request: &SignRequest,
    timeout: u64,
) -> Result<String, RequestError> {
    let session = load_session()?;

    // Configure client with timeout to prevent indefinite blocking
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout + 10)) // Add buffer for network overhead
        .build()?;

    println!("🔐 Requesting approval...");
    println!("   Command: {} {}", request.command, request.args.join(" "));
    println!("   Host: {}", request.hostname);
    println!("   User: {}", request.username);

    // Submit request
    let resp = client
        .post(format!("{}/api/requests", server_url))
        .bearer_auth(&session.access_token)
        .json(request)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(RequestError::ServerError(format!(
            "Request submission failed ({}): {}",
            status, body
        )));
    }

    let response: RequestSubmissionResponse = resp.json().await?;

    println!("   Request ID: {}", response.request_id);
    println!("\n⏳ Waiting for approval ({}s timeout)...", timeout);

    // Poll for approval
    let approval = poll_for_approval(
        &client,
        server_url,
        &response.request_id,
        &session.access_token,
        timeout,
    )
    .await?;

    match approval.status.as_str() {
        "approved" => {
            println!(
                "✅ Approved by: {}",
                approval.approver.unwrap_or_else(|| "unknown".to_string())
            );
            Ok(approval.signed_token.ok_or_else(|| {
                RequestError::InvalidResponse("Missing signed token in approval".to_string())
            })?)
        }
        "denied" => Err(RequestError::Denied(
            approval
                .reason
                .unwrap_or_else(|| "No reason provided".to_string()),
        )),
        _ => Err(RequestError::InvalidResponse(format!(
            "Unknown status: {}",
            approval.status
        ))),
    }
}

/// Poll for approval from server
async fn poll_for_approval(
    client: &Client,
    server_url: &str,
    request_id: &str,
    access_token: &str,
    timeout: u64,
) -> Result<ApprovalResponse, RequestError> {
    let start = std::time::Instant::now();
    let timeout_duration = Duration::from_secs(timeout);
    let poll_interval = Duration::from_secs(2);

    loop {
        if start.elapsed() > timeout_duration {
            return Err(RequestError::Timeout(timeout));
        }

        tokio::time::sleep(poll_interval).await;

        let response = client
            .get(format!("{}/api/requests/{}", server_url, request_id))
            .bearer_auth(access_token)
            .send()
            .await?;

        if response.status().is_success() {
            let approval: ApprovalResponse = response.json().await?;

            // Check if request is still pending
            if approval.status == "pending" {
                continue;
            }

            return Ok(approval);
        } else if response.status() == 404 {
            return Err(RequestError::InvalidResponse(
                "Request not found on server".to_string(),
            ));
        } else {
            let error_text = response.text().await.unwrap_or_default();
            return Err(RequestError::ServerError(error_text));
        }
    }
}

/// Generate SSR token and optionally write to file
pub fn generate_ssr_token(
    request: &SignRequest,
    output: Option<&PathBuf>,
) -> Result<(), RequestError> {
    let token = SignRequestToken::new(request.clone());
    let pem = token.to_pem()?;

    if let Some(path) = output {
        std::fs::write(path, &pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        eprintln!("✅ SSR token written to: {}", path.display());
    } else {
        println!("{}", pem);
    }

    Ok(())
}

/// Load signed invocation from file or stdin
pub fn load_signed_invocation(input: &PathBuf) -> Result<String, RequestError> {
    let content = if input.as_os_str() == "-" {
        // Read from stdin
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        buffer
    } else {
        // Read from file
        std::fs::read_to_string(input)?
    };

    Ok(content)
}

/// Fetch signed invocation from server by request ID
pub async fn fetch_signed_invocation(
    server_url: &str,
    request_id: &str,
) -> Result<String, RequestError> {
    let session = load_session()?;
    let client = Client::new();

    let response = client
        .get(format!("{}/api/requests/{}/signed", server_url, request_id))
        .bearer_auth(&session.access_token)
        .send()
        .await?;

    if response.status().is_success() {
        #[derive(Deserialize)]
        struct SignedResponse {
            signed_token: String,
        }

        let signed_response: SignedResponse = response.json().await?;
        Ok(signed_response.signed_token)
    } else {
        let error_text = response.text().await.unwrap_or_default();
        Err(RequestError::ServerError(error_text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_allowed_env_var() {
        let allowlist = vec![
            "PATH".to_string(),
            "HOME".to_string(),
            "RSUDO_*".to_string(),
        ];

        assert!(is_allowed_env_var("PATH", &allowlist));
        assert!(is_allowed_env_var("HOME", &allowlist));
        assert!(is_allowed_env_var("RSUDO_TIMEOUT", &allowlist));
        assert!(is_allowed_env_var("RSUDO_SERVER", &allowlist));
        assert!(!is_allowed_env_var("AWS_SECRET_KEY", &allowlist));
        assert!(!is_allowed_env_var("PASSWORD", &allowlist));
    }

    #[test]
    fn test_get_env_allowlist_default() {
        let config = Config::default();
        let allowlist = get_env_allowlist(&config);

        assert!(allowlist.contains(&"PATH".to_string()));
        assert!(allowlist.contains(&"HOME".to_string()));
        assert!(allowlist.contains(&"RSUDO_*".to_string()));
    }

    #[test]
    fn test_get_env_allowlist_from_env() {
        std::env::set_var("RSUDO_ENV_ALLOWLIST", "MY_VAR,CUSTOM_KEY");
        let config = Config::default();
        let allowlist = get_env_allowlist(&config);

        assert!(allowlist.contains(&"MY_VAR".to_string()));
        assert!(allowlist.contains(&"CUSTOM_KEY".to_string()));

        std::env::remove_var("RSUDO_ENV_ALLOWLIST");
    }

    #[test]
    fn test_build_sign_request() {
        let session = Session {
            access_token: "access123".to_string(),
            refresh_token: "refresh456".to_string(),
            access_token_expires_at: "2027-12-31T23:59:59Z".to_string(),
            refresh_token_expires_at: "2027-01-30T23:59:59Z".to_string(),
            client_id: "client-001".to_string(),
            machine_group: "dev-boxes".to_string(),
            user_identity: "user@example.com".to_string(),
        };

        let config = Config::default();
        let command = vec!["reboot".to_string()];
        let request = build_sign_request(&command, 300, &session, &config, true, false).unwrap();

        assert_eq!(request.command, "reboot");
        assert!(request.args.is_empty());
        assert_eq!(request.client_id, "client-001");
        assert!(!request.nonce.is_empty());
    }

    #[test]
    fn test_build_sign_request_with_args() {
        let session = Session {
            access_token: "access123".to_string(),
            refresh_token: "refresh456".to_string(),
            access_token_expires_at: "2027-12-31T23:59:59Z".to_string(),
            refresh_token_expires_at: "2027-01-30T23:59:59Z".to_string(),
            client_id: "client-001".to_string(),
            machine_group: "dev-boxes".to_string(),
            user_identity: "user@example.com".to_string(),
        };

        let config = Config::default();
        let command = vec![
            "systemctl".to_string(),
            "restart".to_string(),
            "nginx".to_string(),
        ];
        let request = build_sign_request(&command, 300, &session, &config, true, false).unwrap();

        assert_eq!(request.command, "systemctl");
        assert_eq!(request.args, vec!["restart", "nginx"]);
    }
}
