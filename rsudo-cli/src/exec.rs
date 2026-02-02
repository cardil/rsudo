//! Privilege execution for rsudo
//!
//! Handles the two-phase execution model: unprivileged approval, then privileged execution.

use rsudo_core::{SignRequest, SignRequestToken};
use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::process::Command;
use thiserror::Error;

/// Execution errors
#[derive(Debug, Error)]
pub enum ExecError {
    /// Transaction not found
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    /// Invalid transaction
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Command execution failed
    #[error("Command execution failed: {0}")]
    ExecutionFailed(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// SSR token error
    #[error("SSR token error: {0}")]
    Ssr(#[from] rsudo_core::SsrError),
}

/// Transaction storage for approved requests
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Transaction {
    request: SignRequest,
    signed_token: String,
}

/// Check if we're running in privileged phase (via RSUDO_TXN env var)
pub fn is_privileged_phase() -> bool {
    std::env::var("RSUDO_TXN").is_ok()
}

/// Get transaction ID from environment
pub fn get_transaction_id() -> Option<String> {
    std::env::var("RSUDO_TXN").ok()
}

/// Store transaction for privileged phase
pub fn store_transaction(request: &SignRequest, signed_token: &str) -> Result<String, ExecError> {
    let txn_id = uuid::Uuid::new_v4().to_string();

    // Store in temporary file
    let txn_dir = std::env::temp_dir().join("rsudo-txn");
    std::fs::create_dir_all(&txn_dir)?;

    let txn_file = txn_dir.join(&txn_id);
    let txn = Transaction {
        request: request.clone(),
        signed_token: signed_token.to_string(),
    };

    let txn_json =
        serde_json::to_string(&txn).map_err(|e| ExecError::InvalidTransaction(e.to_string()))?;

    std::fs::write(&txn_file, txn_json)?;

    // Set restrictive permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&txn_file)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&txn_file, perms)?;
    }

    Ok(txn_id)
}

/// Load transaction from storage
pub fn load_transaction(txn_id: &str) -> Result<Transaction, ExecError> {
    let txn_file = std::env::temp_dir().join("rsudo-txn").join(txn_id);

    if !txn_file.exists() {
        return Err(ExecError::TransactionNotFound(txn_id.to_string()));
    }

    let txn_json = std::fs::read_to_string(&txn_file)?;
    let txn: Transaction = serde_json::from_str(&txn_json)
        .map_err(|e| ExecError::InvalidTransaction(e.to_string()))?;

    // Clean up transaction file after loading
    let _ = std::fs::remove_file(&txn_file);

    Ok(txn)
}

/// Re-invoke rsudo with sudo for privileged execution
pub fn reinvoke_with_sudo(txn_id: &str, command: &[String]) -> Result<(), ExecError> {
    // Get the current binary path
    let binary_path = std::env::current_exe()?;

    // Build sudo command
    let mut sudo_cmd = Command::new("sudo");
    sudo_cmd.env("RSUDO_TXN", txn_id);
    sudo_cmd.arg(&binary_path);

    // Add the original command arguments for audit visibility
    for arg in command {
        sudo_cmd.arg(arg);
    }

    // Execute with exec() - this replaces the current process
    let err = sudo_cmd.exec();

    // If we get here, exec failed
    Err(ExecError::ExecutionFailed(format!(
        "sudo exec failed: {}",
        err
    )))
}

/// Execute command in privileged phase
pub fn execute_privileged(txn_id: &str) -> Result<(), ExecError> {
    // Load and validate transaction
    let txn = load_transaction(txn_id)?;

    // Parse and validate signed token
    let token = SignRequestToken::from_pem(&txn.signed_token)?;
    let request = &token.request;

    // Verify the request matches the transaction
    if request.nonce != txn.request.nonce {
        return Err(ExecError::InvalidTransaction(
            "Request nonce mismatch".to_string(),
        ));
    }

    // Check if request has expired
    if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(&request.expires_at) {
        if chrono::Utc::now() > expires_at {
            return Err(ExecError::InvalidTransaction(
                "Request has expired".to_string(),
            ));
        }
    }

    // Sanitize environment before execution
    let sanitized_env = sanitize_environment(&request.env);

    // Build command
    let mut cmd = Command::new(&request.command);
    cmd.args(&request.args);
    cmd.current_dir(&request.cwd);
    cmd.env_clear();

    // Set sanitized environment
    for (key, value) in sanitized_env {
        cmd.env(key, value);
    }

    // Execute command and wait for completion
    let status = cmd.status()?;

    // Exit with the same code as the command
    std::process::exit(status.code().unwrap_or(1));
}

/// Sanitize environment variables before privileged execution
fn sanitize_environment(env: &HashMap<String, String>) -> HashMap<String, String> {
    let mut sanitized = HashMap::new();

    // List of dangerous variables to exclude
    const DANGEROUS_VARS: &[&str] = &[
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
    ];

    for (key, value) in env {
        // Skip dangerous variables
        if DANGEROUS_VARS.contains(&key.as_str()) {
            eprintln!("⚠️  Filtered dangerous environment variable: {}", key);
            continue;
        }

        sanitized.insert(key.clone(), value.clone());
    }

    // Always set some safe defaults
    sanitized.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );

    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_privileged_phase() {
        // Should be false in test environment
        assert!(!is_privileged_phase());

        // Set the env var
        std::env::set_var("RSUDO_TXN", "test-txn-123");
        assert!(is_privileged_phase());

        std::env::remove_var("RSUDO_TXN");
    }

    #[test]
    fn test_get_transaction_id() {
        assert!(get_transaction_id().is_none());

        std::env::set_var("RSUDO_TXN", "test-txn-456");
        assert_eq!(get_transaction_id(), Some("test-txn-456".to_string()));

        std::env::remove_var("RSUDO_TXN");
    }

    #[test]
    fn test_sanitize_environment() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/custom/path".to_string());
        env.insert("HOME".to_string(), "/home/user".to_string());
        env.insert("LD_PRELOAD".to_string(), "/evil/lib.so".to_string());
        env.insert(
            "DYLD_INSERT_LIBRARIES".to_string(),
            "/evil/dylib".to_string(),
        );

        let sanitized = sanitize_environment(&env);

        // PATH should be overridden with safe default
        assert!(sanitized.get("PATH").unwrap().contains("/usr/bin"));

        // HOME should be preserved
        assert_eq!(sanitized.get("HOME"), Some(&"/home/user".to_string()));

        // Dangerous vars should be filtered
        assert!(!sanitized.contains_key("LD_PRELOAD"));
        assert!(!sanitized.contains_key("DYLD_INSERT_LIBRARIES"));
    }
}
