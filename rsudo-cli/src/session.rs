//! Session management for rsudo
//!
//! Handles storing and loading session credentials in ~/.cache/rsudo/

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

/// Session errors
#[derive(Debug, Error)]
pub enum SessionError {
    /// Failed to access session directory
    #[error("Failed to access session directory: {0}")]
    DirectoryAccess(#[from] std::io::Error),

    /// Failed to serialize/deserialize session
    #[error("Failed to serialize/deserialize session: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Session not found
    #[error("Session not found - run 'rsudoctl login' first")]
    NotFound,

    /// Session expired
    #[error("Session expired - run 'rsudoctl login' again")]
    Expired,

    /// Invalid session data
    #[error("Invalid session data: {0}")]
    Invalid(String),
}

/// Session credentials stored locally
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    /// Access token for API requests
    pub access_token: String,

    /// Refresh token for renewing access token
    pub refresh_token: String,

    /// Access token expiry timestamp (ISO 8601 UTC)
    pub access_token_expires_at: String,

    /// Refresh token expiry timestamp (ISO 8601 UTC)
    pub refresh_token_expires_at: String,

    /// Client identifier
    pub client_id: String,

    /// Machine group this client belongs to
    pub machine_group: String,

    /// User identity (email or username)
    pub user_identity: String,
}

impl Session {
    /// Check if the access token is expired
    pub fn is_access_token_expired(&self) -> bool {
        // Parse the expiry timestamp and compare with current time
        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(&self.access_token_expires_at) {
            chrono::Utc::now() >= expiry
        } else {
            // If we can't parse the timestamp, assume expired for safety
            true
        }
    }

    /// Check if the refresh token is expired
    pub fn is_refresh_token_expired(&self) -> bool {
        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(&self.refresh_token_expires_at) {
            chrono::Utc::now() >= expiry
        } else {
            true
        }
    }

    /// Check if the session is valid (refresh token not expired)
    pub fn is_valid(&self) -> bool {
        !self.is_refresh_token_expired()
    }
}

/// Get the session directory path (~/.cache/rsudo/)
pub fn session_dir() -> Result<PathBuf, SessionError> {
    let cache_dir = dirs::cache_dir()
        .ok_or_else(|| SessionError::Invalid("Could not determine cache directory".to_string()))?;

    Ok(cache_dir.join("rsudo"))
}

/// Get the session file path (~/.cache/rsudo/session.json)
pub fn session_file() -> Result<PathBuf, SessionError> {
    Ok(session_dir()?.join("session.json"))
}

/// Get the machine ID file path (~/.cache/rsudo/machine_id)
pub fn machine_id_file() -> Result<PathBuf, SessionError> {
    Ok(session_dir()?.join("machine_id"))
}

/// Load session from disk
pub fn load_session() -> Result<Session, SessionError> {
    let path = session_file()?;

    if !path.exists() {
        return Err(SessionError::NotFound);
    }

    let contents = fs::read_to_string(&path)?;
    let session: Session = serde_json::from_str(&contents)?;

    // Check if session is expired
    if !session.is_valid() {
        return Err(SessionError::Expired);
    }

    Ok(session)
}

/// Save session to disk
pub fn save_session(session: &Session) -> Result<(), SessionError> {
    let dir = session_dir()?;

    // Create directory with restrictive permissions to avoid TOCTOU window
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700) // rwx------
            .create(&dir)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(&dir)?;

    let path = session_file()?;
    let contents = serde_json::to_string_pretty(session)?;
    fs::write(&path, contents)?;

    // Set restrictive permissions on the file (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600); // rw-------
        fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

/// Delete session from disk
pub fn delete_session() -> Result<(), SessionError> {
    let path = session_file()?;

    if path.exists() {
        fs::remove_file(&path)?;
    }

    Ok(())
}

/// Load or generate machine ID
pub fn load_or_generate_machine_id() -> Result<String, SessionError> {
    let path = machine_id_file()?;

    if path.exists() {
        // Load existing machine ID
        Ok(fs::read_to_string(&path)?.trim().to_string())
    } else {
        // Generate new machine ID
        let machine_id = uuid::Uuid::new_v4().to_string();

        // Create directory if needed
        let dir = session_dir()?;
        fs::create_dir_all(&dir)?;

        // Save machine ID
        fs::write(&path, &machine_id)?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&path, perms)?;
        }

        Ok(machine_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_serialization() {
        let session = Session {
            access_token: "access123".to_string(),
            refresh_token: "refresh456".to_string(),
            access_token_expires_at: "2026-12-31T23:59:59Z".to_string(),
            refresh_token_expires_at: "2027-01-30T23:59:59Z".to_string(),
            client_id: "client-001".to_string(),
            machine_group: "dev-boxes".to_string(),
            user_identity: "user@example.com".to_string(),
        };

        let json = serde_json::to_string(&session).unwrap();
        let deserialized: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(session, deserialized);
    }

    #[test]
    fn test_session_expiry_check() {
        // Create a session with expired access token
        let session = Session {
            access_token: "access123".to_string(),
            refresh_token: "refresh456".to_string(),
            access_token_expires_at: "2020-01-01T00:00:00Z".to_string(),
            refresh_token_expires_at: "2027-01-30T23:59:59Z".to_string(),
            client_id: "client-001".to_string(),
            machine_group: "dev-boxes".to_string(),
            user_identity: "user@example.com".to_string(),
        };

        assert!(session.is_access_token_expired());
        assert!(!session.is_refresh_token_expired());
        assert!(session.is_valid()); // Valid because refresh token is not expired
    }

    #[test]
    fn test_session_fully_expired() {
        let session = Session {
            access_token: "access123".to_string(),
            refresh_token: "refresh456".to_string(),
            access_token_expires_at: "2020-01-01T00:00:00Z".to_string(),
            refresh_token_expires_at: "2020-01-02T00:00:00Z".to_string(),
            client_id: "client-001".to_string(),
            machine_group: "dev-boxes".to_string(),
            user_identity: "user@example.com".to_string(),
        };

        assert!(session.is_access_token_expired());
        assert!(session.is_refresh_token_expired());
        assert!(!session.is_valid());
    }

    #[test]
    fn test_session_paths() {
        // Just verify the functions don't panic
        let _ = session_dir();
        let _ = session_file();
        let _ = machine_id_file();
    }
}
