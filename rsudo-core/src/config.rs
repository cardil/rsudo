//! Configuration loading and merging
//!
//! Handles loading rsudo configuration from multiple sources with proper precedence.

use crate::types::Config;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// TOML parsing error
    #[error("TOML parse error: {0}")]
    TomlError(#[from] toml::de::Error),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Configuration loader
pub struct ConfigLoader {
    system_config_path: PathBuf,
    dropin_dir: PathBuf,
    user_config_path: Option<PathBuf>,
}

impl ConfigLoader {
    /// Create a new config loader with default paths
    pub fn new() -> Self {
        Self {
            system_config_path: PathBuf::from("/etc/rsudo/config.toml"),
            dropin_dir: PathBuf::from("/etc/rsudo.d"),
            user_config_path: Self::default_user_config_path(),
        }
    }

    /// Create a config loader with custom paths (for testing)
    pub fn with_paths(
        system_config: PathBuf,
        dropin_dir: PathBuf,
        user_config: Option<PathBuf>,
    ) -> Self {
        Self {
            system_config_path: system_config,
            dropin_dir,
            user_config_path: user_config,
        }
    }

    /// Get the default user config path
    fn default_user_config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|dir| dir.join("rsudo").join("config.toml"))
    }

    /// Load configuration from all sources
    pub fn load(&self) -> Result<Config, ConfigError> {
        let mut config = Config::default();

        // 1. Load system config
        if self.system_config_path.exists() {
            let system_config = self.load_file(&self.system_config_path)?;
            config = self.merge_configs(config, system_config, false);
        }

        // 2. Load drop-in configs (alphabetical order)
        if self.dropin_dir.exists() && self.dropin_dir.is_dir() {
            let mut dropin_files = Vec::new();

            for entry in fs::read_dir(&self.dropin_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("toml") {
                    dropin_files.push(path);
                }
            }

            // Sort alphabetically
            dropin_files.sort();

            for path in dropin_files {
                let dropin_config = self.load_file(&path)?;
                config = self.merge_configs(config, dropin_config, false);
            }
        }

        // 3. Load user config (with restrictions)
        if let Some(user_path) = &self.user_config_path {
            if user_path.exists() {
                let user_config = self.load_file(user_path)?;
                config = self.merge_configs(config, user_config, true);
            }
        }

        Ok(config)
    }

    /// Load a single config file
    fn load_file(&self, path: &Path) -> Result<Config, ConfigError> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Merge two configs with proper precedence
    ///
    /// If `is_user_config` is true, security-critical fields are not overridden
    fn merge_configs(&self, mut base: Config, overlay: Config, is_user_config: bool) -> Config {
        // Client config - always mergeable
        if overlay.client.key_file.is_some() {
            base.client.key_file = overlay.client.key_file;
        }
        if overlay.client.default_timeout.is_some() {
            base.client.default_timeout = overlay.client.default_timeout;
        }

        // Server config - URL and CA cert are security-critical
        if !is_user_config {
            if overlay.server.url.is_some() {
                base.server.url = overlay.server.url;
            }
            if overlay.server.ca_cert.is_some() {
                base.server.ca_cert = overlay.server.ca_cert;
            }
        }

        // Policy config - security-critical, not overridable by user
        if !is_user_config {
            if overlay.policy.allowed_commands.is_some() {
                base.policy.allowed_commands = overlay.policy.allowed_commands;
            }
            if overlay.policy.require_tty.is_some() {
                base.policy.require_tty = overlay.policy.require_tty;
            }
        }

        // Audit config - always mergeable
        if overlay.audit.log_file.is_some() {
            base.audit.log_file = overlay.audit.log_file;
        }
        if overlay.audit.syslog.is_some() {
            base.audit.syslog = overlay.audit.syslog;
        }

        // Request config - always mergeable
        if overlay.request.default_timeout.is_some() {
            base.request.default_timeout = overlay.request.default_timeout;
        }

        base
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_config(content: &str, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)
    }

    #[test]
    fn test_load_system_config() {
        let temp_dir = TempDir::new().unwrap();
        let system_config = temp_dir.path().join("config.toml");

        let config_content = r#"
[server]
url = "https://rsudo.example.com"

[policy]
allowed_commands = ["reboot", "shutdown"]
"#;

        create_test_config(config_content, &system_config).unwrap();

        let loader = ConfigLoader::with_paths(system_config, temp_dir.path().join("rsudo.d"), None);

        let config = loader.load().unwrap();

        assert_eq!(
            config.server.url,
            Some("https://rsudo.example.com".to_string())
        );
        assert_eq!(
            config.policy.allowed_commands,
            Some(vec!["reboot".to_string(), "shutdown".to_string()])
        );
    }

    #[test]
    fn test_dropin_configs_alphabetical() {
        let temp_dir = TempDir::new().unwrap();
        let system_config = temp_dir.path().join("config.toml");
        let dropin_dir = temp_dir.path().join("rsudo.d");

        fs::create_dir_all(&dropin_dir).unwrap();

        // System config
        create_test_config(
            r#"
[request]
default_timeout = 100
"#,
            &system_config,
        )
        .unwrap();

        // Drop-in 1 (loaded first alphabetically)
        create_test_config(
            r#"
[request]
default_timeout = 200
"#,
            &dropin_dir.join("10-first.toml"),
        )
        .unwrap();

        // Drop-in 2 (loaded second, should override)
        create_test_config(
            r#"
[request]
default_timeout = 300
"#,
            &dropin_dir.join("20-second.toml"),
        )
        .unwrap();

        let loader = ConfigLoader::with_paths(system_config, dropin_dir, None);
        let config = loader.load().unwrap();

        // Should have the value from the last drop-in
        assert_eq!(config.request.default_timeout, Some(300));
    }

    #[test]
    fn test_user_config_cannot_override_security() {
        let temp_dir = TempDir::new().unwrap();
        let system_config = temp_dir.path().join("config.toml");
        let user_config = temp_dir.path().join("user-config.toml");

        // System config with security settings
        create_test_config(
            r#"
[server]
url = "https://secure.example.com"

[policy]
allowed_commands = ["reboot"]
"#,
            &system_config,
        )
        .unwrap();

        // User trying to override security settings
        create_test_config(
            r#"
[server]
url = "https://malicious.example.com"

[policy]
allowed_commands = ["*"]

[client]
default_timeout = 600
"#,
            &user_config,
        )
        .unwrap();

        let loader = ConfigLoader::with_paths(
            system_config,
            temp_dir.path().join("rsudo.d"),
            Some(user_config),
        );

        let config = loader.load().unwrap();

        // Security settings should NOT be overridden
        assert_eq!(
            config.server.url,
            Some("https://secure.example.com".to_string())
        );
        assert_eq!(
            config.policy.allowed_commands,
            Some(vec!["reboot".to_string()])
        );

        // Non-security settings CAN be overridden
        assert_eq!(config.client.default_timeout, Some(600));
    }

    #[test]
    fn test_missing_configs_use_defaults() {
        let temp_dir = TempDir::new().unwrap();

        let loader = ConfigLoader::with_paths(
            temp_dir.path().join("nonexistent.toml"),
            temp_dir.path().join("rsudo.d"),
            None,
        );

        let config = loader.load().unwrap();

        // Should have default values
        assert_eq!(config.client.default_timeout, Some(300));
        assert_eq!(config.policy.allowed_commands, Some(vec!["*".to_string()]));
    }

    #[test]
    fn test_partial_config_merge() {
        let temp_dir = TempDir::new().unwrap();
        let system_config = temp_dir.path().join("config.toml");
        let user_config = temp_dir.path().join("user-config.toml");

        // System config with some settings
        create_test_config(
            r#"
[server]
url = "https://rsudo.example.com"

[audit]
syslog = true
"#,
            &system_config,
        )
        .unwrap();

        // User config with different settings
        create_test_config(
            r#"
[client]
key_file = "/home/user/.rsudo/key"

[audit]
log_file = "/tmp/audit.log"
"#,
            &user_config,
        )
        .unwrap();

        let loader = ConfigLoader::with_paths(
            system_config,
            temp_dir.path().join("rsudo.d"),
            Some(user_config),
        );

        let config = loader.load().unwrap();

        // Both configs should be merged
        assert_eq!(
            config.server.url,
            Some("https://rsudo.example.com".to_string())
        );
        assert_eq!(
            config.client.key_file,
            Some("/home/user/.rsudo/key".to_string())
        );
        assert_eq!(config.audit.syslog, Some(true));
        assert_eq!(config.audit.log_file, Some("/tmp/audit.log".to_string()));
    }
}
