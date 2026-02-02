//! Configuration management for rsudo
//!
//! Handles reading and writing user configuration.

use rsudo_core::ConfigLoader;
use std::path::PathBuf;
use thiserror::Error;

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// TOML parse error
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// TOML serialize error
    #[error("TOML serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    /// Config directory not found
    #[error("Could not determine config directory")]
    NoConfigDir,
}

/// Get user config file path (~/.config/rsudo/config.toml)
pub fn user_config_path() -> Result<PathBuf, ConfigError> {
    dirs::config_dir()
        .map(|d| d.join("rsudo").join("config.toml"))
        .ok_or(ConfigError::NoConfigDir)
}

/// Show current configuration
pub fn show_config() -> i32 {
    let loader = ConfigLoader::new();
    match loader.load() {
        Ok(config) => match toml::to_string_pretty(&config) {
            Ok(toml_str) => {
                println!("{}", toml_str);
                0
            }
            Err(e) => {
                eprintln!("rsudoctl: failed to serialize config: {}", e);
                3
            }
        },
        Err(e) => {
            eprintln!("rsudoctl: failed to load config: {}", e);
            4
        }
    }
}

/// Get a configuration value
pub fn get_config(key: &str) -> i32 {
    let loader = ConfigLoader::new();
    let config = match loader.load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rsudoctl: failed to load config: {}", e);
            return 4;
        }
    };

    // Convert config to TOML table for navigation
    let config_str = match toml::to_string(&config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rsudoctl: failed to serialize config: {}", e);
            return 3;
        }
    };

    let table: toml::Table = match config_str.parse() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("rsudoctl: failed to parse config: {}", e);
            return 3;
        }
    };

    // Navigate to the key
    let parts: Vec<&str> = key.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        eprintln!("rsudoctl: invalid key format: {}", key);
        eprintln!("Use format like: section.key or section.subsection.key");
        return 2;
    }

    let value = navigate_table(&table, &parts);
    match value {
        Some(v) => {
            println!("{}", format_value(v));
            0
        }
        None => {
            eprintln!("rsudoctl: key not found: {}", key);
            1
        }
    }
}

/// Navigate TOML table to find a value
fn navigate_table<'a>(table: &'a toml::Table, parts: &[&str]) -> Option<&'a toml::Value> {
    if parts.is_empty() {
        return None;
    }

    let first = table.get(parts[0])?;

    if parts.len() == 1 {
        return Some(first);
    }

    match first {
        toml::Value::Table(inner) => navigate_table(inner, &parts[1..]),
        _ => None,
    }
}

/// Format a TOML value for display
fn format_value(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Array(a) => {
            let items: Vec<String> = a.iter().map(format_value).collect();
            items.join(", ")
        }
        toml::Value::Table(t) => toml::to_string_pretty(t).unwrap_or_else(|_| "{}".to_string()),
        toml::Value::Datetime(d) => d.to_string(),
    }
}

/// Set a configuration value
pub fn set_config(key: &str, value: &str) -> i32 {
    let config_path = match user_config_path() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("rsudoctl: could not determine config directory");
            return 4;
        }
    };

    // Load existing user config or create empty
    let mut config: toml::Table = if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match content.parse() {
                Ok(table) => table,
                Err(e) => {
                    eprintln!("rsudoctl: failed to parse config: {}", e);
                    return 3;
                }
            },
            Err(e) => {
                eprintln!("rsudoctl: failed to read config: {}", e);
                return 3;
            }
        }
    } else {
        toml::Table::new()
    };

    // Parse key path (e.g., "env.warn" -> ["env", "warn"])
    let parts: Vec<&str> = key.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        eprintln!("rsudoctl: invalid key format: {}", key);
        eprintln!("Use format like: section.key or section.subsection.key");
        return 2;
    }

    // Parse value to appropriate TOML type
    let toml_value = if value == "true" {
        toml::Value::Boolean(true)
    } else if value == "false" {
        toml::Value::Boolean(false)
    } else if let Ok(n) = value.parse::<i64>() {
        toml::Value::Integer(n)
    } else {
        toml::Value::String(value.to_string())
    };

    // Navigate/create nested structure and set value
    match parts.len() {
        1 => {
            config.insert(parts[0].to_string(), toml_value);
        }
        2 => {
            let section = config
                .entry(parts[0].to_string())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if let toml::Value::Table(ref mut table) = section {
                table.insert(parts[1].to_string(), toml_value);
            } else {
                eprintln!("rsudoctl: {} is not a section", parts[0]);
                return 3;
            }
        }
        3 => {
            let section = config
                .entry(parts[0].to_string())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if let toml::Value::Table(ref mut table) = section {
                let subsection = table
                    .entry(parts[1].to_string())
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                if let toml::Value::Table(ref mut inner) = subsection {
                    inner.insert(parts[2].to_string(), toml_value);
                } else {
                    eprintln!("rsudoctl: {}.{} is not a section", parts[0], parts[1]);
                    return 3;
                }
            } else {
                eprintln!("rsudoctl: {} is not a section", parts[0]);
                return 3;
            }
        }
        _ => unreachable!(),
    }

    // Ensure directory exists
    if let Some(parent) = config_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("rsudoctl: failed to create config directory: {}", e);
            return 4;
        }
    }

    // Serialize config
    let config_str = match toml::to_string_pretty(&config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rsudoctl: failed to serialize config: {}", e);
            return 3;
        }
    };

    // Write config
    match std::fs::write(&config_path, config_str) {
        Ok(()) => {
            eprintln!("✅ Set {} = {} in {}", key, value, config_path.display());
            0
        }
        Err(e) => {
            eprintln!("rsudoctl: failed to write config: {}", e);
            4
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_navigate_table() {
        let mut inner = toml::Table::new();
        inner.insert("key".to_string(), toml::Value::String("value".to_string()));

        let mut table = toml::Table::new();
        table.insert("section".to_string(), toml::Value::Table(inner));

        assert_eq!(
            navigate_table(&table, &["section", "key"]),
            Some(&toml::Value::String("value".to_string()))
        );

        assert_eq!(navigate_table(&table, &["missing"]), None);
    }

    #[test]
    fn test_format_value() {
        assert_eq!(
            format_value(&toml::Value::String("test".to_string())),
            "test"
        );
        assert_eq!(format_value(&toml::Value::Boolean(true)), "true");
        assert_eq!(format_value(&toml::Value::Integer(42)), "42");
    }
}
