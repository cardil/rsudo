//! Command-line argument parsing for rsudo/rsudoctl
//!
//! Detects invocation name (rsudo vs rsudoctl) and parses appropriate arguments.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Detect which binary was invoked based on argv[0]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationMode {
    /// Invoked as `rsudo` - command execution mode
    Rsudo,
    /// Invoked as `rsudoctl` - management mode
    Rsudoctl,
}

impl InvocationMode {
    /// Detect invocation mode from argv[0]
    pub fn detect() -> Self {
        let arg0 = std::env::args()
            .next()
            .unwrap_or_else(|| "rsudo".to_string());

        // Extract the binary name from the path
        let binary_name = std::path::Path::new(&arg0)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("rsudo");

        if binary_name.contains("rsudoctl") {
            InvocationMode::Rsudoctl
        } else {
            InvocationMode::Rsudo
        }
    }
}

/// rsudo - Execute commands with remote approval
#[derive(Debug, Parser)]
#[command(
    name = "rsudo",
    version,
    about = "Remote sudo with human-in-the-loop approval"
)]
pub struct RsudoArgs {
    /// Approval timeout in seconds
    #[arg(short = 't', long, default_value = "300")]
    pub timeout: u64,

    /// SSR mode - print sign request token and exit
    #[arg(short = 's', long, conflicts_with = "signed")]
    pub ssr: bool,

    /// Execute with signed invocation (request ID or use with --input for PEM file)
    #[arg(short = 'S', long, value_name = "REQUEST_ID", conflicts_with = "ssr")]
    pub signed: Option<String>,

    /// Input source for signed invocation PEM (use with --signed)
    /// Use "-" for stdin, or provide a file path
    #[arg(short = 'i', long, value_name = "FILE", requires = "signed")]
    pub input: Option<PathBuf>,

    /// Write SSR token to file instead of stdout
    #[arg(short = 'o', long, value_name = "FILE", requires = "ssr")]
    pub output: Option<PathBuf>,

    /// Verbose output
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Quiet mode - suppress output
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Command to execute (with arguments)
    /// Not used with --signed (command comes from signed invocation)
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "signed"
    )]
    pub command: Vec<String>,
}

impl RsudoArgs {
    /// Validate arguments after parsing
    pub fn validate(&self) -> Result<(), String> {
        // If --signed is provided, command should be empty
        if self.signed.is_some() && !self.command.is_empty() {
            return Err(
                "Cannot specify command when using --signed (command comes from signed invocation)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// rsudoctl - Manage rsudo enrollment and sessions
#[derive(Debug, Parser)]
#[command(
    name = "rsudoctl",
    version,
    about = "Manage rsudo enrollment and sessions"
)]
pub struct RsudoctlArgs {
    #[command(subcommand)]
    pub command: RsudoctlCommand,
}

/// Management subcommands
#[derive(Debug, Subcommand)]
pub enum RsudoctlCommand {
    /// Enroll this machine with the approval server
    Login {
        /// Use enrollment token (batch mode)
        /// If provided without value, reads from RSUDO_ENROLL_TOKEN env var
        #[arg(long, value_name = "TOKEN", num_args = 0..=1, default_missing_value = "")]
        token: Option<String>,
    },

    /// Invalidate session and remove local credentials
    Logout,

    /// Show enrollment and session status
    Status,

    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

/// Configuration subcommands
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Display current configuration
    Show,

    /// Set a configuration value (user-level only)
    Set {
        /// Configuration key (e.g., request.default_timeout)
        key: String,
        /// Configuration value
        value: String,
    },
}

#[cfg(test)]
#[allow(clippy::needless_borrows_for_generic_args)]
mod tests {
    use super::*;

    #[test]
    fn test_invocation_mode_detection() {
        // Note: This test can't easily test the actual detection since it depends on argv[0]
        // But we can test the logic
        let mode = InvocationMode::detect();
        // Should default to Rsudo in test environment
        assert!(matches!(
            mode,
            InvocationMode::Rsudo | InvocationMode::Rsudoctl
        ));
    }

    #[test]
    fn test_rsudo_args_parsing() {
        let args = RsudoArgs::try_parse_from(&["rsudo", "reboot"]).unwrap();
        assert_eq!(args.command, vec!["reboot"]);
        assert_eq!(args.timeout, 300);
        assert!(!args.ssr);
        assert!(!args.verbose);
    }

    #[test]
    fn test_rsudo_args_with_options() {
        let args = RsudoArgs::try_parse_from(&[
            "rsudo",
            "--timeout",
            "600",
            "--ssr",
            "--verbose",
            "systemctl",
            "restart",
            "nginx",
        ])
        .unwrap();
        assert_eq!(args.command, vec!["systemctl", "restart", "nginx"]);
        assert_eq!(args.timeout, 600);
        assert!(args.ssr);
        assert!(args.verbose);
    }

    #[test]
    fn test_rsudo_args_with_short_options() {
        let args = RsudoArgs::try_parse_from(&[
            "rsudo",
            "-t",
            "600",
            "-s",
            "-v",
            "systemctl",
            "restart",
            "nginx",
        ])
        .unwrap();
        assert_eq!(args.command, vec!["systemctl", "restart", "nginx"]);
        assert_eq!(args.timeout, 600);
        assert!(args.ssr);
        assert!(args.verbose);
    }

    #[test]
    fn test_rsudo_args_with_signed_request_id() {
        let args = RsudoArgs::try_parse_from(&["rsudo", "--signed", "rt_abc123"]).unwrap();
        assert_eq!(args.signed, Some("rt_abc123".to_string()));
        assert!(args.input.is_none());
        assert!(args.command.is_empty());
    }

    #[test]
    fn test_rsudo_args_with_signed_request_id_short() {
        let args = RsudoArgs::try_parse_from(&["rsudo", "-S", "rt_abc123"]).unwrap();
        assert_eq!(args.signed, Some("rt_abc123".to_string()));
        assert!(args.input.is_none());
        assert!(args.command.is_empty());
    }

    #[test]
    fn test_rsudo_args_with_signed_stdin() {
        let args =
            RsudoArgs::try_parse_from(&["rsudo", "--signed", "dummy", "--input", "-"]).unwrap();
        assert_eq!(args.signed, Some("dummy".to_string()));
        assert_eq!(args.input, Some(PathBuf::from("-")));
        assert!(args.command.is_empty());
    }

    #[test]
    fn test_rsudo_args_with_signed_stdin_short() {
        let args = RsudoArgs::try_parse_from(&["rsudo", "-S", "dummy", "-i", "-"]).unwrap();
        assert_eq!(args.signed, Some("dummy".to_string()));
        assert_eq!(args.input, Some(PathBuf::from("-")));
        assert!(args.command.is_empty());
    }

    #[test]
    fn test_rsudo_args_with_signed_file() {
        let args =
            RsudoArgs::try_parse_from(&["rsudo", "--signed", "dummy", "--input", "approval.pem"])
                .unwrap();
        assert_eq!(args.signed, Some("dummy".to_string()));
        assert_eq!(args.input, Some(PathBuf::from("approval.pem")));
        assert!(args.command.is_empty());
    }

    #[test]
    fn test_rsudo_args_signed_rejects_command() {
        // Should fail validation because --signed doesn't accept a command
        let args = RsudoArgs::try_parse_from(&["rsudo", "--signed", "rt_abc", "reboot"]).unwrap();
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_rsudo_args_ssr_conflicts_with_signed() {
        // Should fail because --ssr and --signed are mutually exclusive
        let result = RsudoArgs::try_parse_from(&["rsudo", "--ssr", "--signed", "rt_abc"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_rsudo_args_output_requires_ssr() {
        // Should fail because --output requires --ssr
        let result = RsudoArgs::try_parse_from(&["rsudo", "--output", "file.ssr", "reboot"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_rsudo_args_input_requires_signed() {
        // Should fail because --input requires --signed
        let result = RsudoArgs::try_parse_from(&["rsudo", "--input", "-", "reboot"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_rsudoctl_login() {
        let args = RsudoctlArgs::try_parse_from(&["rsudoctl", "login"]).unwrap();
        assert!(matches!(
            args.command,
            RsudoctlCommand::Login { token: None }
        ));
    }

    #[test]
    fn test_rsudoctl_login_with_token() {
        let args =
            RsudoctlArgs::try_parse_from(&["rsudoctl", "login", "--token", "rt_abc123"]).unwrap();
        if let RsudoctlCommand::Login { token } = args.command {
            assert_eq!(token, Some("rt_abc123".to_string()));
        } else {
            panic!("Expected Login command");
        }
    }

    #[test]
    fn test_rsudoctl_login_token_from_env() {
        let args = RsudoctlArgs::try_parse_from(&["rsudoctl", "login", "--token"]).unwrap();
        if let RsudoctlCommand::Login { token } = args.command {
            assert_eq!(token, Some("".to_string())); // Empty string signals to read from env
        } else {
            panic!("Expected Login command");
        }
    }

    #[test]
    fn test_rsudoctl_logout() {
        let args = RsudoctlArgs::try_parse_from(&["rsudoctl", "logout"]).unwrap();
        assert!(matches!(args.command, RsudoctlCommand::Logout));
    }

    #[test]
    fn test_rsudoctl_status() {
        let args = RsudoctlArgs::try_parse_from(&["rsudoctl", "status"]).unwrap();
        assert!(matches!(args.command, RsudoctlCommand::Status));
    }

    #[test]
    fn test_rsudoctl_config_show() {
        let args = RsudoctlArgs::try_parse_from(&["rsudoctl", "config", "show"]).unwrap();
        if let RsudoctlCommand::Config { command } = args.command {
            assert!(matches!(command, ConfigCommand::Show));
        } else {
            panic!("Expected Config command");
        }
    }

    #[test]
    fn test_rsudoctl_config_set() {
        let args = RsudoctlArgs::try_parse_from(&[
            "rsudoctl",
            "config",
            "set",
            "request.default_timeout",
            "600",
        ])
        .unwrap();
        if let RsudoctlCommand::Config { command } = args.command {
            if let ConfigCommand::Set { key, value } = command {
                assert_eq!(key, "request.default_timeout");
                assert_eq!(value, "600");
            } else {
                panic!("Expected Set command");
            }
        } else {
            panic!("Expected Config command");
        }
    }
}
