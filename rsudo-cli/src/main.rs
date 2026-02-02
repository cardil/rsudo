//! rsudo CLI - Remote sudo with human-in-the-loop approval

mod args;
mod config;
mod exec;
mod login;
mod request;
mod session;

use args::{ConfigCommand, InvocationMode, RsudoArgs, RsudoctlArgs, RsudoctlCommand};
use clap::Parser;
use rsudo_core::{Config, ConfigLoader};
use std::process;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Detect invocation mode
    let mode = InvocationMode::detect();

    // Run appropriate handler
    let exit_code = match mode {
        InvocationMode::Rsudo => handle_rsudo().await,
        InvocationMode::Rsudoctl => handle_rsudoctl().await,
    };

    process::exit(exit_code);
}

/// Handle rsudo (command execution) mode
async fn handle_rsudo() -> i32 {
    // Check if we're in privileged phase
    if exec::is_privileged_phase() {
        if let Some(txn_id) = exec::get_transaction_id() {
            return match exec::execute_privileged(&txn_id) {
                Ok(()) => 0, // Should not reach here - exec replaces process
                Err(e) => {
                    eprintln!("rsudo: execution error: {}", e);
                    3
                }
            };
        }
    }

    // Parse arguments
    let args = match RsudoArgs::try_parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            return 2;
        }
    };

    // Validate arguments
    if let Err(e) = args.validate() {
        eprintln!("rsudo: {}", e);
        return 2;
    }

    // Load configuration
    let loader = ConfigLoader::new();
    let config = match loader.load() {
        Ok(config) => config,
        Err(e) => {
            if !args.quiet {
                eprintln!("rsudo: warning: failed to load config: {}", e);
            }
            Config::default()
        }
    };

    // Get server URL from config
    let server_url = match config.server.url.as_ref() {
        Some(url) => url.clone(),
        None => {
            eprintln!("rsudo: error: server URL not configured");
            eprintln!("Set server URL in /etc/rsudo/config.toml or ~/.config/rsudo/config.toml");
            return 4;
        }
    };

    // Handle different modes
    if let Some(signed_value) = args.signed {
        // Signed mode - execute with signed invocation
        handle_signed_mode(&signed_value, args.input.as_ref(), &server_url).await
    } else if args.ssr {
        // SSR mode - generate and output token
        handle_ssr_mode(&args, &config).await
    } else {
        // Hanging mode - request approval and execute
        handle_hanging_mode(&args, &config, &server_url).await
    }
}

/// Handle signed invocation mode
async fn handle_signed_mode(
    signed_value: &str,
    input: Option<&std::path::PathBuf>,
    server_url: &str,
) -> i32 {
    let signed_token = if let Some(input_path) = input {
        // Load from file or stdin
        match request::load_signed_invocation(input_path) {
            Ok(token) => token,
            Err(e) => {
                eprintln!("rsudo: failed to load signed invocation: {}", e);
                return 3;
            }
        }
    } else {
        // Fetch from server by request ID
        match request::fetch_signed_invocation(server_url, signed_value).await {
            Ok(token) => token,
            Err(e) => {
                eprintln!("rsudo: failed to fetch signed invocation: {}", e);
                return 3;
            }
        }
    };

    // Parse the signed token to get the request
    let token = match rsudo_core::SignRequestToken::from_pem(&signed_token) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("rsudo: invalid signed token: {}", e);
            return 3;
        }
    };

    let request = &token.request;

    // Store transaction and re-invoke with sudo
    match exec::store_transaction(request, &signed_token) {
        Ok(txn_id) => {
            let command = vec![request.command.clone()]
                .into_iter()
                .chain(request.args.clone())
                .collect::<Vec<_>>();

            match exec::reinvoke_with_sudo(&txn_id, &command) {
                Ok(()) => 0, // Should not reach here
                Err(e) => {
                    eprintln!("rsudo: failed to execute: {}", e);
                    3
                }
            }
        }
        Err(e) => {
            eprintln!("rsudo: failed to store transaction: {}", e);
            3
        }
    }
}

/// Handle SSR mode
async fn handle_ssr_mode(args: &RsudoArgs, config: &Config) -> i32 {
    // Load session
    let session = match session::load_session() {
        Ok(session) => session,
        Err(e) => {
            eprintln!("rsudo: {}", e);
            return 6;
        }
    };

    // Build sign request
    let request = match request::build_sign_request(
        &args.command,
        args.timeout,
        &session,
        config,
        args.quiet,
        args.verbose,
    ) {
        Ok(request) => request,
        Err(e) => {
            eprintln!("rsudo: failed to build request: {}", e);
            return 3;
        }
    };

    // Generate and output SSR token
    match request::generate_ssr_token(&request, args.output.as_ref()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("rsudo: failed to generate SSR token: {}", e);
            3
        }
    }
}

/// Handle hanging mode (normal execution with approval)
async fn handle_hanging_mode(args: &RsudoArgs, config: &Config, server_url: &str) -> i32 {
    // Load session
    let session = match session::load_session() {
        Ok(session) => session,
        Err(e) => {
            eprintln!("rsudo: {}", e);
            return 6;
        }
    };

    // Build sign request
    let request = match request::build_sign_request(
        &args.command,
        args.timeout,
        &session,
        config,
        args.quiet,
        args.verbose,
    ) {
        Ok(request) => request,
        Err(e) => {
            eprintln!("rsudo: failed to build request: {}", e);
            return 3;
        }
    };

    // Submit request and wait for approval
    let signed_token =
        match request::submit_hanging_request(server_url, &request, args.timeout).await {
            Ok(token) => token,
            Err(e) => match e {
                request::RequestError::Denied(reason) => {
                    eprintln!("rsudo: request denied: {}", reason);
                    return 2;
                }
                request::RequestError::Timeout(secs) => {
                    eprintln!("rsudo: request timeout after {}s", secs);
                    return 3;
                }
                request::RequestError::Session(_) => {
                    eprintln!("rsudo: {}", e);
                    return 6;
                }
                _ => {
                    eprintln!("rsudo: {}", e);
                    return 5;
                }
            },
        };

    // Store transaction and re-invoke with sudo
    match exec::store_transaction(&request, &signed_token) {
        Ok(txn_id) => match exec::reinvoke_with_sudo(&txn_id, &args.command) {
            Ok(()) => 0, // Should not reach here
            Err(e) => {
                eprintln!("rsudo: failed to execute: {}", e);
                3
            }
        },
        Err(e) => {
            eprintln!("rsudo: failed to store transaction: {}", e);
            3
        }
    }
}

/// Handle rsudoctl (management) mode
async fn handle_rsudoctl() -> i32 {
    // Parse arguments
    let args = match RsudoctlArgs::try_parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            return 2;
        }
    };

    // Load configuration
    let loader = ConfigLoader::new();
    let config = match loader.load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("rsudoctl: warning: failed to load config: {}", e);
            Config::default()
        }
    };

    // Handle subcommands - only login requires server_url
    match args.command {
        RsudoctlCommand::Login { token } => {
            // Defer server_url check to when it's actually needed
            let server_url = match config.server.url.as_ref() {
                Some(url) => url.clone(),
                None => {
                    eprintln!("rsudoctl: error: server URL not configured");
                    eprintln!("Set server URL in /etc/rsudo/config.toml");
                    return 4;
                }
            };
            handle_login(token, &server_url).await
        }
        RsudoctlCommand::Logout => handle_logout(),
        RsudoctlCommand::Status => handle_status(),
        RsudoctlCommand::Config { command } => handle_config(command),
    }
}

/// Handle login command
async fn handle_login(token: Option<String>, server_url: &str) -> i32 {
    let result = if let Some(token_value) = token {
        // Batch mode with enrollment token
        let actual_token = if token_value.is_empty() {
            // Read from environment variable
            match std::env::var("RSUDO_ENROLL_TOKEN") {
                Ok(t) => t,
                Err(_) => {
                    eprintln!("rsudoctl: RSUDO_ENROLL_TOKEN environment variable not set");
                    return 7;
                }
            }
        } else {
            token_value
        };

        login::login_with_token(server_url, &actual_token).await
    } else {
        // Interactive OAuth flow
        login::login_interactive(server_url).await
    };

    match result {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("rsudoctl: login failed: {}", e);
            match e {
                login::LoginError::TokenInvalid(_) | login::LoginError::ValidationFailed(_) => 7,
                login::LoginError::OAuthFailed(_) | login::LoginError::Timeout => 6,
                _ => 5,
            }
        }
    }
}

/// Handle logout command
fn handle_logout() -> i32 {
    match session::delete_session() {
        Ok(()) => {
            println!("✅ Logged out successfully");
            0
        }
        Err(e) => {
            eprintln!("rsudoctl: logout failed: {}", e);
            3
        }
    }
}

/// Handle status command
fn handle_status() -> i32 {
    match session::load_session() {
        Ok(session) => {
            println!("✅ Enrolled");
            println!("   User: {}", session.user_identity);
            println!("   Client ID: {}", session.client_id);
            println!("   Machine Group: {}", session.machine_group);
            println!(
                "   Access Token Expires: {}",
                session.access_token_expires_at
            );
            println!(
                "   Refresh Token Expires: {}",
                session.refresh_token_expires_at
            );

            if session.is_access_token_expired() {
                println!("\n⚠️  Access token expired - will be refreshed on next request");
            }

            if !session.is_valid() {
                println!("\n❌ Session expired - run 'rsudoctl login' again");
                return 6;
            }

            0
        }
        Err(e) => {
            println!("❌ Not enrolled: {}", e);
            6
        }
    }
}

/// Handle config commands
fn handle_config(command: ConfigCommand) -> i32 {
    match command {
        ConfigCommand::Show => config::show_config(),
        ConfigCommand::Get { key } => config::get_config(&key),
        ConfigCommand::Set { key, value } => config::set_config(&key, &value),
    }
}
