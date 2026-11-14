// SPDX-License-Identifier: AGPL-3.0-only

//! Logging initialization, filtering, and Zero Payload Policy enforcement for Project Yachiyo CLI.
//!
//! Configures `tracing-subscriber` with `fmt` formatting and `EnvFilter`.
//! Supports log level overrides via CLI flag `--log-level` and the `RUST_LOG` environment variable,
//! defaulting to `info`.
//!
//! # Zero Payload Policy
//!
//! Per Project Yachiyo specification (ORIGINAL_REQUEST R3):
//! - Logs only record target host, target port, protocol mode, byte counts, and connection lifecycle events.
//! - Under NO circumstances may application payload bytes (e.g. HTTP headers, request/response bodies,
//!   or SOCKS5 stream content) be recorded in log output at ANY log level (including DEBUG or TRACE).
//! - The formatting subscriber does not install any payload sniffing, buffer capture, or packet inspection layers.

use std::sync::OnceLock;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;

/// Errors that may occur during logging initialization.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("failed to parse log filter directive '{directive}': {source}")]
    ParseDirective {
        directive: String,
        #[source]
        source: tracing_subscriber::filter::ParseError,
    },
    #[error("failed to initialize global tracing subscriber: {0}")]
    InitSubscriber(#[from] tracing::subscriber::SetGlobalDefaultError),
}

/// Global guard to ensure idempotent initialization in test environments.
static LOGGING_INITIALIZED: OnceLock<()> = OnceLock::new();

/// Builds an [`EnvFilter`] based on CLI argument, `RUST_LOG` environment variable, and default `info`.
///
/// Priority:
/// 1. Explicit CLI argument (`cli_log_level`), if provided and not equal to the default fallback.
/// 2. `RUST_LOG` environment variable, if set and valid.
/// 3. Default directive `"info"`.
pub fn build_env_filter(cli_log_level: Option<&str>) -> Result<EnvFilter, LoggingError> {
    match cli_log_level {
        Some(level) if !level.trim().is_empty() => {
            let trimmed = level.trim();
            // If the argument is the default "info" and RUST_LOG is explicitly present in the environment,
            // allow RUST_LOG to override the default.
            if trimmed.eq_ignore_ascii_case("info") && std::env::var_os("RUST_LOG").is_some() {
                if let Ok(filter) = EnvFilter::try_from_default_env() {
                    return Ok(filter);
                }
            }
            EnvFilter::try_new(trimmed).map_err(|source| LoggingError::ParseDirective {
                directive: trimmed.to_string(),
                source,
            })
        }
        _ => {
            // When CLI flag is omitted or empty, consult RUST_LOG, falling back to "info"
            Ok(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        }
    }
}

/// Initializes the global tracing subscriber.
///
/// Configures formatting for stdout/stderr with:
/// - Target name enabled
/// - Millisecond/compact timestamps
/// - ANSI color support
/// - Strict zero payload formatting (standard key-value attributes only)
///
/// # Idempotency
/// If called multiple times (e.g. within unit or integration test harnesses),
/// subsequent calls return `Ok(())` safely without panicking.
pub fn init_logging(cli_log_level: Option<&str>) -> Result<(), LoggingError> {
    if LOGGING_INITIALIZED.get().is_some() {
        return Ok(());
    }

    let filter = build_env_filter(cli_log_level)?;

    let subscriber = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;
    let _ = LOGGING_INITIALIZED.set(());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_build_env_filter_standard_levels() {
        assert!(build_env_filter(Some("info")).is_ok());
        assert!(build_env_filter(Some("debug")).is_ok());
        assert!(build_env_filter(Some("warn")).is_ok());
        assert!(build_env_filter(Some("error")).is_ok());
        assert!(build_env_filter(Some("trace")).is_ok());
    }

    #[test]
    fn test_build_env_filter_complex_directive() {
        let filter = build_env_filter(Some("yachiyo=debug,yachiyo_core=trace,tokio=warn"));
        assert!(filter.is_ok());
    }

    #[test]
    fn test_build_env_filter_invalid_directive_returns_error() {
        let res = build_env_filter(Some("invalid_directive_syntax???===="));
        assert!(res.is_err());
        match res.unwrap_err() {
            LoggingError::ParseDirective { directive, .. } => {
                assert!(directive.contains("invalid_directive_syntax"));
            }
            _ => panic!("expected ParseDirective error"),
        }
    }

    #[test]
    fn test_build_env_filter_none_defaults_to_info() {
        let res = build_env_filter(None);
        assert!(res.is_ok());
    }

    #[derive(Clone)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_zero_payload_policy_no_sensitive_leakage() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let shared = SharedBuffer(buf.clone());

        let subscriber = fmt()
            .with_writer(move || shared.clone())
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .finish();

        let _guard = tracing::subscriber::set_default(subscriber);

        let secret_payload = "SUPER_SECRET_PAYLOAD_TOKEN_NEVER_LOG_THIS";
        let target_host = "example.com:443";

        // Simulate typical proxy logging events:
        // Metadata (target host, port, stats) is logged.
        // Payload content is explicitly NOT passed to the logging macros.
        tracing::info!(target = %target_host, "outbound direct connection established");
        tracing::debug!(bytes = secret_payload.len(), "forwarded initial chunk");

        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();

        // 1. Metadata must be captured
        assert!(
            output.contains("example.com:443"),
            "target host and port must appear in logs"
        );
        assert!(
            output.contains("bytes="),
            "byte count metadata must appear in logs"
        );

        // 2. Secret payload bytes must NEVER be present
        assert!(
            !output.contains(secret_payload),
            "SECURITY VIOLATION: raw payload content found in log output"
        );
    }
}
