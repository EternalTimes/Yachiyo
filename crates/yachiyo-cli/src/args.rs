// SPDX-License-Identifier: AGPL-3.0-only

//! Command-line argument parsing, listener address resolution, and pre-flight loopback security validation.

use clap::Parser;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use yachiyo_core::connection::DEFAULT_MAX_CONNECTIONS;
use yachiyo_core::{Config, ConfigError, OutboundRegistry, RuleSet};
use yachiyo_inbound::InboundConfig;

/// Default mixed listener endpoint when no specific listener flags are provided.
pub const DEFAULT_MIXED_ADDR: &str = "127.0.0.1:18484";

/// Default mixed listener endpoint as a typed SocketAddr constant.
pub const DEFAULT_MIXED_SOCKET_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 18484));

/// Command-line arguments for the Yachiyo proxy binary.
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[command(
    name = "yachiyo",
    version = env!("CARGO_PKG_VERSION"),
    about = "Project Yachiyo - Asynchronous proxy daemon",
    long_about = "A high-performance SOCKS5 and HTTP CONNECT proxy daemon with mixed-port sniffing, loopback security confinement, and graceful shutdown lifecycle."
)]
pub struct CliArgs {
    /// Mixed listener endpoint (demultiplexes SOCKS5 and HTTP CONNECT by first byte).
    /// Defaults to 127.0.0.1:18484 when neither --socks nor --http is specified.
    #[arg(long, value_name = "ADDR")]
    pub mixed: Option<SocketAddr>,

    /// Dedicated SOCKS5 listener endpoint.
    #[arg(long, value_name = "ADDR")]
    pub socks: Option<SocketAddr>,

    /// Dedicated HTTP CONNECT listener endpoint.
    #[arg(long, value_name = "ADDR")]
    pub http: Option<SocketAddr>,

    /// Allow binding listeners to non-loopback network interfaces (e.g. 0.0.0.0, [::], LAN IPs).
    #[arg(long)]
    pub allow_lan: bool,

    /// Log level or tracing filter directive (e.g., info, debug, trace, warn, error).
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    pub log_level: String,

    /// Handshake timeout in seconds (default: 10).
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    pub handshake_timeout: u64,

    /// Outbound connection timeout in seconds (default: 10).
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    pub connect_timeout: u64,

    /// Bidirectional idle timeout in seconds (default: 300).
    #[arg(long, default_value_t = 300, value_name = "SECS")]
    pub idle_timeout: u64,

    /// Maximum concurrent connections allowed before rejection (default: 1024).
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS, value_name = "LIMIT")]
    pub max_connections: usize,

    /// Path to native YAML configuration file (schema_version: 1).
    #[arg(short = 'c', long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Validate configuration and CLI options, then exit without starting listeners.
    #[arg(long)]
    pub check: bool,
}

/// Resolved listener endpoints after evaluating defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedListeners {
    pub mixed: Option<SocketAddr>,
    pub socks: Option<SocketAddr>,
    pub http: Option<SocketAddr>,
}

/// Errors originating from CLI argument validation or security constraints.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArgsError {
    #[error(
        "refusing to bind non-loopback address '{addr}' for --{flag}: \
         must specify --allow-lan to bind to non-loopback or public network interfaces"
    )]
    NonLoopbackAddressForbidden {
        flag: &'static str,
        addr: SocketAddr,
    },

    #[error("no listener addresses configured; specify --mixed, --socks, or --http")]
    NoListenersConfigured,
}

/// Checks whether a given socket address is a loopback address.
///
/// Recognizes:
/// - IPv4 `127.0.0.0/8`
/// - IPv6 `::1`
/// - IPv4-mapped loopback addresses `::ffff:127.x.x.x`
pub fn is_loopback_addr(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

impl CliArgs {
    /// Resolves the effective listener addresses based on CLI inputs and default fallback rules.
    ///
    /// Rules:
    /// - If neither `--socks`, `--http`, nor `--mixed` is supplied, defaults to `mixed = 127.0.0.1:18484`.
    /// - If `--socks` or `--http` is supplied without `--mixed`, only those dedicated listeners are activated.
    /// - If `--mixed` is explicitly supplied, it is activated alongside any dedicated listeners.
    pub fn resolve_listeners(&self) -> ResolvedListeners {
        if self.mixed.is_none() && self.socks.is_none() && self.http.is_none() {
            ResolvedListeners {
                mixed: Some(DEFAULT_MIXED_SOCKET_ADDR),
                socks: None,
                http: None,
            }
        } else {
            ResolvedListeners {
                mixed: self.mixed,
                socks: self.socks,
                http: self.http,
            }
        }
    }

    /// Performs pre-flight security validation on all resolved listener addresses.
    ///
    /// If `--allow-lan` is false, every address to be bound MUST be a loopback address.
    /// Rejects non-loopback bindings (e.g. `0.0.0.0`, `[::]`, LAN IPs) with [`ArgsError::NonLoopbackAddressForbidden`].
    pub fn validate_security(&self) -> Result<(), ArgsError> {
        if self.allow_lan {
            return Ok(());
        }

        let resolved = self.resolve_listeners();
        let endpoints: [(&'static str, Option<SocketAddr>); 3] = [
            ("mixed", resolved.mixed),
            ("socks", resolved.socks),
            ("http", resolved.http),
        ];

        for (flag, addr_opt) in endpoints {
            if let Some(addr) = addr_opt {
                if !is_loopback_addr(&addr) {
                    return Err(ArgsError::NonLoopbackAddressForbidden { flag, addr });
                }
            }
        }

        Ok(())
    }

    /// Converts the validated CLI arguments into an [`InboundConfig`] suitable for `yachiyo-inbound`.
    ///
    /// Automatically applies standard timeouts:
    /// - `handshake_timeout`: 10s
    /// - `connect_timeout`: 10s
    /// - `idle_timeout`: 300s
    pub fn to_inbound_config(&self) -> Result<InboundConfig, ArgsError> {
        self.validate_security()?;
        let resolved = self.resolve_listeners();

        if resolved.mixed.is_none() && resolved.socks.is_none() && resolved.http.is_none() {
            return Err(ArgsError::NoListenersConfigured);
        }

        Ok(InboundConfig {
            mixed_addr: resolved.mixed,
            socks_addr: resolved.socks,
            http_addr: resolved.http,
            handshake_timeout: Duration::from_secs(self.handshake_timeout),
            connect_timeout: Duration::from_secs(self.connect_timeout),
            idle_timeout: Duration::from_secs(self.idle_timeout),
            rules: Arc::new(RuleSet::default_direct()),
            outbounds: Arc::new(OutboundRegistry::new()),
            config_generation: 0,
        })
    }

    /// Resolves full runtime configuration from either `--config <PATH>` or CLI flags.
    pub fn resolve_runtime(&self) -> Result<RuntimeConfig, RuntimeConfigError> {
        if let Some(ref path) = self.config {
            let cfg = Config::from_file(path)?;
            let inbound = InboundConfig {
                mixed_addr: cfg.listeners.mixed,
                socks_addr: cfg.listeners.socks,
                http_addr: cfg.listeners.http,
                handshake_timeout: cfg.timeouts.handshake,
                connect_timeout: cfg.timeouts.connect,
                idle_timeout: cfg.timeouts.idle,
                rules: Arc::new(cfg.rules),
                outbounds: Arc::new(cfg.outbounds),
                config_generation: 1,
            };
            Ok(RuntimeConfig {
                inbound,
                max_connections: cfg.limits.max_connections,
                drain_timeout: cfg.timeouts.drain,
                log_level: cfg.logging.level,
            })
        } else {
            let inbound = self.to_inbound_config()?;
            Ok(RuntimeConfig {
                inbound,
                max_connections: self.max_connections,
                drain_timeout: crate::signal::DEFAULT_DRAIN_TIMEOUT,
                log_level: self.log_level.clone(),
            })
        }
    }
}

/// Unified runtime settings resolved from CLI flags or a native YAML configuration file.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub inbound: InboundConfig,
    pub max_connections: usize,
    pub drain_timeout: Duration,
    pub log_level: String,
}

/// Errors returned while resolving runtime configuration.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeConfigError {
    #[error(transparent)]
    Args(#[from] ArgsError),
    #[error(transparent)]
    Config(#[from] ConfigError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_default_args_resolution() {
        let args = CliArgs::try_parse_from(["yachiyo"]).expect("parse defaults");
        assert_eq!(args.mixed, None);
        assert_eq!(args.socks, None);
        assert_eq!(args.http, None);
        assert!(!args.allow_lan);
        assert_eq!(args.log_level, "info");

        let resolved = args.resolve_listeners();
        assert_eq!(resolved.mixed, Some(DEFAULT_MIXED_SOCKET_ADDR));
        assert_eq!(resolved.socks, None);
        assert_eq!(resolved.http, None);
        assert!(args.validate_security().is_ok());
    }

    #[test]
    fn test_explicit_mixed_arg() {
        let args = CliArgs::try_parse_from(["yachiyo", "--mixed", "127.0.0.1:19999"])
            .expect("parse explicit mixed");
        let resolved = args.resolve_listeners();
        assert_eq!(
            resolved.mixed,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19999))
        );
        assert_eq!(resolved.socks, None);
        assert_eq!(resolved.http, None);
    }

    #[test]
    fn test_socks_only_disables_default_mixed() {
        let args = CliArgs::try_parse_from(["yachiyo", "--socks", "127.0.0.1:1080"])
            .expect("parse socks only");
        let resolved = args.resolve_listeners();
        assert_eq!(resolved.mixed, None);
        assert_eq!(
            resolved.socks,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080))
        );
        assert_eq!(resolved.http, None);
    }

    #[test]
    fn test_http_only_disables_default_mixed() {
        let args = CliArgs::try_parse_from(["yachiyo", "--http", "127.0.0.1:8080"])
            .expect("parse http only");
        let resolved = args.resolve_listeners();
        assert_eq!(resolved.mixed, None);
        assert_eq!(resolved.socks, None);
        assert_eq!(
            resolved.http,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))
        );
    }

    #[test]
    fn test_socks_and_http_independent() {
        let args = CliArgs::try_parse_from([
            "yachiyo",
            "--socks",
            "127.0.0.1:1080",
            "--http",
            "127.0.0.1:8080",
        ])
        .expect("parse both independent");
        let resolved = args.resolve_listeners();
        assert_eq!(resolved.mixed, None);
        assert!(resolved.socks.is_some());
        assert!(resolved.http.is_some());
    }

    #[test]
    fn test_mixed_and_socks_combined() {
        let args = CliArgs::try_parse_from([
            "yachiyo",
            "--mixed",
            "127.0.0.1:18484",
            "--socks",
            "127.0.0.1:1080",
        ])
        .expect("parse combined");
        let resolved = args.resolve_listeners();
        assert!(resolved.mixed.is_some());
        assert!(resolved.socks.is_some());
        assert_eq!(resolved.http, None);
    }

    #[test]
    fn test_security_rejects_unspecified_ipv4_without_allow_lan() {
        let args = CliArgs::try_parse_from(["yachiyo", "--mixed", "0.0.0.0:18484"]).unwrap();
        let err = args.validate_security().unwrap_err();
        assert_eq!(
            err,
            ArgsError::NonLoopbackAddressForbidden {
                flag: "mixed",
                addr: "0.0.0.0:18484".parse().unwrap(),
            }
        );
    }

    #[test]
    fn test_security_rejects_unspecified_ipv6_without_allow_lan() {
        let args = CliArgs::try_parse_from(["yachiyo", "--http", "[::]:8080"]).unwrap();
        let err = args.validate_security().unwrap_err();
        assert_eq!(
            err,
            ArgsError::NonLoopbackAddressForbidden {
                flag: "http",
                addr: "[::]:8080".parse().unwrap(),
            }
        );
    }

    #[test]
    fn test_security_rejects_lan_ip_without_allow_lan() {
        let args = CliArgs::try_parse_from(["yachiyo", "--socks", "192.168.1.100:1080"]).unwrap();
        let err = args.validate_security().unwrap_err();
        assert_eq!(
            err,
            ArgsError::NonLoopbackAddressForbidden {
                flag: "socks",
                addr: "192.168.1.100:1080".parse().unwrap(),
            }
        );
    }

    #[test]
    fn test_security_allows_non_loopback_with_allow_lan() {
        let args = CliArgs::try_parse_from(["yachiyo", "--mixed", "0.0.0.0:18484", "--allow-lan"])
            .unwrap();
        assert!(args.validate_security().is_ok());

        let cfg = args.to_inbound_config().unwrap();
        assert_eq!(cfg.mixed_addr, Some("0.0.0.0:18484".parse().unwrap()));
    }

    #[test]
    fn test_security_allows_ipv6_loopback() {
        let args = CliArgs::try_parse_from(["yachiyo", "--mixed", "[::1]:18484"]).unwrap();
        assert!(args.validate_security().is_ok());
    }

    #[test]
    fn test_security_allows_ipv4_mapped_ipv6_loopback() {
        let args =
            CliArgs::try_parse_from(["yachiyo", "--mixed", "[::ffff:127.0.0.1]:18484"]).unwrap();
        assert!(args.validate_security().is_ok());
    }

    #[test]
    fn test_custom_log_level() {
        let args = CliArgs::try_parse_from(["yachiyo", "--log-level", "debug"]).unwrap();
        assert_eq!(args.log_level, "debug");
    }

    #[test]
    fn test_invalid_socket_addr_syntax_fails_clap() {
        let res = CliArgs::try_parse_from(["yachiyo", "--mixed", "invalid_address"]);
        assert!(res.is_err());
    }

    #[test]
    fn test_to_inbound_config_populates_timeouts() {
        let args = CliArgs::try_parse_from(["yachiyo"]).unwrap();
        let config = args.to_inbound_config().unwrap();
        assert_eq!(config.handshake_timeout, Duration::from_secs(10));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.idle_timeout, Duration::from_secs(300));
        assert_eq!(config.mixed_addr, Some(DEFAULT_MIXED_SOCKET_ADDR));
        assert_eq!(args.max_connections, 1024);
    }

    #[test]
    fn test_custom_timeouts_and_max_connections() {
        let args = CliArgs::try_parse_from([
            "yachiyo",
            "--handshake-timeout",
            "5",
            "--connect-timeout",
            "7",
            "--idle-timeout",
            "120",
            "--max-connections",
            "512",
        ])
        .unwrap();

        assert_eq!(args.handshake_timeout, 5);
        assert_eq!(args.connect_timeout, 7);
        assert_eq!(args.idle_timeout, 120);
        assert_eq!(args.max_connections, 512);

        let config = args.to_inbound_config().unwrap();
        assert_eq!(config.handshake_timeout, Duration::from_secs(5));
        assert_eq!(config.connect_timeout, Duration::from_secs(7));
        assert_eq!(config.idle_timeout, Duration::from_secs(120));
    }
}
