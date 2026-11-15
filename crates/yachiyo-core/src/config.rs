// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned native YAML configuration schema and semantic validation.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::rule::{Rule, RuleError, RuleSet};

/// Supported native configuration schema version.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Maximum permitted configuration file size (1 MiB).
pub const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

/// Maximum permitted number of rules in a single configuration.
pub const MAX_RULES: usize = 10_000;

/// Maximum permitted YAML nesting depth.
pub const MAX_YAML_DEPTH: usize = 16;

/// Default mixed listener address.
pub const DEFAULT_MIXED_ADDR: &str = "127.0.0.1:18484";

/// Errors returned when loading or validating a configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("config exceeds maximum size of {MAX_CONFIG_FILE_BYTES} bytes (got {size} bytes)")]
    FileTooLarge { size: u64 },

    #[error("YAML alias/anchor syntax is prohibited for safety (line {line})")]
    ProhibitedYamlAlias { line: usize },

    #[error("YAML nesting depth exceeds maximum of {MAX_YAML_DEPTH}")]
    ExcessiveNesting,

    #[error("invalid YAML syntax or unknown field: {0}")]
    YamlParse(#[from] serde_yml::Error),

    #[error("unsupported schema_version {found} (expected {CURRENT_SCHEMA_VERSION})")]
    UnsupportedSchemaVersion { found: u32 },

    #[error("non-loopback bind address '{addr}' requires listeners.allow_lan: true")]
    NonLoopbackWithoutAllowLan { addr: SocketAddr },

    #[error("duplicate listener address configured: {addr}")]
    DuplicateListenerAddr { addr: SocketAddr },

    #[error("invalid timeout '{field}': must be greater than 0 seconds")]
    ZeroTimeout { field: &'static str },

    #[error("invalid limits.max_connections: must be greater than 0")]
    ZeroMaxConnections,

    #[error("rules count {count} exceeds maximum of {MAX_RULES}")]
    TooManyRules { count: usize },

    #[error("invalid rule at index {index}: {source}")]
    InvalidRule {
        index: usize,
        #[source]
        source: RuleError,
    },

    #[error("invalid ruleset: {0}")]
    InvalidRuleSet(#[from] RuleError),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: u32,
    #[serde(default)]
    listeners: RawListenersConfig,
    #[serde(default)]
    timeouts: RawTimeoutsConfig,
    #[serde(default)]
    limits: RawLimitsConfig,
    #[serde(default)]
    logging: RawLoggingConfig,
    rules: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListenersConfig {
    mixed: Option<SocketAddr>,
    socks: Option<SocketAddr>,
    http: Option<SocketAddr>,
    #[serde(default)]
    allow_lan: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTimeoutsConfig {
    #[serde(default = "default_handshake_secs")]
    handshake_secs: u64,
    #[serde(default = "default_connect_secs")]
    connect_secs: u64,
    #[serde(default = "default_idle_secs")]
    idle_secs: u64,
    #[serde(default = "default_drain_secs")]
    drain_secs: u64,
}

impl Default for RawTimeoutsConfig {
    fn default() -> Self {
        Self {
            handshake_secs: default_handshake_secs(),
            connect_secs: default_connect_secs(),
            idle_secs: default_idle_secs(),
            drain_secs: default_drain_secs(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimitsConfig {
    #[serde(default = "default_max_connections")]
    max_connections: usize,
}

impl Default for RawLimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLoggingConfig {
    #[serde(default = "default_log_level")]
    level: String,
}

impl Default for RawLoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_handshake_secs() -> u64 {
    10
}
fn default_connect_secs() -> u64 {
    10
}
fn default_idle_secs() -> u64 {
    300
}
fn default_drain_secs() -> u64 {
    5
}
fn default_max_connections() -> usize {
    1024
}
fn default_log_level() -> String {
    "info".to_string()
}

/// Validated listener configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenersConfig {
    pub mixed: Option<SocketAddr>,
    pub socks: Option<SocketAddr>,
    pub http: Option<SocketAddr>,
    pub allow_lan: bool,
}

/// Validated timeout configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutsConfig {
    pub handshake: Duration,
    pub connect: Duration,
    pub idle: Duration,
    pub drain: Duration,
}

/// Validated concurrency limit configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitsConfig {
    pub max_connections: usize,
}

/// Validated logging configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    pub level: String,
}

/// Fully parsed and semantically validated native configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub schema_version: u32,
    pub listeners: ListenersConfig,
    pub timeouts: TimeoutsConfig,
    pub limits: LimitsConfig,
    pub logging: LoggingConfig,
    pub rules: RuleSet,
}

impl Config {
    /// Loads and validates a YAML configuration from disk.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let meta = std::fs::metadata(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;

        if meta.len() > MAX_CONFIG_FILE_BYTES {
            return Err(ConfigError::FileTooLarge { size: meta.len() });
        }

        let content = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;

        Self::from_yaml_str(&content)
    }

    /// Parses and semantically validates a YAML configuration string.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, ConfigError> {
        if yaml.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(ConfigError::FileTooLarge {
                size: yaml.len() as u64,
            });
        }

        // Pre-parse safety guard: inspect into generic Value first to enforce nesting depth
        // and reject anchors/aliases without executing any custom tags.
        check_yaml_aliases(yaml)?;
        let value: serde_yml::Value = serde_yml::from_str(yaml)?;
        check_yaml_depth(&value, 1)?;

        let raw: RawConfig = serde_yml::from_value(value)?;

        if raw.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchemaVersion {
                found: raw.schema_version,
            });
        }

        // Resolve default mixed listener when none of mixed/socks/http is specified.
        let mixed = if raw.listeners.mixed.is_none()
            && raw.listeners.socks.is_none()
            && raw.listeners.http.is_none()
        {
            Some(
                DEFAULT_MIXED_ADDR
                    .parse::<SocketAddr>()
                    .expect("default mixed addr is valid"),
            )
        } else {
            raw.listeners.mixed
        };

        let mut seen_addrs = HashSet::new();
        for addr in [mixed, raw.listeners.socks, raw.listeners.http]
            .into_iter()
            .flatten()
        {
            if !seen_addrs.insert(addr) {
                return Err(ConfigError::DuplicateListenerAddr { addr });
            }
            if !raw.listeners.allow_lan && !is_loopback_socket_addr(addr) {
                return Err(ConfigError::NonLoopbackWithoutAllowLan { addr });
            }
        }

        if raw.timeouts.handshake_secs == 0 {
            return Err(ConfigError::ZeroTimeout {
                field: "handshake_secs",
            });
        }
        if raw.timeouts.connect_secs == 0 {
            return Err(ConfigError::ZeroTimeout {
                field: "connect_secs",
            });
        }
        if raw.timeouts.idle_secs == 0 {
            return Err(ConfigError::ZeroTimeout { field: "idle_secs" });
        }
        if raw.timeouts.drain_secs == 0 {
            return Err(ConfigError::ZeroTimeout {
                field: "drain_secs",
            });
        }

        if raw.limits.max_connections == 0 {
            return Err(ConfigError::ZeroMaxConnections);
        }

        if raw.rules.len() > MAX_RULES {
            return Err(ConfigError::TooManyRules {
                count: raw.rules.len(),
            });
        }

        let mut parsed_rules = Vec::with_capacity(raw.rules.len());
        for (index, line) in raw.rules.iter().enumerate() {
            let rule =
                Rule::parse(line).map_err(|source| ConfigError::InvalidRule { index, source })?;
            parsed_rules.push(rule);
        }
        let rules = RuleSet::new(parsed_rules)?;

        Ok(Self {
            schema_version: raw.schema_version,
            listeners: ListenersConfig {
                mixed,
                socks: raw.listeners.socks,
                http: raw.listeners.http,
                allow_lan: raw.listeners.allow_lan,
            },
            timeouts: TimeoutsConfig {
                handshake: Duration::from_secs(raw.timeouts.handshake_secs),
                connect: Duration::from_secs(raw.timeouts.connect_secs),
                idle: Duration::from_secs(raw.timeouts.idle_secs),
                drain: Duration::from_secs(raw.timeouts.drain_secs),
            },
            limits: LimitsConfig {
                max_connections: raw.limits.max_connections,
            },
            logging: LoggingConfig {
                level: raw.logging.level,
            },
            rules,
        })
    }
}

/// Returns `true` if `addr` is a loopback address (IPv4 `127.0.0.0/8`, IPv6 `::1`,
/// or IPv4-mapped IPv6 `::ffff:127.0.0.0/8`).
pub fn is_loopback_socket_addr(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Scans unquoted YAML tokens for `&anchor` / `*alias` markers to prevent billion-laughs
/// alias expansion attacks.
fn check_yaml_aliases(yaml: &str) -> Result<(), ConfigError> {
    for (idx, line) in yaml.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let mut in_single = false;
        let mut in_double = false;
        let mut escaped = false;
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            if in_double {
                if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    in_double = false;
                }
                i += 1;
                continue;
            }
            if in_single {
                if b == b'\'' {
                    in_single = false;
                }
                i += 1;
                continue;
            }
            match b {
                b'#' => break,
                b'"' => in_double = true,
                b'\'' => in_single = true,
                b'&' | b'*' => {
                    let prev_ok =
                        i == 0 || bytes[i - 1].is_ascii_whitespace() || bytes[i - 1] == b':';
                    let next_ok = i + 1 < bytes.len() && !bytes[i + 1].is_ascii_whitespace();
                    if prev_ok && next_ok {
                        return Err(ConfigError::ProhibitedYamlAlias { line: idx + 1 });
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    Ok(())
}

fn check_yaml_depth(value: &serde_yml::Value, depth: usize) -> Result<(), ConfigError> {
    if depth > MAX_YAML_DEPTH {
        return Err(ConfigError::ExcessiveNesting);
    }
    match value {
        serde_yml::Value::Sequence(seq) => {
            for item in seq {
                check_yaml_depth(item, depth + 1)?;
            }
        }
        serde_yml::Value::Mapping(map) => {
            for (_, v) in map {
                check_yaml_depth(v, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_minimal_config_uses_safe_defaults() {
        let yaml = r#"
schema_version: 1
rules:
  - DOMAIN,ads.example.com,REJECT
  - MATCH,DIRECT
"#;
        let cfg = Config::from_yaml_str(yaml).unwrap();
        assert_eq!(cfg.schema_version, 1);
        assert_eq!(
            cfg.listeners.mixed,
            Some("127.0.0.1:18484".parse().unwrap())
        );
        assert!(!cfg.listeners.allow_lan);
        assert_eq!(cfg.timeouts.handshake, Duration::from_secs(10));
        assert_eq!(cfg.timeouts.connect, Duration::from_secs(10));
        assert_eq!(cfg.timeouts.idle, Duration::from_secs(300));
        assert_eq!(cfg.timeouts.drain, Duration::from_secs(5));
        assert_eq!(cfg.limits.max_connections, 1024);
        assert_eq!(cfg.logging.level, "info");
        assert_eq!(cfg.rules.rules().len(), 2);
    }

    #[test]
    fn test_unknown_field_is_rejected_never_silently_ignored() {
        let yaml = r#"
schema_version: 1
unknown_top_level: true
rules:
  - MATCH,DIRECT
"#;
        let err = Config::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(err, ConfigError::YamlParse(_)));
    }

    #[test]
    fn test_unsupported_schema_version_is_rejected() {
        let yaml = r#"
schema_version: 99
rules:
  - MATCH,DIRECT
"#;
        let err = Config::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::UnsupportedSchemaVersion { found: 99 }
        ));
    }

    #[test]
    fn test_non_loopback_listener_requires_allow_lan() {
        let yaml = r#"
schema_version: 1
listeners:
  mixed: 0.0.0.0:18484
rules:
  - MATCH,DIRECT
"#;
        let err = Config::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::NonLoopbackWithoutAllowLan { .. }
        ));
    }

    #[test]
    fn test_duplicate_listener_addr_is_rejected() {
        let yaml = r#"
schema_version: 1
listeners:
  mixed: 127.0.0.1:18484
  socks: 127.0.0.1:18484
rules:
  - MATCH,DIRECT
"#;
        let err = Config::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateListenerAddr { .. }));
    }

    #[test]
    fn test_yaml_alias_is_prohibited() {
        let yaml = r#"
schema_version: 1
logging:
  level: &lvl info
rules:
  - MATCH,DIRECT
"#;
        let err = Config::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(err, ConfigError::ProhibitedYamlAlias { .. }));
    }

    #[test]
    fn test_missing_final_match_rule_is_rejected() {
        let yaml = r#"
schema_version: 1
rules:
  - DOMAIN,example.com,REJECT
"#;
        let err = Config::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidRuleSet(RuleError::MissingFinalMatch)
        ));
    }
}
