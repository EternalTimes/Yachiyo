// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned native YAML configuration schema and semantic validation.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::address::TargetAddr;
use crate::group::{
    FallbackGroup, OutboundRegistry, OutboundTarget, SelectorGroup, UrlTestGroup,
    parse_http_probe_url,
};
use crate::rule::{Policy, Rule, RuleError, RuleSet};
use crate::socks5_outbound::{Socks5Auth, Socks5OutboundConfig};

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

    #[error("outbound name '{name}' is reserved for built-in policy")]
    ReservedOutboundName { name: String },

    #[error("invalid outbound '{name}': {reason}")]
    InvalidOutbound { name: String, reason: String },

    #[error("rule at index {index} references undefined outbound '{name}'")]
    UnknownOutboundReference { index: usize, name: String },
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
    #[serde(default)]
    outbounds: BTreeMap<String, RawOutboundConfig>,
    rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum RawOutboundConfig {
    Socks5 {
        server: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Trojan {
        server: String,
        password: String,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        alpn: Vec<String>,
        #[serde(default)]
        skip_cert_verify: bool,
    },
    Selector {
        outbounds: Vec<String>,
        #[serde(default)]
        selected: Option<String>,
    },
    UrlTest {
        outbounds: Vec<String>,
        #[serde(default = "default_health_check_url")]
        url: String,
        #[serde(default = "default_interval_secs")]
        interval_secs: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
        #[serde(default = "default_tolerance_ms")]
        tolerance_ms: u64,
    },
    Fallback {
        outbounds: Vec<String>,
        #[serde(default = "default_health_check_url")]
        url: String,
        #[serde(default = "default_interval_secs")]
        interval_secs: u64,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },
}

fn default_health_check_url() -> String {
    crate::group::DEFAULT_HEALTH_CHECK_URL.to_string()
}

fn default_interval_secs() -> u64 {
    crate::group::DEFAULT_HEALTH_CHECK_INTERVAL.as_secs()
}

fn default_timeout_secs() -> u64 {
    crate::group::DEFAULT_HEALTH_CHECK_TIMEOUT.as_secs()
}

fn default_tolerance_ms() -> u64 {
    crate::group::DEFAULT_URL_TEST_TOLERANCE.as_millis() as u64
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
    pub outbounds: OutboundRegistry,
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

        // 1. Pre-validate outbound names
        let all_outbound_names: HashSet<String> = raw.outbounds.keys().cloned().collect();
        for name in &all_outbound_names {
            if name.eq_ignore_ascii_case("DIRECT") || name.eq_ignore_ascii_case("REJECT") {
                return Err(ConfigError::ReservedOutboundName { name: name.clone() });
            }
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(ConfigError::InvalidOutbound {
                    name: name.clone(),
                    reason: "outbound name must consist of ASCII alphanumeric, '-' or '_'"
                        .to_string(),
                });
            }
        }

        // 2. Validate outbound candidate references and build graph for cycle detection
        let mut group_graph: HashMap<String, Vec<String>> = HashMap::new();
        for (name, raw_out) in &raw.outbounds {
            let candidates = match raw_out {
                RawOutboundConfig::Socks5 { .. } | RawOutboundConfig::Trojan { .. } => {
                    continue;
                }
                RawOutboundConfig::Selector { outbounds, .. }
                | RawOutboundConfig::UrlTest { outbounds, .. }
                | RawOutboundConfig::Fallback { outbounds, .. } => outbounds,
            };

            if candidates.is_empty() {
                return Err(ConfigError::InvalidOutbound {
                    name: name.clone(),
                    reason: "outbounds list cannot be empty".to_string(),
                });
            }

            let mut group_targets = Vec::new();
            for target in candidates {
                if target == name {
                    return Err(ConfigError::InvalidOutbound {
                        name: name.clone(),
                        reason: "group cannot reference itself".to_string(),
                    });
                }
                if target.eq_ignore_ascii_case("DIRECT") || target.eq_ignore_ascii_case("REJECT") {
                    continue;
                }
                if !all_outbound_names.contains(target) {
                    return Err(ConfigError::InvalidOutbound {
                        name: name.clone(),
                        reason: format!("references undefined outbound '{target}'"),
                    });
                }
                group_targets.push(target.clone());
            }
            group_graph.insert(name.clone(), group_targets);
        }

        // 3. Detect cycles among outbound groups via DFS
        {
            fn dfs_cycle(
                node: &str,
                graph: &HashMap<String, Vec<String>>,
                visited: &mut HashSet<String>,
                on_stack: &mut HashSet<String>,
                path: &mut Vec<String>,
            ) -> Result<(), ConfigError> {
                visited.insert(node.to_string());
                on_stack.insert(node.to_string());
                path.push(node.to_string());

                if let Some(neighbors) = graph.get(node) {
                    for neighbor in neighbors {
                        if on_stack.contains(neighbor) {
                            path.push(neighbor.clone());
                            let cycle_str = path.join(" -> ");
                            return Err(ConfigError::InvalidOutbound {
                                name: node.to_string(),
                                reason: format!(
                                    "circular dependency detected in outbound groups: {cycle_str}"
                                ),
                            });
                        }
                        if !visited.contains(neighbor) {
                            dfs_cycle(neighbor, graph, visited, on_stack, path)?;
                        }
                    }
                }

                path.pop();
                on_stack.remove(node);
                Ok(())
            }

            let mut visited = HashSet::new();
            let mut on_stack = HashSet::new();
            let mut path = Vec::new();
            for group_name in group_graph.keys() {
                if !visited.contains(group_name) {
                    dfs_cycle(
                        group_name,
                        &group_graph,
                        &mut visited,
                        &mut on_stack,
                        &mut path,
                    )?;
                }
            }
        }

        // 4. Construct outbound registry entries
        let mut outbounds = OutboundRegistry::new();
        for (name, raw_out) in raw.outbounds {
            match raw_out {
                RawOutboundConfig::Socks5 {
                    server,
                    username,
                    password,
                } => {
                    let server_addr: TargetAddr =
                        server.parse().map_err(|e| ConfigError::InvalidOutbound {
                            name: name.clone(),
                            reason: format!("invalid server address '{server}': {e}"),
                        })?;
                    if server_addr.port == 0 {
                        return Err(ConfigError::InvalidOutbound {
                            name,
                            reason: "server port cannot be 0".to_string(),
                        });
                    }
                    let auth = match (username, password) {
                        (None, None) => Socks5Auth::None,
                        (Some(u), Some(p)) => {
                            if u.is_empty() || u.len() > 255 || p.is_empty() || p.len() > 255 {
                                return Err(ConfigError::InvalidOutbound {
                                    name,
                                    reason:
                                        "SOCKS5 username and password must each be 1..=255 bytes"
                                            .to_string(),
                                });
                            }
                            Socks5Auth::UsernamePassword {
                                username: u,
                                password: p,
                            }
                        }
                        _ => {
                            return Err(ConfigError::InvalidOutbound {
                                name,
                                reason: "username and password must both be specified together"
                                    .to_string(),
                            });
                        }
                    };
                    outbounds.insert(
                        name,
                        OutboundTarget::Socks5(Socks5OutboundConfig {
                            server: server_addr,
                            auth,
                        }),
                    );
                }
                RawOutboundConfig::Trojan {
                    server,
                    password,
                    sni,
                    alpn,
                    skip_cert_verify,
                } => {
                    let server_addr: TargetAddr =
                        server.parse().map_err(|e| ConfigError::InvalidOutbound {
                            name: name.clone(),
                            reason: format!("invalid server address '{server}': {e}"),
                        })?;
                    if server_addr.port == 0 {
                        return Err(ConfigError::InvalidOutbound {
                            name,
                            reason: "server port cannot be 0".to_string(),
                        });
                    }
                    if password.is_empty() {
                        return Err(ConfigError::InvalidOutbound {
                            name,
                            reason: "password cannot be empty".to_string(),
                        });
                    }
                    if let Some(ref s) = sni {
                        if s.is_empty() {
                            return Err(ConfigError::InvalidOutbound {
                                name,
                                reason: "sni cannot be empty if specified".to_string(),
                            });
                        }
                    }
                    let alpn = if alpn.is_empty() {
                        vec!["h2".to_string(), "http/1.1".to_string()]
                    } else {
                        alpn
                    };
                    let sha224_hex = crate::trojan::sha224_hex_bytes(password.as_bytes());
                    let tls_config =
                        crate::trojan::build_tls_client_config(&alpn, skip_cert_verify).map_err(
                            |e| ConfigError::InvalidOutbound {
                                name: name.clone(),
                                reason: format!("failed to build TLS client configuration: {e}"),
                            },
                        )?;

                    outbounds.insert(
                        name,
                        OutboundTarget::Trojan(crate::trojan::TrojanOutboundConfig {
                            server: server_addr,
                            password,
                            sha224_hex,
                            sni,
                            alpn,
                            skip_cert_verify,
                            tls_config,
                        }),
                    );
                }
                RawOutboundConfig::Selector {
                    outbounds: candidates,
                    selected,
                } => {
                    if let Some(ref sel) = selected {
                        if !candidates.contains(sel) {
                            return Err(ConfigError::InvalidOutbound {
                                name: name.clone(),
                                reason: format!(
                                    "selected outbound '{sel}' is not present in outbounds list"
                                ),
                            });
                        }
                    }
                    let group = SelectorGroup::new(name.clone(), candidates, selected);
                    outbounds.insert(name, OutboundTarget::Selector(std::sync::Arc::new(group)));
                }
                RawOutboundConfig::UrlTest {
                    outbounds: candidates,
                    url,
                    interval_secs,
                    timeout_secs,
                    tolerance_ms,
                } => {
                    if interval_secs == 0 {
                        return Err(ConfigError::InvalidOutbound {
                            name: name.clone(),
                            reason: "interval_secs must be greater than 0".to_string(),
                        });
                    }
                    if timeout_secs == 0 {
                        return Err(ConfigError::InvalidOutbound {
                            name: name.clone(),
                            reason: "timeout_secs must be greater than 0".to_string(),
                        });
                    }
                    parse_http_probe_url(&url).map_err(|e| ConfigError::InvalidOutbound {
                        name: name.clone(),
                        reason: format!("invalid health check url: {e}"),
                    })?;
                    let group = UrlTestGroup::new(
                        name.clone(),
                        candidates,
                        url,
                        Duration::from_secs(interval_secs),
                        Duration::from_secs(timeout_secs),
                        Duration::from_millis(tolerance_ms),
                    );
                    outbounds.insert(name, OutboundTarget::UrlTest(std::sync::Arc::new(group)));
                }
                RawOutboundConfig::Fallback {
                    outbounds: candidates,
                    url,
                    interval_secs,
                    timeout_secs,
                } => {
                    if interval_secs == 0 {
                        return Err(ConfigError::InvalidOutbound {
                            name: name.clone(),
                            reason: "interval_secs must be greater than 0".to_string(),
                        });
                    }
                    if timeout_secs == 0 {
                        return Err(ConfigError::InvalidOutbound {
                            name: name.clone(),
                            reason: "timeout_secs must be greater than 0".to_string(),
                        });
                    }
                    parse_http_probe_url(&url).map_err(|e| ConfigError::InvalidOutbound {
                        name: name.clone(),
                        reason: format!("invalid health check url: {e}"),
                    })?;
                    let group = FallbackGroup::new(
                        name.clone(),
                        candidates,
                        url,
                        Duration::from_secs(interval_secs),
                        Duration::from_secs(timeout_secs),
                    );
                    outbounds.insert(name, OutboundTarget::Fallback(std::sync::Arc::new(group)));
                }
            }
        }

        let mut parsed_rules = Vec::with_capacity(raw.rules.len());
        for (index, line) in raw.rules.iter().enumerate() {
            let rule =
                Rule::parse(line).map_err(|source| ConfigError::InvalidRule { index, source })?;
            if let Policy::Outbound(ref out_name) = *rule.policy() {
                if !outbounds.contains(out_name) {
                    return Err(ConfigError::UnknownOutboundReference {
                        index,
                        name: out_name.clone(),
                    });
                }
            }
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
            outbounds,
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
    use crate::group::ResolvedOutbound;

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

    #[test]
    fn test_socks5_outbound_config_and_reference_validation() {
        let yaml = r#"
schema_version: 1
outbounds:
  upstream:
    type: socks5
    server: 192.0.2.1:1080
    username: demo-user
    password: demo-password
rules:
  - DOMAIN-SUFFIX,example.com,upstream
  - MATCH,DIRECT
"#;
        let cfg = Config::from_yaml_str(yaml).unwrap();
        assert!(cfg.outbounds.contains("upstream"));

        let dangling = r#"
schema_version: 1
rules:
  - DOMAIN,example.com,missing-node
  - MATCH,DIRECT
"#;
        assert!(matches!(
            Config::from_yaml_str(dangling).unwrap_err(),
            ConfigError::UnknownOutboundReference { index: 0, .. }
        ));

        let reserved = r#"
schema_version: 1
outbounds:
  DIRECT:
    type: socks5
    server: 192.0.2.1:1080
rules:
  - MATCH,DIRECT
"#;
        assert!(matches!(
            Config::from_yaml_str(reserved).unwrap_err(),
            ConfigError::ReservedOutboundName { .. }
        ));

        let partial_auth = r#"
schema_version: 1
outbounds:
  upstream:
    type: socks5
    server: 192.0.2.1:1080
    username: only-user
rules:
  - MATCH,upstream
"#;
        assert!(matches!(
            Config::from_yaml_str(partial_auth).unwrap_err(),
            ConfigError::InvalidOutbound { .. }
        ));
    }

    #[test]
    fn test_outbound_groups_config_validation_and_resolution() {
        let valid_groups = r#"
schema_version: 1
outbounds:
  node_a:
    type: socks5
    server: 192.0.2.1:1080
  node_b:
    type: socks5
    server: 192.0.2.2:1080
  auto_test:
    type: url-test
    outbounds:
      - node_a
      - node_b
    url: http://cp.cloudflare.com/generate_204
    interval_secs: 180
    timeout_secs: 4
    tolerance_ms: 40
  fallback_group:
    type: fallback
    outbounds:
      - auto_test
      - DIRECT
  proxy_selector:
    type: selector
    outbounds:
      - fallback_group
      - node_a
      - DIRECT
    selected: fallback_group
rules:
  - MATCH,proxy_selector
"#;
        let cfg = Config::from_yaml_str(valid_groups).unwrap();
        assert!(cfg.outbounds.contains("proxy_selector"));
        assert!(cfg.outbounds.contains("fallback_group"));
        assert!(cfg.outbounds.contains("auto_test"));

        // Test resolution chain
        let (leaf, chain) = cfg.outbounds.resolve_with_chain("proxy_selector").unwrap();
        assert_eq!(chain[0], "proxy_selector");
        assert_eq!(chain[1], "fallback_group");
        assert_eq!(chain[2], "auto_test");
        assert_eq!(chain[3], "node_a");
        assert!(matches!(leaf, crate::group::ResolvedOutbound::Socks5(_)));

        // Test circular dependency rejection
        let circular = r#"
schema_version: 1
outbounds:
  group1:
    type: selector
    outbounds: [group2]
  group2:
    type: fallback
    outbounds: [group1]
rules:
  - MATCH,group1
"#;
        let err = Config::from_yaml_str(circular).unwrap_err();
        match err {
            ConfigError::InvalidOutbound { reason, .. } => {
                assert!(reason.contains("circular dependency detected"));
            }
            other => panic!("expected circular dependency error, got {other:?}"),
        }

        // Test self-reference rejection
        let self_ref = r#"
schema_version: 1
outbounds:
  self_loop:
    type: selector
    outbounds: [self_loop]
rules:
  - MATCH,self_loop
"#;
        let err = Config::from_yaml_str(self_ref).unwrap_err();
        match err {
            ConfigError::InvalidOutbound { reason, .. } => {
                assert!(reason.contains("group cannot reference itself"));
            }
            other => panic!("expected self-reference error, got {other:?}"),
        }

        // Test invalid selector 'selected' target
        let invalid_sel = r#"
schema_version: 1
outbounds:
  node:
    type: socks5
    server: 192.0.2.1:1080
  my_sel:
    type: selector
    outbounds: [node]
    selected: non_existent
rules:
  - MATCH,my_sel
"#;
        let err = Config::from_yaml_str(invalid_sel).unwrap_err();
        match err {
            ConfigError::InvalidOutbound { reason, .. } => {
                assert!(reason.contains("not present in outbounds list"));
            }
            other => panic!("expected selected not in list error, got {other:?}"),
        }
    }

    #[test]
    fn test_trojan_config_validation() {
        let valid = r#"
schema_version: 1
outbounds:
  trojan_node:
    type: trojan
    server: trojan.example.com:443
    password: my-trojan-password
    sni: custom.sni.example.com
    alpn: [h2]
    skip_cert_verify: true
rules:
  - MATCH,trojan_node
"#;
        let cfg = Config::from_yaml_str(valid).unwrap();
        match cfg.outbounds.get("trojan_node").unwrap() {
            OutboundTarget::Trojan(trojan) => {
                assert_eq!(trojan.server.to_string(), "trojan.example.com:443");
                assert_eq!(trojan.password, "my-trojan-password");
                assert_eq!(
                    trojan.sha224_hex,
                    crate::trojan::sha224_hex_bytes(b"my-trojan-password")
                );
                assert_eq!(trojan.sni.as_deref(), Some("custom.sni.example.com"));
                assert_eq!(trojan.alpn, vec!["h2".to_string()]);
                assert!(trojan.skip_cert_verify);
            }
            other => panic!("expected OutboundTarget::Trojan, got {other:?}"),
        }

        // Test default ALPN
        let default_alpn = r#"
schema_version: 1
outbounds:
  trojan_node:
    type: trojan
    server: 192.0.2.1:443
    password: secret
rules:
  - MATCH,trojan_node
"#;
        let cfg = Config::from_yaml_str(default_alpn).unwrap();
        match cfg.outbounds.get("trojan_node").unwrap() {
            OutboundTarget::Trojan(trojan) => {
                assert_eq!(trojan.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
                assert!(!trojan.skip_cert_verify);
                assert_eq!(trojan.sni, None);
            }
            other => panic!("expected OutboundTarget::Trojan, got {other:?}"),
        }

        // Empty password rejection
        let empty_pw = r#"
schema_version: 1
outbounds:
  trojan_node:
    type: trojan
    server: 192.0.2.1:443
    password: ""
rules:
  - MATCH,trojan_node
"#;
        let err = Config::from_yaml_str(empty_pw).unwrap_err();
        match err {
            ConfigError::InvalidOutbound { reason, .. } => {
                assert!(reason.contains("password cannot be empty"));
            }
            other => panic!("expected password cannot be empty, got {other:?}"),
        }

        // Port 0 rejection
        let port_0 = r#"
schema_version: 1
outbounds:
  trojan_node:
    type: trojan
    server: 192.0.2.1:0
    password: test
rules:
  - MATCH,trojan_node
"#;
        let err = Config::from_yaml_str(port_0).unwrap_err();
        match err {
            ConfigError::InvalidOutbound { reason, .. } => {
                assert!(reason.contains("server port cannot be 0"));
            }
            other => panic!("expected port 0 error, got {other:?}"),
        }

        // Empty SNI rejection
        let empty_sni = r#"
schema_version: 1
outbounds:
  trojan_node:
    type: trojan
    server: 192.0.2.1:443
    password: test
    sni: ""
rules:
  - MATCH,trojan_node
"#;
        let err = Config::from_yaml_str(empty_sni).unwrap_err();
        match err {
            ConfigError::InvalidOutbound { reason, .. } => {
                assert!(reason.contains("sni cannot be empty"));
            }
            other => panic!("expected empty sni error, got {other:?}"),
        }

        // Group referencing trojan node
        let group_ref = r#"
schema_version: 1
outbounds:
  trojan1:
    type: trojan
    server: 192.0.2.1:443
    password: test
  my_group:
    type: selector
    outbounds: [trojan1]
rules:
  - MATCH,my_group
"#;
        let cfg = Config::from_yaml_str(group_ref).unwrap();
        let (resolved, chain) = cfg.outbounds.resolve_with_chain("my_group").unwrap();
        assert_eq!(chain, vec!["my_group", "trojan1"]);
        match resolved {
            ResolvedOutbound::Trojan(t) => {
                assert_eq!(t.server.to_string(), "192.0.2.1:443");
            }
            other => panic!("expected ResolvedOutbound::Trojan, got {other:?}"),
        }
    }
}
