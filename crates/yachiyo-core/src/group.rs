// SPDX-License-Identifier: AGPL-3.0-only

//! Outbound selection groups (`Selector`, `UrlTest`, `Fallback`) and active health checking.
//!
//! Provides:
//! - [`SelectorGroup`]: Manual or statically configured outbound choice among candidates.
//! - [`UrlTestGroup`]: Automated choice of lowest-latency healthy outbound within a tolerance margin.
//! - [`FallbackGroup`]: Priority-ordered selection of first healthy candidate.
//! - [`OutboundRegistry`]: Maps named outbound policies and resolves group references to concrete dial targets.
//! - Background health check probe runner measuring RTT via minimal HTTP probes.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;
use tracing::debug;

use crate::address::TargetAddr;
use crate::forward::OutboundStream;
use crate::outbound::DirectDialer;
use crate::socks5_outbound::{Socks5Dialer, Socks5OutboundConfig};
use crate::trojan::{TrojanDialer, TrojanOutboundConfig};

/// Default health check URL for URL-test and fallback groups (Cloudflare 204 endpoint).
pub const DEFAULT_HEALTH_CHECK_URL: &str = "http://cp.cloudflare.com/generate_204";

/// Default health check probing interval: 300 seconds (5 minutes).
pub const DEFAULT_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(300);

/// Default probe timeout: 5 seconds.
pub const DEFAULT_HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Default tolerance threshold for URL-test: 50 milliseconds.
pub const DEFAULT_URL_TEST_TOLERANCE: Duration = Duration::from_millis(50);

/// Error encountered during outbound reference resolution.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OutboundResolveError {
    #[error("outbound '{name}' not found (chain: {chain:?})")]
    NotFound { name: String, chain: Vec<String> },

    #[error("outbound resolution exceeded recursion limit (chain: {chain:?})")]
    RecursionLimitExceeded { chain: Vec<String> },
}

/// Errors returned during outbound health check probing.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("probe url error: {0}")]
    InvalidUrl(String),

    #[error("i/o error during probe: {0}")]
    Io(#[from] io::Error),

    #[error("probe timed out")]
    TimedOut,

    #[error("empty response from probe target")]
    EmptyResponse,

    #[error("invalid HTTP response format")]
    InvalidResponse,

    #[error("HTTP status {0} indicates unhealthy endpoint")]
    HttpStatus(u16),

    #[error("cannot probe REJECT target")]
    Rejected,
}

/// Recorded health and latency statistics for an outbound candidate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeHealth {
    /// Round-trip time in milliseconds recorded by the most recent check.
    pub latency_ms: Option<u64>,
    /// Timestamp of the last check.
    #[serde(skip)]
    pub last_checked: Option<Instant>,
    /// Whether the endpoint is considered available.
    pub healthy: bool,
}

impl Default for NodeHealth {
    fn default() -> Self {
        Self {
            latency_ms: None,
            last_checked: None,
            healthy: true, // Optimistically healthy until proven otherwise
        }
    }
}

/// Diagnostic health and status report for an outbound node or group.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeHealthReport {
    /// Type of outbound: "direct", "reject", "socks5", "selector", "url-test", "fallback".
    pub node_type: String,
    /// Whether the node or group is considered available.
    pub healthy: bool,
    /// Round-trip latency in milliseconds if tested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// Seconds elapsed since the last health probe check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_checked_secs_ago: Option<u64>,
    /// Active selected candidate if this is a group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<String>,
    /// Candidate outbound names if this is a group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<Vec<String>>,
    /// Remote server target address if this is a proxy dialer node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

impl NodeHealthReport {
    /// Formats the report as a JSON object fragment.
    pub fn to_json(&self) -> String {
        let mut fields = Vec::new();
        fields.push(format!(
            r#""node_type":"{}""#,
            crate::diagnostics::escape_json(&self.node_type)
        ));
        fields.push(format!(r#""healthy":{}"#, self.healthy));
        if let Some(latency) = self.latency_ms {
            fields.push(format!(r#""latency_ms":{latency}"#));
        }
        if let Some(secs) = self.last_checked_secs_ago {
            fields.push(format!(r#""last_checked_secs_ago":{secs}"#));
        }
        if let Some(ref sel) = self.selected {
            fields.push(format!(
                r#""selected":"{}""#,
                crate::diagnostics::escape_json(sel)
            ));
        }
        if let Some(ref cands) = self.candidates {
            let list = cands
                .iter()
                .map(|c| format!(r#""{}""#, crate::diagnostics::escape_json(c)))
                .collect::<Vec<_>>()
                .join(",");
            fields.push(format!(r#""candidates":[{list}]"#));
        }
        if let Some(ref srv) = self.server {
            fields.push(format!(
                r#""server":"{}""#,
                crate::diagnostics::escape_json(srv)
            ));
        }
        format!("{{{}}}", fields.join(","))
    }
}

/// Manual or configured choice outbound group (`type: selector`).
#[derive(Debug)]
pub struct SelectorGroup {
    pub name: String,
    pub candidates: Vec<String>,
    selected: Arc<RwLock<String>>,
}

impl SelectorGroup {
    /// Creates a new selector group defaulting to `selected` or the first candidate.
    pub fn new(name: String, candidates: Vec<String>, initial_selection: Option<String>) -> Self {
        let initial = initial_selection
            .filter(|s| candidates.contains(s))
            .or_else(|| candidates.first().cloned())
            .unwrap_or_default();

        Self {
            name,
            candidates,
            selected: Arc::new(RwLock::new(initial)),
        }
    }

    /// Returns the currently active selected outbound name.
    pub fn select(&self) -> String {
        self.selected.read().unwrap().clone()
    }

    /// Switches the active outbound to `target`, returning an error if not in `candidates`.
    pub fn set_selected(&self, target: &str) -> Result<(), String> {
        if !self.candidates.iter().any(|c| c == target) {
            return Err(format!(
                "target '{target}' is not a candidate in selector group '{}'",
                self.name
            ));
        }
        *self.selected.write().unwrap() = target.to_string();
        Ok(())
    }
}

impl PartialEq for SelectorGroup {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.candidates == other.candidates
            && self.select() == other.select()
    }
}
impl Eq for SelectorGroup {}

/// Automated lowest-latency selection group (`type: url-test`).
#[derive(Debug)]
pub struct UrlTestGroup {
    pub name: String,
    pub candidates: Vec<String>,
    pub url: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub tolerance: Duration,
    current_selected: Arc<RwLock<Option<String>>>,
    health_records: Arc<RwLock<HashMap<String, NodeHealth>>>,
}

impl UrlTestGroup {
    /// Creates a new URL-test group.
    pub fn new(
        name: String,
        candidates: Vec<String>,
        url: String,
        interval: Duration,
        timeout: Duration,
        tolerance: Duration,
    ) -> Self {
        let mut health_map = HashMap::new();
        for c in &candidates {
            health_map.insert(c.clone(), NodeHealth::default());
        }

        Self {
            name,
            candidates,
            url,
            interval,
            timeout,
            tolerance,
            current_selected: Arc::new(RwLock::new(None)),
            health_records: Arc::new(RwLock::new(health_map)),
        }
    }

    /// Evaluates the candidate with the lowest latency, applying tolerance hysteresis to prevent flap.
    pub fn select(&self) -> String {
        let healths = self.health_records.read().unwrap();

        let mut available = Vec::new();
        for name in &self.candidates {
            if let Some(record) = healths.get(name) {
                if record.healthy {
                    if let Some(lat) = record.latency_ms {
                        available.push((name.clone(), lat));
                    }
                }
            }
        }

        if available.is_empty() {
            return self.candidates.first().cloned().unwrap_or_default();
        }

        available.sort_by_key(|(_, lat)| *lat);
        let (best_name, best_lat) = &available[0];

        let mut curr_guard = self.current_selected.write().unwrap();
        if let Some(ref curr) = *curr_guard {
            if let Some((_, curr_lat)) = available.iter().find(|(name, _)| name == curr) {
                if curr_lat.saturating_sub(*best_lat) <= self.tolerance.as_millis() as u64 {
                    return curr.clone();
                }
            }
        }

        *curr_guard = Some(best_name.clone());
        best_name.clone()
    }

    /// Updates the health record for a candidate.
    pub fn update_health(&self, candidate: &str, result: Result<Duration, &ProbeError>) {
        let mut healths = self.health_records.write().unwrap();
        let record = healths.entry(candidate.to_string()).or_default();
        record.last_checked = Some(Instant::now());
        match result {
            Ok(lat) => {
                record.healthy = true;
                record.latency_ms = Some(lat.as_millis() as u64);
            }
            Err(_) => {
                record.healthy = false;
                record.latency_ms = None;
            }
        }
    }

    /// Returns a snapshot of candidate health statistics.
    pub fn health_snapshot(&self) -> HashMap<String, NodeHealth> {
        self.health_records.read().unwrap().clone()
    }
}

impl PartialEq for UrlTestGroup {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.candidates == other.candidates
            && self.url == other.url
            && self.interval == other.interval
            && self.timeout == other.timeout
            && self.tolerance == other.tolerance
    }
}
impl Eq for UrlTestGroup {}

/// Priority-ordered fallback group (`type: fallback`).
#[derive(Debug)]
pub struct FallbackGroup {
    pub name: String,
    pub candidates: Vec<String>,
    pub url: String,
    pub interval: Duration,
    pub timeout: Duration,
    health_records: Arc<RwLock<HashMap<String, NodeHealth>>>,
}

impl FallbackGroup {
    /// Creates a new fallback group.
    pub fn new(
        name: String,
        candidates: Vec<String>,
        url: String,
        interval: Duration,
        timeout: Duration,
    ) -> Self {
        let mut health_map = HashMap::new();
        for c in &candidates {
            health_map.insert(c.clone(), NodeHealth::default());
        }

        Self {
            name,
            candidates,
            url,
            interval,
            timeout,
            health_records: Arc::new(RwLock::new(health_map)),
        }
    }

    /// Selects the first candidate in priority order that is currently healthy.
    pub fn select(&self) -> String {
        let healths = self.health_records.read().unwrap();
        for name in &self.candidates {
            if let Some(record) = healths.get(name) {
                if record.healthy {
                    return name.clone();
                }
            }
        }
        self.candidates.first().cloned().unwrap_or_default()
    }

    /// Updates the health record for a candidate.
    pub fn update_health(&self, candidate: &str, result: Result<Duration, &ProbeError>) {
        let mut healths = self.health_records.write().unwrap();
        let record = healths.entry(candidate.to_string()).or_default();
        record.last_checked = Some(Instant::now());
        match result {
            Ok(lat) => {
                record.healthy = true;
                record.latency_ms = Some(lat.as_millis() as u64);
            }
            Err(_) => {
                record.healthy = false;
                record.latency_ms = None;
            }
        }
    }

    /// Returns a snapshot of candidate health statistics.
    pub fn health_snapshot(&self) -> HashMap<String, NodeHealth> {
        self.health_records.read().unwrap().clone()
    }
}

impl PartialEq for FallbackGroup {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.candidates == other.candidates
            && self.url == other.url
            && self.interval == other.interval
            && self.timeout == other.timeout
    }
}
impl Eq for FallbackGroup {}

/// Outbound target variant (leaf or group).
#[derive(Debug, Clone)]
pub enum OutboundTarget {
    Direct,
    Reject,
    Socks5(Socks5OutboundConfig),
    Trojan(TrojanOutboundConfig),
    Selector(Arc<SelectorGroup>),
    UrlTest(Arc<UrlTestGroup>),
    Fallback(Arc<FallbackGroup>),
}

impl PartialEq for OutboundTarget {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Direct, Self::Direct) => true,
            (Self::Reject, Self::Reject) => true,
            (Self::Socks5(a), Self::Socks5(b)) => a == b,
            (Self::Trojan(a), Self::Trojan(b)) => a == b,
            (Self::Selector(a), Self::Selector(b)) => a == b,
            (Self::UrlTest(a), Self::UrlTest(b)) => a == b,
            (Self::Fallback(a), Self::Fallback(b)) => a == b,
            _ => false,
        }
    }
}
impl Eq for OutboundTarget {}

/// Concrete leaf dial target resolved from an outbound or group chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedOutbound {
    Direct,
    Reject,
    Socks5(Socks5OutboundConfig),
    Trojan(TrojanOutboundConfig),
}

/// Registry storing all named outbounds and groups, providing recursive resolution.
#[derive(Debug, Clone, Default)]
pub struct OutboundRegistry {
    entries: HashMap<String, OutboundTarget>,
}

impl PartialEq for OutboundRegistry {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}
impl Eq for OutboundRegistry {}

impl OutboundRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a named outbound target.
    pub fn insert(&mut self, name: String, target: OutboundTarget) {
        self.entries.insert(name, target);
    }

    /// Retrieves an outbound target by name.
    pub fn get(&self, name: &str) -> Option<&OutboundTarget> {
        self.entries.get(name)
    }

    /// Returns `true` if `name` is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Returns an iterator over all registered outbound names and targets.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &OutboundTarget)> {
        self.entries.iter()
    }

    /// Recursively resolves `name` to a concrete leaf dial target.
    pub fn resolve(&self, name: &str) -> Result<ResolvedOutbound, OutboundResolveError> {
        self.resolve_with_chain(name).map(|(leaf, _)| leaf)
    }

    /// Recursively resolves `name` to a concrete leaf dial target, returning the resolution chain.
    pub fn resolve_with_chain(
        &self,
        name: &str,
    ) -> Result<(ResolvedOutbound, Vec<String>), OutboundResolveError> {
        let mut chain = Vec::new();
        let mut current_name = name.to_string();
        const MAX_DEPTH: usize = 16;

        for _ in 0..MAX_DEPTH {
            chain.push(current_name.clone());

            if current_name.eq_ignore_ascii_case("DIRECT") {
                return Ok((ResolvedOutbound::Direct, chain));
            }
            if current_name.eq_ignore_ascii_case("REJECT") {
                return Ok((ResolvedOutbound::Reject, chain));
            }

            match self.entries.get(&current_name) {
                Some(OutboundTarget::Direct) => return Ok((ResolvedOutbound::Direct, chain)),
                Some(OutboundTarget::Reject) => return Ok((ResolvedOutbound::Reject, chain)),
                Some(OutboundTarget::Socks5(cfg)) => {
                    return Ok((ResolvedOutbound::Socks5(cfg.clone()), chain));
                }
                Some(OutboundTarget::Trojan(cfg)) => {
                    return Ok((ResolvedOutbound::Trojan(cfg.clone()), chain));
                }
                Some(OutboundTarget::Selector(group)) => {
                    current_name = group.select();
                }
                Some(OutboundTarget::UrlTest(group)) => {
                    current_name = group.select();
                }
                Some(OutboundTarget::Fallback(group)) => {
                    current_name = group.select();
                }
                None => {
                    return Err(OutboundResolveError::NotFound {
                        name: current_name,
                        chain,
                    });
                }
            }
        }

        Err(OutboundResolveError::RecursionLimitExceeded { chain })
    }

    /// Spawns background health check tasks for all URL-test and Fallback groups in this registry.
    pub fn spawn_health_checks(
        self: &Arc<Self>,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        for target in self.entries.values() {
            match target {
                OutboundTarget::UrlTest(group) => {
                    let registry = Arc::clone(self);
                    let group = Arc::clone(group);
                    let mut rx = shutdown_rx.clone();
                    let handle = tokio::spawn(async move {
                        loop {
                            if *rx.borrow() {
                                break;
                            }
                            for candidate in &group.candidates {
                                let res = probe_candidate(
                                    &registry,
                                    candidate,
                                    &group.url,
                                    group.timeout,
                                )
                                .await;
                                match &res {
                                    Ok(lat) => {
                                        debug!(
                                            group = %group.name,
                                            candidate = %candidate,
                                            latency_ms = lat.as_millis(),
                                            "health check passed"
                                        );
                                    }
                                    Err(e) => {
                                        debug!(
                                            group = %group.name,
                                            candidate = %candidate,
                                            error = %e,
                                            "health check failed"
                                        );
                                    }
                                }
                                group.update_health(candidate, res.as_ref().copied());
                            }

                            let _ = tokio::time::timeout(group.interval, rx.changed()).await;
                            if *rx.borrow() {
                                break;
                            }
                        }
                    });
                    handles.push(handle);
                }
                OutboundTarget::Fallback(group) => {
                    let registry = Arc::clone(self);
                    let group = Arc::clone(group);
                    let mut rx = shutdown_rx.clone();
                    let handle = tokio::spawn(async move {
                        loop {
                            if *rx.borrow() {
                                break;
                            }
                            for candidate in &group.candidates {
                                let res = probe_candidate(
                                    &registry,
                                    candidate,
                                    &group.url,
                                    group.timeout,
                                )
                                .await;
                                match &res {
                                    Ok(lat) => {
                                        debug!(
                                            group = %group.name,
                                            candidate = %candidate,
                                            latency_ms = lat.as_millis(),
                                            "health check passed"
                                        );
                                    }
                                    Err(e) => {
                                        debug!(
                                            group = %group.name,
                                            candidate = %candidate,
                                            error = %e,
                                            "health check failed"
                                        );
                                    }
                                }
                                group.update_health(candidate, res.as_ref().copied());
                            }

                            let _ = tokio::time::timeout(group.interval, rx.changed()).await;
                            if *rx.borrow() {
                                break;
                            }
                        }
                    });
                    handles.push(handle);
                }
                _ => {}
            }
        }

        handles
    }

    /// Collects a unified health and status report across all leaf nodes and outbound groups.
    ///
    /// Redacts all credentials (passwords, tokens) to prevent sensitive information leakage.
    pub fn health_report(&self) -> HashMap<String, NodeHealthReport> {
        let mut report = HashMap::new();

        // Built-in standard endpoints
        report.insert(
            "DIRECT".to_string(),
            NodeHealthReport {
                node_type: "direct".to_string(),
                healthy: true,
                latency_ms: None,
                last_checked_secs_ago: None,
                selected: None,
                candidates: None,
                server: None,
            },
        );
        report.insert(
            "REJECT".to_string(),
            NodeHealthReport {
                node_type: "reject".to_string(),
                healthy: true,
                latency_ms: None,
                last_checked_secs_ago: None,
                selected: None,
                candidates: None,
                server: None,
            },
        );

        for (name, target) in &self.entries {
            match target {
                OutboundTarget::Direct => {
                    report.insert(
                        name.clone(),
                        NodeHealthReport {
                            node_type: "direct".to_string(),
                            healthy: true,
                            latency_ms: None,
                            last_checked_secs_ago: None,
                            selected: None,
                            candidates: None,
                            server: None,
                        },
                    );
                }
                OutboundTarget::Reject => {
                    report.insert(
                        name.clone(),
                        NodeHealthReport {
                            node_type: "reject".to_string(),
                            healthy: true,
                            latency_ms: None,
                            last_checked_secs_ago: None,
                            selected: None,
                            candidates: None,
                            server: None,
                        },
                    );
                }
                OutboundTarget::Socks5(cfg) => {
                    // Strictly redact passwords/tokens
                    let server_str =
                        crate::diagnostics::redact_credentials(&cfg.server.to_string());
                    report.insert(
                        name.clone(),
                        NodeHealthReport {
                            node_type: "socks5".to_string(),
                            healthy: true,
                            latency_ms: None,
                            last_checked_secs_ago: None,
                            selected: None,
                            candidates: None,
                            server: Some(server_str),
                        },
                    );
                }
                OutboundTarget::Trojan(cfg) => {
                    // Strictly redact credentials in server string
                    let server_str =
                        crate::diagnostics::redact_credentials(&cfg.server.to_string());
                    report.insert(
                        name.clone(),
                        NodeHealthReport {
                            node_type: "trojan".to_string(),
                            healthy: true,
                            latency_ms: None,
                            last_checked_secs_ago: None,
                            selected: None,
                            candidates: None,
                            server: Some(server_str),
                        },
                    );
                }
                OutboundTarget::Selector(group) => {
                    let sel = group.select();
                    report.insert(
                        name.clone(),
                        NodeHealthReport {
                            node_type: "selector".to_string(),
                            healthy: true,
                            latency_ms: None,
                            last_checked_secs_ago: None,
                            selected: if sel.is_empty() { None } else { Some(sel) },
                            candidates: Some(group.candidates.clone()),
                            server: None,
                        },
                    );
                }
                OutboundTarget::UrlTest(group) => {
                    let sel = group.select();
                    let snapshot = group.health_snapshot();
                    let (healthy, latency_ms, last_checked_secs_ago) =
                        if let Some(record) = snapshot.get(&sel) {
                            (
                                record.healthy,
                                record.latency_ms,
                                record.last_checked.map(|t| t.elapsed().as_secs()),
                            )
                        } else {
                            (true, None, None)
                        };

                    report.insert(
                        name.clone(),
                        NodeHealthReport {
                            node_type: "url-test".to_string(),
                            healthy,
                            latency_ms,
                            last_checked_secs_ago,
                            selected: if sel.is_empty() { None } else { Some(sel) },
                            candidates: Some(group.candidates.clone()),
                            server: None,
                        },
                    );
                }
                OutboundTarget::Fallback(group) => {
                    let sel = group.select();
                    let snapshot = group.health_snapshot();
                    let (healthy, latency_ms, last_checked_secs_ago) =
                        if let Some(record) = snapshot.get(&sel) {
                            (
                                record.healthy,
                                record.latency_ms,
                                record.last_checked.map(|t| t.elapsed().as_secs()),
                            )
                        } else {
                            (true, None, None)
                        };

                    report.insert(
                        name.clone(),
                        NodeHealthReport {
                            node_type: "fallback".to_string(),
                            healthy,
                            latency_ms,
                            last_checked_secs_ago,
                            selected: if sel.is_empty() { None } else { Some(sel) },
                            candidates: Some(group.candidates.clone()),
                            server: None,
                        },
                    );
                }
            }
        }

        report
    }
}

/// Parses an HTTP probe URL into `(host, port, path)`.
pub fn parse_http_probe_url(url: &str) -> Result<(String, u16, String), ProbeError> {
    let stripped = url
        .strip_prefix("http://")
        .ok_or_else(|| ProbeError::InvalidUrl("probe URL must start with http://".to_string()))?;

    let (authority, path) = match stripped.find('/') {
        Some(idx) => (&stripped[..idx], &stripped[idx..]),
        None => (stripped, "/"),
    };

    if authority.is_empty() {
        return Err(ProbeError::InvalidUrl(
            "empty host in probe URL".to_string(),
        ));
    }

    let (host, port) = if authority.starts_with('[') {
        let closing = authority.find(']').ok_or_else(|| {
            ProbeError::InvalidUrl("missing closing ']' in IPv6 host".to_string())
        })?;
        let ip_str = &authority[1..closing];
        let port_part = &authority[closing + 1..];
        let port = if let Some(p) = port_part.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|e| ProbeError::InvalidUrl(format!("invalid port in probe URL: {e}")))?
        } else {
            80
        };
        (ip_str.to_string(), port)
    } else if let Some(colon) = authority.rfind(':') {
        let host_part = &authority[..colon];
        let port_part = &authority[colon + 1..];
        let port = port_part
            .parse::<u16>()
            .map_err(|e| ProbeError::InvalidUrl(format!("invalid port in probe URL: {e}")))?;
        (host_part.to_string(), port)
    } else {
        (authority.to_string(), 80)
    };

    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    Ok((host, port, path))
}

/// Probes a concrete [`ResolvedOutbound`] leaf with an HTTP GET probe and returns measured latency.
pub async fn probe_leaf(
    leaf: &ResolvedOutbound,
    target_addr: &TargetAddr,
    host_header: &str,
    path: &str,
    timeout: Duration,
) -> Result<Duration, ProbeError> {
    let start = Instant::now();

    let mut stream: OutboundStream = match leaf {
        ResolvedOutbound::Direct => DirectDialer::new(timeout)
            .dial(target_addr)
            .await
            .map(OutboundStream::from)
            .map_err(ProbeError::Io)?,
        ResolvedOutbound::Socks5(cfg) => Socks5Dialer::dial(cfg, target_addr, timeout)
            .await
            .map(OutboundStream::from)
            .map_err(ProbeError::Io)?,
        ResolvedOutbound::Trojan(cfg) => TrojanDialer::dial(cfg, target_addr, timeout, None)
            .await
            .map_err(ProbeError::Io)?,
        ResolvedOutbound::Reject => return Err(ProbeError::Rejected),
    };

    let remaining = timeout.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return Err(ProbeError::TimedOut);
    }

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Yachiyo/0.1\r\nConnection: close\r\n\r\n"
    );

    tokio::time::timeout(remaining, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| ProbeError::TimedOut)?
        .map_err(ProbeError::Io)?;

    let remaining = timeout.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return Err(ProbeError::TimedOut);
    }

    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(remaining, stream.read(&mut buf))
        .await
        .map_err(|_| ProbeError::TimedOut)?
        .map_err(ProbeError::Io)?;

    if n == 0 {
        return Err(ProbeError::EmptyResponse);
    }

    let resp_str = String::from_utf8_lossy(&buf[..n]);
    let first_line = resp_str.lines().next().ok_or(ProbeError::InvalidResponse)?;
    let mut parts = first_line.split_whitespace();
    let _version = parts.next().ok_or(ProbeError::InvalidResponse)?;
    let status_code = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(ProbeError::InvalidResponse)?;

    if !(200..400).contains(&status_code) {
        return Err(ProbeError::HttpStatus(status_code));
    }

    Ok(start.elapsed())
}

/// Executes a health check probe for a named candidate within `registry`.
pub async fn probe_candidate(
    registry: &OutboundRegistry,
    candidate: &str,
    url: &str,
    timeout: Duration,
) -> Result<Duration, ProbeError> {
    let (host, port, path) = parse_http_probe_url(url)?;
    let target_addr: TargetAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| ProbeError::InvalidUrl(format!("{e}")))?;

    let leaf = registry
        .resolve(candidate)
        .map_err(|e| ProbeError::InvalidUrl(e.to_string()))?;

    let host_header = if port == 80 {
        host
    } else {
        format!("{host}:{port}")
    };

    probe_leaf(&leaf, &target_addr, &host_header, &path, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_probe_url() {
        let (host, port, path) =
            parse_http_probe_url("http://127.0.0.1:8080/generate_204").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
        assert_eq!(path, "/generate_204");

        let (host, port, path) = parse_http_probe_url("http://[::1]:1080/test").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 1080);
        assert_eq!(path, "/test");

        let (host, port, path) =
            parse_http_probe_url("http://cp.cloudflare.com/generate_204").unwrap();
        assert_eq!(host, "cp.cloudflare.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/generate_204");

        assert!(parse_http_probe_url("https://example.com").is_err());
        assert!(parse_http_probe_url("ftp://example.com").is_err());
        assert!(parse_http_probe_url("http://").is_err());
    }

    #[test]
    fn test_selector_group_selection_and_switch() {
        let selector = SelectorGroup::new(
            "proxy".to_string(),
            vec!["node_a".to_string(), "node_b".to_string()],
            None,
        );
        assert_eq!(selector.select(), "node_a");

        selector.set_selected("node_b").unwrap();
        assert_eq!(selector.select(), "node_b");

        assert!(selector.set_selected("node_c").is_err());
    }

    #[test]
    fn test_url_test_tolerance_hysteresis() {
        let group = UrlTestGroup::new(
            "auto".to_string(),
            vec!["node_a".to_string(), "node_b".to_string()],
            DEFAULT_HEALTH_CHECK_URL.to_string(),
            DEFAULT_HEALTH_CHECK_INTERVAL,
            DEFAULT_HEALTH_CHECK_TIMEOUT,
            Duration::from_millis(50),
        );

        // Initially node_a: 80ms, node_b: 75ms (difference = 5ms <= 50ms tolerance)
        group.update_health("node_a", Ok(Duration::from_millis(80)));
        group.update_health("node_b", Ok(Duration::from_millis(75)));
        // Picks lowest initially: node_b (75ms)
        assert_eq!(group.select(), "node_b");

        // Now node_a improves to 70ms (difference = 75 - 70 = 5ms <= 50ms tolerance)
        group.update_health("node_a", Ok(Duration::from_millis(70)));
        // Hysteresis keeps node_b to prevent flapping!
        assert_eq!(group.select(), "node_b");

        // Node_a improves significantly to 20ms (difference = 75 - 20 = 55ms > 50ms)
        group.update_health("node_a", Ok(Duration::from_millis(20)));
        // Exceeds tolerance -> switches to node_a!
        assert_eq!(group.select(), "node_a");

        // Node_a fails
        let err = ProbeError::TimedOut;
        group.update_health("node_a", Err(&err));
        // Switches to healthy node_b
        assert_eq!(group.select(), "node_b");
    }

    #[test]
    fn test_fallback_group_priority_order() {
        let group = FallbackGroup::new(
            "fallback".to_string(),
            vec![
                "primary".to_string(),
                "secondary".to_string(),
                "tertiary".to_string(),
            ],
            DEFAULT_HEALTH_CHECK_URL.to_string(),
            DEFAULT_HEALTH_CHECK_INTERVAL,
            DEFAULT_HEALTH_CHECK_TIMEOUT,
        );

        // Optimistically, primary is picked first
        assert_eq!(group.select(), "primary");

        // Primary fails
        let err = ProbeError::TimedOut;
        group.update_health("primary", Err(&err));
        assert_eq!(group.select(), "secondary");

        // Secondary fails too
        group.update_health("secondary", Err(&err));
        assert_eq!(group.select(), "tertiary");

        // Primary recovers
        group.update_health("primary", Ok(Duration::from_millis(30)));
        assert_eq!(group.select(), "primary");
    }

    #[test]
    fn test_registry_recursive_chain_resolution() {
        let mut registry = OutboundRegistry::new();

        let selector = Arc::new(SelectorGroup::new(
            "my_selector".to_string(),
            vec!["my_fallback".to_string(), "DIRECT".to_string()],
            None,
        ));
        let fallback = Arc::new(FallbackGroup::new(
            "my_fallback".to_string(),
            vec!["DIRECT".to_string()],
            DEFAULT_HEALTH_CHECK_URL.to_string(),
            DEFAULT_HEALTH_CHECK_INTERVAL,
            DEFAULT_HEALTH_CHECK_TIMEOUT,
        ));

        registry.insert(
            "my_selector".to_string(),
            OutboundTarget::Selector(selector),
        );
        registry.insert(
            "my_fallback".to_string(),
            OutboundTarget::Fallback(fallback),
        );

        let (leaf, chain) = registry.resolve_with_chain("my_selector").unwrap();
        assert_eq!(leaf, ResolvedOutbound::Direct);
        assert_eq!(chain, vec!["my_selector", "my_fallback", "DIRECT"]);
    }

    #[test]
    fn test_outbound_registry_health_report() {
        let mut registry = OutboundRegistry::new();
        let selector = Arc::new(SelectorGroup::new(
            "auto".to_string(),
            vec!["DIRECT".to_string(), "REJECT".to_string()],
            None,
        ));
        registry.insert("auto".to_string(), OutboundTarget::Selector(selector));

        let report = registry.health_report();
        assert!(report.contains_key("DIRECT"));
        assert!(report.contains_key("REJECT"));
        assert!(report.contains_key("auto"));

        let auto_report = report.get("auto").unwrap();
        assert_eq!(auto_report.node_type, "selector");
        assert_eq!(auto_report.selected, Some("DIRECT".to_string()));
        assert_eq!(
            auto_report.candidates,
            Some(vec!["DIRECT".to_string(), "REJECT".to_string()])
        );

        let json = auto_report.to_json();
        assert!(json.contains(r#""node_type":"selector""#));
        assert!(json.contains(r#""healthy":true"#));
        assert!(json.contains(r#""selected":"DIRECT""#));
    }
}
