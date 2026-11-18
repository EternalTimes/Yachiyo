// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime status, diagnostics tracking, active connection inspection, and traffic telemetry.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::address::TargetAddr;

/// Redacts credentials (passwords, tokens, secrets) from URLs and diagnostic strings.
///
/// Replaces sensitive userinfo passwords with `[REDACTED]`, e.g. `http://user:secret@example.com`
/// becomes `http://user:[REDACTED]@example.com`.
pub fn redact_credentials(input: &str) -> String {
    // 1. Redact URI/URL credentials: "scheme://user:pass@host"
    let mut result = input.to_string();

    if let Some(scheme_pos) = result.find("://") {
        let after_scheme = scheme_pos + 3;
        if let Some(at_pos) = result[after_scheme..].find('@') {
            let at_abs = after_scheme + at_pos;
            let user_info = &result[after_scheme..at_abs];
            if let Some(colon_pos) = user_info.find(':') {
                let pass_start = after_scheme + colon_pos + 1;
                result.replace_range(pass_start..at_abs, "[REDACTED]");
            }
        }
    }

    // 2. Redact standalone "password: ..." or "token: ..." patterns if present
    for key in &["password", "secret", "token", "passwd"] {
        let pattern = format!("{key}=");
        if let Some(pos) = result.to_lowercase().find(&pattern) {
            let val_start = pos + pattern.len();
            let val_end = result[val_start..]
                .find([' ', '&', ';', ','])
                .map(|p| val_start + p)
                .unwrap_or(result.len());
            result.replace_range(val_start..val_end, "[REDACTED]");
        }
    }

    result
}

/// Helper function to escape strings for JSON formatting.
pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Snapshot of the daemon runtime status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStatusSnapshot {
    pub ok: bool,
    pub uptime_secs: u64,
    pub active_connections: usize,
    pub max_connections: usize,
    pub config_generation: u64,
    pub listeners: Vec<String>,
    pub total_connections: u64,
    #[serde(default)]
    pub pid: u32,
}

impl RuntimeStatusSnapshot {
    /// Formats the snapshot as a valid JSON string matching the IPC protocol contract.
    pub fn to_json(&self) -> String {
        let listeners_json = self
            .listeners
            .iter()
            .map(|l| format!(r#""{}""#, escape_json(l)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"ok":{},"uptime_secs":{},"active_connections":{},"max_connections":{},"config_generation":{},"listeners":[{}],"total_connections":{},"pid":{}}}"#,
            self.ok,
            self.uptime_secs,
            self.active_connections,
            self.max_connections,
            self.config_generation,
            listeners_json,
            self.total_connections,
            self.pid
        )
    }
}

/// Snapshot of cumulative traffic telemetry statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficStatsSnapshot {
    pub ok: bool,
    pub total_upload_bytes: u64,
    pub total_download_bytes: u64,
    pub total_bytes: u64,
    pub total_connections: u64,
    pub active_connections: usize,
}

impl TrafficStatsSnapshot {
    /// Formats the snapshot as a valid JSON string matching the IPC protocol contract.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"ok":{},"total_upload_bytes":{},"total_download_bytes":{},"total_bytes":{},"total_connections":{},"active_connections":{}}}"#,
            self.ok,
            self.total_upload_bytes,
            self.total_download_bytes,
            self.total_bytes,
            self.total_connections,
            self.active_connections
        )
    }
}

/// Snapshot of an in-flight active connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveConnSnapshot {
    pub id: u64,
    pub peer_addr: String,
    pub target: String,
    pub policy: String,
    pub duration_secs: u64,
}

impl ActiveConnSnapshot {
    /// Formats the connection snapshot as a JSON object fragment.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"id":{},"peer_addr":"{}","target":"{}","policy":"{}","duration_secs":{}}}"#,
            self.id,
            escape_json(&self.peer_addr),
            escape_json(&self.target),
            escape_json(&self.policy),
            self.duration_secs
        )
    }
}

#[derive(Debug, Clone)]
struct ActiveConnRecord {
    id: u64,
    peer_addr: SocketAddr,
    target: TargetAddr,
    policy: String,
    start_time: Instant,
}

/// RAII guard ensuring an active connection is deregistered upon completion or drop.
pub struct ActiveConnGuard {
    id: u64,
    tracker: Weak<DiagnosticsTracker>,
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        if let Some(tracker) = self.tracker.upgrade() {
            tracker.deregister_connection(self.id);
        }
    }
}

/// Centralized status and diagnostics tracker for Project Yachiyo.
///
/// Tracks process uptime, listener endpoints, cumulative connection counts,
/// directional traffic volume, and in-flight active connections with credential redaction.
#[derive(Debug)]
pub struct DiagnosticsTracker {
    start_time: Instant,
    pid: u32,
    max_connections: usize,
    config_generation: AtomicU64,
    total_connections: AtomicU64,
    total_tx_bytes: AtomicU64,
    total_rx_bytes: AtomicU64,
    listeners: RwLock<Vec<String>>,
    active_conns: RwLock<HashMap<u64, ActiveConnRecord>>,
}

impl DiagnosticsTracker {
    /// Creates a new `DiagnosticsTracker` instance wrapped in an `Arc`.
    pub fn new(max_connections: usize) -> Arc<Self> {
        Arc::new(Self {
            start_time: Instant::now(),
            pid: std::process::id(),
            max_connections,
            config_generation: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            total_tx_bytes: AtomicU64::new(0),
            total_rx_bytes: AtomicU64::new(0),
            listeners: RwLock::new(Vec::new()),
            active_conns: RwLock::new(HashMap::new()),
        })
    }

    /// Registers a newly accepted connection and returns an RAII [`ActiveConnGuard`].
    pub fn register_connection(
        self: &Arc<Self>,
        id: u64,
        peer: SocketAddr,
        target: TargetAddr,
        policy: String,
    ) -> ActiveConnGuard {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        let record = ActiveConnRecord {
            id,
            peer_addr: peer,
            target,
            policy,
            start_time: Instant::now(),
        };

        if let Ok(mut map) = self.active_conns.write() {
            map.insert(id, record);
        }

        ActiveConnGuard {
            id,
            tracker: Arc::downgrade(self),
        }
    }

    /// Deregisters an active connection by its connection ID.
    pub fn deregister_connection(&self, id: u64) {
        if let Ok(mut map) = self.active_conns.write() {
            map.remove(&id);
        }
    }

    /// Accumulates directional byte transfer statistics.
    ///
    /// - `client_to_remote`: Upload / TX bytes
    /// - `remote_to_client`: Download / RX bytes
    pub fn record_transfer(&self, client_to_remote: u64, remote_to_client: u64) {
        self.total_tx_bytes
            .fetch_add(client_to_remote, Ordering::Relaxed);
        self.total_rx_bytes
            .fetch_add(remote_to_client, Ordering::Relaxed);
    }

    /// Returns a point-in-time snapshot of runtime status.
    pub fn runtime_status(&self) -> RuntimeStatusSnapshot {
        let uptime_secs = self.start_time.elapsed().as_secs();
        let active_connections = self.active_count();
        let listeners = self.listeners.read().map(|l| l.clone()).unwrap_or_default();

        RuntimeStatusSnapshot {
            ok: true,
            uptime_secs,
            active_connections,
            max_connections: self.max_connections,
            config_generation: self.config_generation.load(Ordering::Relaxed),
            listeners,
            total_connections: self.total_connections.load(Ordering::Relaxed),
            pid: self.pid,
        }
    }

    /// Returns a list of in-flight active connection snapshots with credential redaction.
    pub fn active_connections(&self) -> Vec<ActiveConnSnapshot> {
        let map = self
            .active_conns
            .read()
            .map(|m| m.clone())
            .unwrap_or_default();

        let mut list: Vec<ActiveConnSnapshot> = map
            .values()
            .map(|r| ActiveConnSnapshot {
                id: r.id,
                peer_addr: r.peer_addr.to_string(),
                target: redact_credentials(&r.target.to_string()),
                policy: redact_credentials(&r.policy),
                duration_secs: r.start_time.elapsed().as_secs(),
            })
            .collect();

        list.sort_by_key(|c| c.id);
        list
    }

    /// Returns cumulative traffic statistics.
    pub fn traffic_stats(&self) -> TrafficStatsSnapshot {
        let total_upload_bytes = self.total_tx_bytes.load(Ordering::Relaxed);
        let total_download_bytes = self.total_rx_bytes.load(Ordering::Relaxed);
        let total_bytes = total_upload_bytes.saturating_add(total_download_bytes);
        let total_connections = self.total_connections.load(Ordering::Relaxed);
        let active_connections = self.active_count();

        TrafficStatsSnapshot {
            ok: true,
            total_upload_bytes,
            total_download_bytes,
            total_bytes,
            total_connections,
            active_connections,
        }
    }

    /// Sets the bound listener addresses.
    pub fn set_listeners(&self, listeners: Vec<String>) {
        if let Ok(mut l) = self.listeners.write() {
            *l = listeners;
        }
    }

    /// Adds a single listener address to the tracked listeners list.
    pub fn add_listener(&self, listener: String) {
        if let Ok(mut l) = self.listeners.write() {
            if !l.contains(&listener) {
                l.push(listener);
            }
        }
    }

    /// Updates the active configuration generation number.
    pub fn set_config_generation(&self, generation: u64) {
        self.config_generation.store(generation, Ordering::Relaxed);
    }

    /// Returns the count of currently active connections.
    pub fn active_count(&self) -> usize {
        self.active_conns.read().map(|m| m.len()).unwrap_or(0)
    }

    /// Returns the cumulative total of accepted connections.
    pub fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    /// Returns the cumulative total bytes transferred from client to remote (TX / upload).
    pub fn total_tx_bytes(&self) -> u64 {
        self.total_tx_bytes.load(Ordering::Relaxed)
    }

    /// Returns the cumulative total bytes transferred from remote to client (RX / download).
    pub fn total_rx_bytes(&self) -> u64 {
        self.total_rx_bytes.load(Ordering::Relaxed)
    }

    /// Returns the cumulative total bytes across both directions.
    pub fn total_bytes(&self) -> u64 {
        self.total_tx_bytes().saturating_add(self.total_rx_bytes())
    }

    /// Returns the daemon uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Returns the process ID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the configured maximum connection limit.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostics_tracker_lifecycle() {
        let tracker = DiagnosticsTracker::new(1024);
        assert_eq!(tracker.max_connections(), 1024);
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.total_connections(), 0);
        assert_eq!(tracker.total_bytes(), 0);

        tracker.add_listener("127.0.0.1:18484".to_string());
        tracker.set_config_generation(1);

        let peer = "127.0.0.1:54321".parse().unwrap();
        let target = TargetAddr::from_domain("example.com", 80).unwrap();

        let guard = tracker.register_connection(1, peer, target, "DIRECT".to_string());
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(tracker.total_connections(), 1);

        let conns = tracker.active_connections();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].id, 1);
        assert_eq!(conns[0].peer_addr, "127.0.0.1:54321");
        assert_eq!(conns[0].target, "example.com:80");
        assert_eq!(conns[0].policy, "DIRECT");

        let status = tracker.runtime_status();
        assert!(status.ok);
        assert_eq!(status.active_connections, 1);
        assert_eq!(status.total_connections, 1);
        assert_eq!(status.config_generation, 1);
        assert_eq!(status.listeners, vec!["127.0.0.1:18484"]);

        tracker.record_transfer(100, 200);
        assert_eq!(tracker.total_tx_bytes(), 100);
        assert_eq!(tracker.total_rx_bytes(), 200);
        assert_eq!(tracker.total_bytes(), 300);

        let stats = tracker.traffic_stats();
        assert_eq!(stats.total_upload_bytes, 100);
        assert_eq!(stats.total_download_bytes, 200);
        assert_eq!(stats.total_bytes, 300);

        drop(guard);
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.total_connections(), 1);
    }

    #[test]
    fn test_credential_redaction() {
        assert_eq!(
            redact_credentials("https://user:mysecretpassword@example.com/path"),
            "https://user:[REDACTED]@example.com/path"
        );
        assert_eq!(
            redact_credentials("http://alice:super_secret@127.0.0.1:8080/"),
            "http://alice:[REDACTED]@127.0.0.1:8080/"
        );
        assert_eq!(
            redact_credentials("password=supersecret&other=val"),
            "password=[REDACTED]&other=val"
        );
        assert_eq!(redact_credentials("DIRECT"), "DIRECT");
    }

    #[test]
    fn test_json_serialization() {
        let status = RuntimeStatusSnapshot {
            ok: true,
            uptime_secs: 10,
            active_connections: 2,
            max_connections: 1024,
            config_generation: 1,
            listeners: vec!["127.0.0.1:18484".to_string()],
            total_connections: 5,
            pid: 12345,
        };
        let json = status.to_json();
        assert!(json.contains(r#""ok":true"#));
        assert!(json.contains(r#""uptime_secs":10"#));
        assert!(json.contains(r#""listeners":["127.0.0.1:18484"]"#));

        let stats = TrafficStatsSnapshot {
            ok: true,
            total_upload_bytes: 500,
            total_download_bytes: 1500,
            total_bytes: 2000,
            total_connections: 10,
            active_connections: 1,
        };
        let json_stats = stats.to_json();
        assert!(json_stats.contains(r#""total_upload_bytes":500"#));
        assert!(json_stats.contains(r#""total_download_bytes":1500"#));
        assert!(json_stats.contains(r#""total_bytes":2000"#));
    }
}
