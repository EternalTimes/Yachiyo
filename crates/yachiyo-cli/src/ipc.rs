// SPDX-License-Identifier: AGPL-3.0-only

//! Unix domain socket IPC server and client for status and diagnostics inspection.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use yachiyo_cli::args::QueryCommand;
use yachiyo_core::diagnostics::escape_json;
use yachiyo_core::{
    ActiveConnSnapshot, DiagnosticsTracker, NodeHealthReport, OutboundRegistry, RuleSet,
};
use yachiyo_inbound::RuntimeSnapshot;

/// Default filesystem path for the local Unix domain socket IPC endpoint.
pub const DEFAULT_IPC_PATH: &str = "/tmp/yachiyo.sock";

/// RAII guard ensuring the Unix domain socket file is unlinked on task exit or drop.
#[derive(Debug)]
pub struct IpcSocketGuard {
    path: PathBuf,
}

impl Drop for IpcSocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Errors occurring during IPC client requests.
#[derive(Debug, thiserror::Error)]
pub enum IpcClientError {
    #[error("cannot connect to Yachiyo daemon at {}: {source}", path.display())]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error communicating with Yachiyo daemon: {0}")]
    Io(#[from] std::io::Error),
}

/// Unix domain socket IPC server.
pub struct IpcServer {
    listener: UnixListener,
    path: PathBuf,
    diagnostics: Arc<DiagnosticsTracker>,
    snapshot_rx: tokio::sync::watch::Receiver<Arc<RuntimeSnapshot>>,
}

impl IpcServer {
    /// Binds the Unix domain socket at `path`, automatically recovering from stale orphaned sockets.
    #[allow(dead_code)]
    pub async fn bind(
        path: impl AsRef<Path>,
        diagnostics: Arc<DiagnosticsTracker>,
        outbounds: Arc<OutboundRegistry>,
    ) -> Result<Self, std::io::Error> {
        let initial_snapshot = Arc::new(RuntimeSnapshot {
            handshake_timeout: std::time::Duration::from_secs(10),
            connect_timeout: std::time::Duration::from_secs(10),
            idle_timeout: std::time::Duration::from_secs(300),
            rules: Arc::new(RuleSet::default_direct()),
            outbounds,
            config_generation: diagnostics.runtime_status().config_generation,
        });
        let (_tx, rx) = tokio::sync::watch::channel(initial_snapshot);
        Self::bind_with_snapshot(path, true, diagnostics, rx).await
    }

    /// Binds the Unix domain socket at `path` subscribed to live [`RuntimeSnapshot`] updates.
    ///
    /// If `is_custom` is false and the default socket `/tmp/yachiyo.sock` is already in use by another
    /// daemon instance, falls back to `/tmp/yachiyo-{pid}.sock` to prevent multi-instance / test collisions.
    pub async fn bind_with_snapshot(
        path: impl AsRef<Path>,
        is_custom: bool,
        diagnostics: Arc<DiagnosticsTracker>,
        snapshot_rx: tokio::sync::watch::Receiver<Arc<RuntimeSnapshot>>,
    ) -> Result<Self, std::io::Error> {
        let mut target_path = path.as_ref().to_path_buf();

        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        async fn try_bind(target: &Path) -> Result<UnixListener, std::io::Error> {
            if target.exists() {
                match UnixStream::connect(target).await {
                    Ok(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::AddrInUse,
                            format!(
                                "another daemon is already listening on IPC socket '{}'",
                                target.display()
                            ),
                        ));
                    }
                    Err(_) => {
                        // Stale orphaned socket file from ungraceful shutdown
                        let _ = std::fs::remove_file(target);
                    }
                }
            }
            UnixListener::bind(target)
        }

        let listener = match try_bind(&target_path).await {
            Ok(l) => l,
            Err(_) if !is_custom => {
                // Default socket collision between concurrent instances / test runs:
                // Fallback to per-process socket
                let pid = std::process::id();
                target_path = PathBuf::from(format!("/tmp/yachiyo-{pid}.sock"));
                let _ = std::fs::remove_file(&target_path);
                UnixListener::bind(&target_path)?
            }
            Err(e) => return Err(e),
        };

        Ok(Self {
            listener,
            path: target_path,
            diagnostics,
            snapshot_rx,
        })
    }

    /// Returns the socket path bound by this IPC server.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs the IPC request handling loop until `shutdown_rx` receives `true`.
    pub async fn run(
        self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), std::io::Error> {
        let _guard = IpcSocketGuard {
            path: self.path.clone(),
        };

        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            tokio::select! {
                accept_res = self.listener.accept() => {
                    match accept_res {
                        Ok((stream, _)) => {
                            let diag = Arc::clone(&self.diagnostics);
                            let snap_rx = self.snapshot_rx.clone();
                            tokio::spawn(async move {
                                handle_client(stream, diag, snap_rx).await;
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "IPC server accept error");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_client(
    stream: UnixStream,
    diagnostics: Arc<DiagnosticsTracker>,
    snapshot_rx: tokio::sync::watch::Receiver<Arc<RuntimeSnapshot>>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let snap = snapshot_rx.borrow().clone();
                diagnostics.set_config_generation(snap.config_generation);
                let response = process_ipc_command(trimmed, &diagnostics, &snap.outbounds);
                if let Err(e) = writer.write_all(format!("{response}\n").as_bytes()).await {
                    tracing::debug!(error = %e, "IPC write error");
                    break;
                }
                if let Err(e) = writer.flush().await {
                    tracing::debug!(error = %e, "IPC flush error");
                    break;
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "IPC read error");
                break;
            }
        }
    }
}

/// Parses command from plain text line or JSON framing.
fn parse_command_str(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        if let Ok(val) = JsonValue::parse(trimmed) {
            if let Some(cmd) = val
                .get("command")
                .or_else(|| val.get("cmd"))
                .and_then(|v| v.as_str())
            {
                return cmd.to_string();
            }
        }
    }
    trimmed.to_string()
}

/// Evaluates an incoming IPC command and generates a JSON response line.
pub fn process_ipc_command(
    raw: &str,
    diagnostics: &DiagnosticsTracker,
    outbounds: &OutboundRegistry,
) -> String {
    let cmd = parse_command_str(raw);
    let normalized = cmd.trim().to_ascii_uppercase();

    match normalized.as_str() {
        "STATUS" => diagnostics.runtime_status().to_json(),
        "STATS" | "TRAFFIC" => diagnostics.traffic_stats().to_json(),
        "CONNECTIONS" | "CONNS" => format_connections_json(&diagnostics.active_connections()),
        "NODES" | "HEALTH" => format_nodes_json(&outbounds.health_report()),
        "PING" => r#"{"ok":true,"message":"pong"}"#.to_string(),
        _ => format!(
            r#"{{"ok":false,"error":"unknown command: {}"}}"#,
            escape_json(&cmd)
        ),
    }
}

fn format_connections_json(conns: &[ActiveConnSnapshot]) -> String {
    let list = conns
        .iter()
        .map(|c| c.to_json())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"ok":true,"active_count":{},"connections":[{}]}}"#,
        conns.len(),
        list
    )
}

fn format_nodes_json(nodes: &HashMap<String, NodeHealthReport>) -> String {
    let mut entries: Vec<String> = nodes
        .iter()
        .map(|(k, v)| format!(r#""{}":{}"#, escape_json(k), v.to_json()))
        .collect();
    entries.sort();
    format!(r#"{{"ok":true,"nodes":{{{}}}}}"#, entries.join(","))
}

/// Sends a single command to the daemon over the Unix domain socket and returns the response.
pub async fn send_command(socket_path: &Path, command: &str) -> Result<String, IpcClientError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| IpcClientError::Connect {
            path: socket_path.to_path_buf(),
            source: e,
        })?;

    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);

    writer
        .write_all(format!("{command}\n").as_bytes())
        .await
        .map_err(IpcClientError::Io)?;
    writer.flush().await.map_err(IpcClientError::Io)?;

    let mut response = String::new();
    reader
        .read_line(&mut response)
        .await
        .map_err(IpcClientError::Io)?;

    if response.ends_with('\n') {
        response.pop();
        if response.ends_with('\r') {
            response.pop();
        }
    }

    Ok(response)
}

/// Executes a CLI query command via IPC and renders human-readable or raw JSON output.
pub async fn run_cli_query(ipc_path: &Path, cmd: QueryCommand, json: bool) -> ExitCode {
    let query_string;
    let cmd_str = match &cmd {
        QueryCommand::Status => "STATUS",
        QueryCommand::Nodes => "NODES",
        QueryCommand::Connections => "CONNECTIONS",
        QueryCommand::Stats => "STATS",
        QueryCommand::Ping => "PING",
        QueryCommand::Query { target } => {
            query_string = match target.as_deref().unwrap_or("status") {
                "status" | "STATUS" => "STATUS".to_string(),
                "nodes" | "NODES" | "health" | "HEALTH" => "NODES".to_string(),
                "connections" | "CONNECTIONS" | "conns" | "CONNS" => "CONNECTIONS".to_string(),
                "stats" | "STATS" | "traffic" | "TRAFFIC" => "STATS".to_string(),
                "ping" | "PING" => "PING".to_string(),
                other => other.to_string(),
            };
            query_string.as_str()
        }
    };

    match send_command(ipc_path, cmd_str).await {
        Ok(resp) => {
            if json {
                println!("{resp}");
            } else {
                format_query_output(&cmd, &resp);
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn format_query_output(cmd: &QueryCommand, json_str: &str) {
    let val = match JsonValue::parse(json_str) {
        Ok(v) => v,
        Err(_) => {
            println!("{json_str}");
            return;
        }
    };

    if val.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        let err = val
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("Error from daemon: {err}");
        return;
    }

    match cmd {
        QueryCommand::Ping => {
            println!("PONG");
        }
        QueryCommand::Status => {
            let uptime = val.get("uptime_secs").and_then(|v| v.as_u64()).unwrap_or(0);
            let active = val
                .get("active_connections")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let max = val
                .get("max_connections")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let total = val
                .get("total_connections")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let generation = val
                .get("config_generation")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let pid = val.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);

            println!("Yachiyo Daemon Status:");
            if pid > 0 {
                println!("  PID:                {pid}");
            }
            println!("  Uptime:             {uptime}s");
            println!("  Active Connections: {active} / {max}");
            println!("  Total Connections:  {total}");
            println!("  Config Generation:  {generation}");

            if let Some(listeners) = val.get("listeners").and_then(|v| v.as_array()) {
                println!("  Listeners:");
                for l in listeners {
                    if let Some(s) = l.as_str() {
                        println!("    - {s}");
                    }
                }
            }
        }
        QueryCommand::Stats => {
            let upload = val
                .get("total_upload_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let download = val
                .get("total_download_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let total = val.get("total_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            let active = val
                .get("active_connections")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let conns = val
                .get("total_connections")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            println!("Yachiyo Traffic Statistics:");
            println!("  Upload (TX):        {upload} bytes");
            println!("  Download (RX):      {download} bytes");
            println!("  Total Transferred:  {total} bytes");
            println!("  Active Connections: {active}");
            println!("  Total Connections:  {conns}");
        }
        QueryCommand::Connections => {
            let active_count = val
                .get("active_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let conns = val
                .get("connections")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            if conns.is_empty() {
                println!("No active connections.");
            } else {
                println!("Active Connections ({active_count}):");
                for c in &conns {
                    let id = c.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                    let peer = c.get("peer_addr").and_then(|v| v.as_str()).unwrap_or("-");
                    let target = c.get("target").and_then(|v| v.as_str()).unwrap_or("-");
                    let policy = c.get("policy").and_then(|v| v.as_str()).unwrap_or("-");
                    let dur = c.get("duration_secs").and_then(|v| v.as_u64()).unwrap_or(0);
                    println!(
                        "  [{id}] peer: {peer} -> target: {target} | policy: {policy} | {dur}s"
                    );
                }
            }
        }
        QueryCommand::Nodes => {
            let nodes = val
                .get("nodes")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();

            if nodes.is_empty() {
                println!("No outbounds registered.");
            } else {
                println!("Outbound Nodes & Groups:");
                for (name, node) in &nodes {
                    let node_type = node
                        .get("node_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-");
                    let healthy = node
                        .get("healthy")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    println!("  {name} ({node_type}):");
                    println!("    Healthy: {healthy}");
                    if let Some(latency) = node.get("latency_ms").and_then(|v| v.as_u64()) {
                        println!("    Latency: {latency}ms");
                    }
                    if let Some(sel) = node.get("selected").and_then(|v| v.as_str()) {
                        println!("    Selected: {sel}");
                    }
                    if let Some(cands) = node.get("candidates").and_then(|v| v.as_array()) {
                        let cand_str: Vec<&str> = cands.iter().filter_map(|c| c.as_str()).collect();
                        println!("    Candidates: [{}]", cand_str.join(", "));
                    }
                    if let Some(srv) = node.get("server").and_then(|v| v.as_str()) {
                        println!("    Server: {srv}");
                    }
                }
            }
        }
        QueryCommand::Query { target } => {
            let normalized = target.as_deref().unwrap_or("status").to_ascii_uppercase();
            match normalized.as_str() {
                "STATUS" => format_query_output(&QueryCommand::Status, json_str),
                "STATS" | "TRAFFIC" => format_query_output(&QueryCommand::Stats, json_str),
                "CONNECTIONS" | "CONNS" => {
                    format_query_output(&QueryCommand::Connections, json_str)
                }
                "NODES" | "HEALTH" => format_query_output(&QueryCommand::Nodes, json_str),
                "PING" => format_query_output(&QueryCommand::Ping, json_str),
                _ => println!("{json_str}"),
            }
        }
    }
}

/// Lightweight JSON AST value for zero-dependency parsing of IPC response payloads.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Attempts to parse a JSON value from a string slice.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut chars = s.chars().peekable();
        skip_ws(&mut chars);
        let val = parse_val(&mut chars)?;
        skip_ws(&mut chars);
        if chars.next().is_some() {
            return Err("trailing data after JSON value".to_string());
        }
        Ok(val)
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            Self::Object(entries) => {
                for (k, v) in entries {
                    if k == key {
                        return Some(v);
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) if *n >= 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            Self::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Vec<(String, JsonValue)>> {
        match self {
            Self::Object(obj) => Some(obj),
            _ => None,
        }
    }
}

fn skip_ws<I: Iterator<Item = char>>(chars: &mut std::iter::Peekable<I>) {
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }
}

fn parse_val<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
) -> Result<JsonValue, String> {
    skip_ws(chars);
    match chars.peek() {
        Some('{') => parse_obj(chars),
        Some('[') => parse_arr(chars),
        Some('"') => parse_str(chars).map(JsonValue::String),
        Some('t') | Some('f') => parse_bool(chars),
        Some('n') => parse_null(chars),
        Some(&c) if c == '-' || c.is_ascii_digit() => parse_num(chars),
        Some(&c) => Err(format!("unexpected character '{c}'")),
        None => Err("unexpected end of input".to_string()),
    }
}

fn parse_obj<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
) -> Result<JsonValue, String> {
    chars.next(); // consume '{'
    skip_ws(chars);
    let mut entries = Vec::new();

    if let Some(&'}') = chars.peek() {
        chars.next();
        return Ok(JsonValue::Object(entries));
    }

    loop {
        skip_ws(chars);
        let key = parse_str(chars)?;
        skip_ws(chars);
        match chars.next() {
            Some(':') => {}
            Some(c) => return Err(format!("expected ':' after key, got '{c}'")),
            None => return Err("unexpected EOF in object".to_string()),
        }

        let val = parse_val(chars)?;
        entries.push((key, val));
        skip_ws(chars);

        match chars.next() {
            Some(',') => continue,
            Some('}') => break,
            Some(c) => return Err(format!("expected ',' or '}}' in object, got '{c}'")),
            None => return Err("unexpected EOF in object".to_string()),
        }
    }

    Ok(JsonValue::Object(entries))
}

fn parse_arr<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
) -> Result<JsonValue, String> {
    chars.next(); // consume '['
    skip_ws(chars);
    let mut items = Vec::new();

    if let Some(&']') = chars.peek() {
        chars.next();
        return Ok(JsonValue::Array(items));
    }

    loop {
        let val = parse_val(chars)?;
        items.push(val);
        skip_ws(chars);

        match chars.next() {
            Some(',') => continue,
            Some(']') => break,
            Some(c) => return Err(format!("expected ',' or ']' in array, got '{c}'")),
            None => return Err("unexpected EOF in array".to_string()),
        }
    }

    Ok(JsonValue::Array(items))
}

fn parse_str<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
) -> Result<String, String> {
    if chars.next() != Some('"') {
        return Err("expected '\"'".to_string());
    }

    let mut s = String::new();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Ok(s),
            '\\' => match chars.next() {
                Some('"') => s.push('"'),
                Some('\\') => s.push('\\'),
                Some('/') => s.push('/'),
                Some('b') => s.push('\u{08}'),
                Some('f') => s.push('\u{0c}'),
                Some('n') => s.push('\n'),
                Some('r') => s.push('\r'),
                Some('t') => s.push('\t'),
                Some('u') => {
                    let mut hex = String::with_capacity(4);
                    for _ in 0..4 {
                        if let Some(h) = chars.next() {
                            hex.push(h);
                        }
                    }
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(code) {
                            s.push(ch);
                        }
                    }
                }
                Some(other) => s.push(other),
                None => return Err("unexpected EOF in escape sequence".to_string()),
            },
            other => s.push(other),
        }
    }

    Err("unterminated string literal".to_string())
}

fn parse_bool<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
) -> Result<JsonValue, String> {
    let mut word = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_alphabetic() {
            word.push(c);
            chars.next();
        } else {
            break;
        }
    }
    match word.as_str() {
        "true" => Ok(JsonValue::Bool(true)),
        "false" => Ok(JsonValue::Bool(false)),
        _ => Err(format!("unknown boolean literal '{word}'")),
    }
}

fn parse_null<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
) -> Result<JsonValue, String> {
    let mut word = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_alphabetic() {
            word.push(c);
            chars.next();
        } else {
            break;
        }
    }
    if word == "null" {
        Ok(JsonValue::Null)
    } else {
        Err(format!("unknown null literal '{word}'"))
    }
}

fn parse_num<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
) -> Result<JsonValue, String> {
    let mut s = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() || c == '.' || c == '-' || c == '+' || c == 'e' || c == 'E' {
            s.push(c);
            chars.next();
        } else {
            break;
        }
    }
    s.parse::<f64>()
        .map(JsonValue::Number)
        .map_err(|e| format!("invalid number '{s}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_ipc_server_and_client_roundtrip() {
        let sock_path = PathBuf::from(format!("/tmp/test_yachiyo_ipc_{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);

        let diag = DiagnosticsTracker::new(512);
        diag.add_listener("127.0.0.1:18484".to_string());
        let outbounds = Arc::new(OutboundRegistry::new());

        let server = IpcServer::bind(&sock_path, diag.clone(), outbounds)
            .await
            .unwrap();
        assert_eq!(server.path(), &sock_path);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let srv_handle = tokio::spawn(async move {
            server.run(shutdown_rx).await.unwrap();
        });

        // Give server a moment to accept
        tokio::time::sleep(Duration::from_millis(20)).await;

        // 1. PING
        let resp = send_command(&sock_path, "PING").await.unwrap();
        assert!(resp.contains(r#""ok":true"#));
        assert!(resp.contains(r#""message":"pong""#));

        // 2. lowercase ping
        let resp = send_command(&sock_path, "ping").await.unwrap();
        assert!(resp.contains(r#""ok":true"#));

        // 3. JSON framing: {"command": "status"}
        let resp = send_command(&sock_path, r#"{"command": "status"}"#)
            .await
            .unwrap();
        assert!(resp.contains(r#""ok":true"#));
        assert!(resp.contains(r#""active_connections":0"#));
        assert!(resp.contains(r#""max_connections":512"#));

        // 4. STATS
        let resp = send_command(&sock_path, "STATS").await.unwrap();
        assert!(resp.contains(r#""ok":true"#));
        assert!(resp.contains(r#""total_upload_bytes":0"#));

        // 5. CONNECTIONS
        let resp = send_command(&sock_path, "CONNECTIONS").await.unwrap();
        assert!(resp.contains(r#""ok":true"#));
        assert!(resp.contains(r#""active_count":0"#));

        // 6. NODES
        let resp = send_command(&sock_path, "NODES").await.unwrap();
        assert!(resp.contains(r#""ok":true"#));
        assert!(resp.contains(r#""DIRECT""#));

        // 7. Unknown command
        let resp = send_command(&sock_path, "INVALID_CMD").await.unwrap();
        assert!(resp.contains(r#""ok":false"#));
        assert!(resp.contains("unknown command: INVALID_CMD"));

        shutdown_tx.send(true).unwrap();
        srv_handle.await.unwrap();

        // Verify socket file was cleaned up
        assert!(!sock_path.exists());
    }

    #[tokio::test]
    async fn test_stale_socket_recovery() {
        let sock_path = PathBuf::from(format!(
            "/tmp/test_yachiyo_stale_{}.sock",
            std::process::id()
        ));
        // Create orphaned regular file at socket path
        std::fs::write(&sock_path, b"stale data").unwrap();
        assert!(sock_path.exists());

        let diag = DiagnosticsTracker::new(10);
        let outbounds = Arc::new(OutboundRegistry::new());

        // Binding should detect stale unconnectable file, remove it, and succeed
        let server = IpcServer::bind(&sock_path, diag, outbounds).await.unwrap();
        assert!(sock_path.exists());

        drop(server);
        let _ = std::fs::remove_file(&sock_path);
    }

    #[tokio::test]
    async fn test_active_daemon_collision_returns_error() {
        let sock_path = PathBuf::from(format!(
            "/tmp/test_yachiyo_collision_{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&sock_path);

        let diag = DiagnosticsTracker::new(10);
        let outbounds = Arc::new(OutboundRegistry::new());

        let server = IpcServer::bind(&sock_path, diag.clone(), outbounds.clone())
            .await
            .unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let srv_handle = tokio::spawn(async move {
            server.run(shutdown_rx).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(20)).await;

        // Second bind with is_custom=true should fail with AddrInUse
        let res = IpcServer::bind(&sock_path, diag, outbounds).await;
        match res {
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse),
            Ok(_) => panic!("expected AddrInUse error when daemon is already active"),
        }

        let _ = shutdown_tx.send(true);
        let _ = srv_handle.await;
        let _ = std::fs::remove_file(&sock_path);
    }

    #[tokio::test]
    async fn test_ipc_reflects_live_snapshot_reload() {
        let sock_path = PathBuf::from(format!(
            "/tmp/test_yachiyo_reload_ipc_{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&sock_path);

        let diag = DiagnosticsTracker::new(64);
        let initial_snap = Arc::new(RuntimeSnapshot {
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            rules: Arc::new(RuleSet::default_direct()),
            outbounds: Arc::new(OutboundRegistry::new()),
            config_generation: 1,
        });
        let (snap_tx, snap_rx) = tokio::sync::watch::channel(initial_snap);

        let server = IpcServer::bind_with_snapshot(&sock_path, true, diag, snap_rx)
            .await
            .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let srv_handle = tokio::spawn(async move {
            server.run(shutdown_rx).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(20)).await;

        let status_v1 = send_command(&sock_path, "STATUS").await.unwrap();
        assert!(status_v1.contains(r#""config_generation":1"#));

        let parsed_cfg = yachiyo_core::Config::from_yaml_str(
            r#"
schema_version: 1
outbounds:
  reloaded_socks:
    type: socks5
    server: 192.0.2.99:1080
rules:
  - MATCH,reloaded_socks
"#,
        )
        .unwrap();
        snap_tx
            .send(Arc::new(RuntimeSnapshot {
                handshake_timeout: Duration::from_secs(10),
                connect_timeout: Duration::from_secs(10),
                idle_timeout: Duration::from_secs(300),
                rules: Arc::new(parsed_cfg.rules),
                outbounds: Arc::new(parsed_cfg.outbounds),
                config_generation: 2,
            }))
            .unwrap();

        let status_v2 = send_command(&sock_path, "STATUS").await.unwrap();
        assert!(status_v2.contains(r#""config_generation":2"#));

        let nodes_v2 = send_command(&sock_path, "NODES").await.unwrap();
        assert!(nodes_v2.contains(r#""reloaded_socks""#));

        let _ = shutdown_tx.send(true);
        let _ = srv_handle.await;
    }
}
