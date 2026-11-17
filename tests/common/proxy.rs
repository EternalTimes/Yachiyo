// SPDX-License-Identifier: AGPL-3.0-only

//! Proxy test runner fixture for starting, monitoring, and stopping the Yachiyo proxy binary.

use std::net::{SocketAddr, TcpListener};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

/// Configuration for launching the Yachiyo proxy.
#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    /// Mixed port (default is 127.0.0.1:18484 if None and no socks/http specified)
    pub mixed_addr: Option<SocketAddr>,
    /// Dedicated SOCKS5 endpoint
    pub socks_addr: Option<SocketAddr>,
    /// Dedicated HTTP CONNECT endpoint
    pub http_addr: Option<SocketAddr>,
    /// Whether to pass --allow-lan
    pub allow_lan: bool,
    /// Extra CLI arguments
    pub extra_args: Vec<String>,
}

/// Running instance of the Yachiyo proxy process.
pub struct ProxyProcess {
    child: Option<Child>,
    pub mixed_addr: Option<SocketAddr>,
    pub socks_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl ProxyProcess {
    /// Helper to find an unused loopback port outside OS ephemeral ranges (20000..32000)
    /// to avoid TOCTOU collisions with parallel tests and outbound client sockets.
    pub fn get_available_port() -> u16 {
        static NEXT_PORT: AtomicU16 = AtomicU16::new(0);
        const BASE: u16 = 20_000;
        const SPAN: u16 = 12_000;

        let pid_offset = ((std::process::id() as u16).wrapping_mul(131)) % SPAN;
        for _ in 0..SPAN {
            let seq = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
            let candidate = BASE + ((pid_offset.wrapping_add(seq)) % SPAN);
            if TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
                return candidate;
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
        listener
            .local_addr()
            .expect("Failed to get local addr")
            .port()
    }

    /// Helper to get an available IPv4 SocketAddr on 127.0.0.1.
    pub fn get_available_addr() -> SocketAddr {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            Self::get_available_port(),
        )
    }

    /// Try to start a proxy instance, or return None if binary is not yet built.
    pub async fn start_or_skip(config: ProxyConfig) -> Result<Option<Self>, String> {
        if !binary_exists() && std::env::var("YACHIYO_BIN").is_err() {
            eprintln!("[INFO] yachiyo binary not yet built; test skipped pending M3 binary.");
            return Ok(None);
        }
        Self::start(config).await.map(Some)
    }

    /// Start a proxy instance with the specified configuration.
    pub async fn start(config: ProxyConfig) -> Result<Self, String> {
        let bin_path = find_yachiyo_binary()?;
        let mut cmd = Command::new(&bin_path);

        let mut mixed = config.mixed_addr;
        let socks = config.socks_addr;
        let http = config.http_addr;

        if let Some(m) = mixed {
            cmd.arg("--mixed").arg(m.to_string());
        }
        if let Some(s) = socks {
            cmd.arg("--socks").arg(s.to_string());
        }
        if let Some(h) = http {
            cmd.arg("--http").arg(h.to_string());
        }
        if config.allow_lan {
            cmd.arg("--allow-lan");
        }
        for arg in &config.extra_args {
            cmd.arg(arg);
        }

        // If no explicit listener argument is provided, default mixed is 127.0.0.1:18484
        if mixed.is_none() && socks.is_none() && http.is_none() {
            mixed = Some("127.0.0.1:18484".parse().unwrap());
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn yachiyo binary at {}: {}", bin_path, e))?;

        let logs = Arc::new(Mutex::new(Vec::new()));

        // Capture stdout
        if let Some(stdout) = child.stdout.take() {
            let logs_clone = Arc::clone(&logs);
            tokio::spawn(async move {
                let mut reader = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    logs_clone.lock().await.push(line);
                }
            });
        }

        // Capture stderr
        if let Some(stderr) = child.stderr.take() {
            let logs_clone = Arc::clone(&logs);
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    logs_clone.lock().await.push(line);
                }
            });
        }

        // Wait for proxy port(s) to become reachable
        let ports_to_check: Vec<SocketAddr> = [mixed, socks, http].into_iter().flatten().collect();

        for addr in &ports_to_check {
            if let Err(err) = wait_for_port(&mut child, *addr, Duration::from_secs(5)).await {
                let captured = logs.lock().await.join("\n");
                return Err(format!("{err}\n--- proxy logs ---\n{captured}"));
            }
        }

        Ok(Self {
            child: Some(child),
            mixed_addr: mixed,
            socks_addr: socks,
            http_addr: http,
            logs,
        })
    }

    /// Try to run proxy with expecting an immediate failure (e.g. non-loopback without --allow-lan).
    pub async fn run_expecting_failure(args: &[&str]) -> Result<std::process::Output, String> {
        Self::run_cli(args).await
    }

    /// Invoke the `yachiyo` binary as a short-lived CLI command (e.g. `--check` or IPC queries)
    /// and return its captured stdout/stderr/status.
    pub async fn run_cli(args: &[&str]) -> Result<std::process::Output, String> {
        let bin_path = find_yachiyo_binary()?;
        let output = Command::new(&bin_path)
            .args(args)
            .output()
            .await
            .map_err(|e| format!("Failed to run yachiyo: {}", e))?;
        Ok(output)
    }

    /// Get captured logs as a single string.
    pub async fn dump_logs(&self) -> String {
        let lines = self.logs.lock().await;
        lines.join("\n")
    }

    /// Assert that none of the forbidden payloads exist in the captured logs (Zero Payload Logging rule).
    pub async fn assert_zero_payload_logging(&self, forbidden_payloads: &[&str]) {
        let logs = self.dump_logs().await;
        for forbidden in forbidden_payloads {
            assert!(
                !logs.contains(forbidden),
                "VIOLATION: Zero-payload logging rule broken! Log contains payload: {:?}",
                forbidden
            );
        }
    }

    /// Send SIGINT (Ctrl+C) to trigger graceful shutdown.
    #[cfg(unix)]
    pub fn send_sigint(&mut self) -> Result<(), std::io::Error> {
        if let Some(ref child) = self.child {
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGINT);
                }
                return Ok(());
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Child process not found",
        ))
    }

    /// Send SIGTERM to trigger graceful shutdown.
    #[cfg(unix)]
    pub fn send_sigterm(&mut self) -> Result<(), std::io::Error> {
        if let Some(ref child) = self.child {
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                return Ok(());
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Child process not found",
        ))
    }

    /// Send SIGHUP to the proxy process to trigger configuration snapshot reload.
    #[cfg(unix)]
    pub fn send_sighup(&self) -> Result<(), String> {
        let child = self.child.as_ref().ok_or("No child process")?;
        let pid = child.id().ok_or("Child process has no PID")?;
        let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGHUP) };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!(
                "Failed to send SIGHUP: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    /// Wait for the proxy process to exit with a given timeout.
    pub async fn wait_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<std::process::ExitStatus, String> {
        if let Some(mut child) = self.child.take() {
            match tokio::time::timeout(timeout, child.wait()).await {
                Ok(Ok(status)) => Ok(status),
                Ok(Err(e)) => Err(format!("Process wait error: {}", e)),
                Err(_) => {
                    let _ = child.kill().await;
                    Err("Process did not exit within timeout".to_string())
                }
            }
        } else {
            Err("No child process".to_string())
        }
    }

    /// Terminate and cleanup immediately.
    pub async fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
    }
}

async fn wait_for_port(
    child: &mut Child,
    addr: SocketAddr,
    timeout: Duration,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "Proxy process exited prematurely with status {} while waiting for {}",
                status, addr
            ));
        }
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!(
        "Timed out waiting for proxy port {} to become reachable",
        addr
    ))
}

/// Check if the yachiyo CLI binary has been compiled and is available.
pub fn binary_exists() -> bool {
    let candidates = [
        "target/debug/yachiyo",
        "target/release/yachiyo",
        "../target/debug/yachiyo",
        "../../target/debug/yachiyo",
    ];

    for candidate in &candidates {
        if std::path::Path::new(candidate).is_file() {
            return true;
        }
    }
    false
}

fn find_yachiyo_binary() -> Result<String, String> {
    let candidates = [
        "target/debug/yachiyo",
        "target/release/yachiyo",
        "../target/debug/yachiyo",
        "../../target/debug/yachiyo",
    ];

    for candidate in &candidates {
        let path = std::path::Path::new(candidate);
        if path.is_file() {
            return Ok(path.to_string_lossy().to_string());
        }
    }

    if let Ok(path) = std::env::var("YACHIYO_BIN") {
        if std::path::Path::new(&path).is_file() {
            return Ok(path);
        }
    }

    Err("yachiyo binary not found. Build with `cargo build -p yachiyo-cli`".to_string())
}
