// SPDX-License-Identifier: AGPL-3.0-only

//! Adversarial test suite for Project Yachiyo CLI lifecycle coordination and Zero Payload Policy.
//!
//! Validates:
//! 1. Graceful shutdown lifecycle:
//!    - Signal before any connections -> immediate clean exit (exit code 0).
//!    - Signal with connections draining within 5s -> clean exit (exit code 0).
//!    - Signal with connections stalled beyond 5s drain timeout -> forced abort (exit code 1).
//!    - Immediate rejection / refusal of new connections after termination signal.
//!    - Rapid multiple signals (SIGINT + SIGTERM) handled safely without panic.
//! 2. Zero Payload Policy leak test:
//!    - High-volume simulated traffic containing diverse canary tokens at TRACE log level.
//!    - Verification that ZERO canary tokens or token fragments appear in stdout/stderr logs,
//!      while connection metadata (target host, port, stats) is logged.
//! 3. In-process signal drain coordinator concurrency stress tests.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use yachiyo_cli::signal::{ShutdownOutcome, drain_connections};
use yachiyo_core::ConnectionTracker;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

/// Helper to get an available loopback port.
fn get_available_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Running child process fixture with log capturing and signal dispatching.
struct ProcessFixture {
    child: Option<std::process::Child>,
    pub addr: SocketAddr,
    logs: Arc<Mutex<Vec<u8>>>,
}

impl ProcessFixture {
    fn spawn(extra_args: &[&str]) -> Self {
        let port = get_available_port();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let bin = env!("CARGO_BIN_EXE_yachiyo");

        let mut cmd = std::process::Command::new(bin);
        cmd.arg("--mixed").arg(addr.to_string());
        for arg in extra_args {
            cmd.arg(arg);
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn yachiyo binary");

        let logs = Arc::new(Mutex::new(Vec::new()));

        // Stream stdout into shared buffer
        if let Some(stdout) = child.stdout.take() {
            let logs_clone = Arc::clone(&logs);
            std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(stdout);
                let mut buf = [0u8; 1024];
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    logs_clone.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
        }

        // Stream stderr into shared buffer
        if let Some(stderr) = child.stderr.take() {
            let logs_clone = Arc::clone(&logs);
            std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(stderr);
                let mut buf = [0u8; 1024];
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    logs_clone.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
        }

        // Await readiness: listener active log
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(10);
        let mut ready = false;
        while start.elapsed() < timeout {
            if let Ok(Some(exit)) = child.try_wait() {
                let current_logs = logs.lock().unwrap();
                panic!(
                    "yachiyo process exited prematurely with {:?}: {}",
                    exit,
                    String::from_utf8_lossy(&current_logs)
                );
            }
            {
                let current_logs = logs.lock().unwrap();
                let text = String::from_utf8_lossy(&current_logs);
                if text.contains("listener active and ready for connections") {
                    ready = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        // Give a tiny grace period for the accept loop to enter poll
        std::thread::sleep(Duration::from_millis(30));
        assert!(ready, "yachiyo listener failed to report ready within 10s");

        Self {
            child: Some(child),
            addr,
            logs,
        }
    }

    #[cfg(unix)]
    fn send_signal(&self, sig: i32) {
        if let Some(ref child) = self.child {
            let pid = child.id() as i32;
            unsafe {
                let ret = kill(pid, sig);
                assert_eq!(
                    ret,
                    0,
                    "kill({}, {}) failed with errno {}",
                    pid,
                    sig,
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    async fn wait_with_timeout_async(
        &mut self,
        timeout: Duration,
    ) -> Result<std::process::ExitStatus, ()> {
        if let Some(mut child) = self.child.take() {
            let start = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return Ok(status),
                    Ok(None) => {
                        if start.elapsed() > timeout {
                            let _ = child.kill();
                            return Err(());
                        }
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                    Err(_) => {
                        let _ = child.kill();
                        return Err(());
                    }
                }
            }
        } else {
            Err(())
        }
    }

    fn wait_with_timeout(&mut self, timeout: Duration) -> Result<std::process::ExitStatus, ()> {
        if let Some(mut child) = self.child.take() {
            let start = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return Ok(status),
                    Ok(None) => {
                        if start.elapsed() > timeout {
                            let _ = child.kill();
                            return Err(());
                        }
                        std::thread::sleep(Duration::from_millis(30));
                    }
                    Err(_) => {
                        let _ = child.kill();
                        return Err(());
                    }
                }
            }
        } else {
            Err(())
        }
    }

    fn get_logs(&self) -> String {
        std::thread::sleep(Duration::from_millis(50));
        let bytes = self.logs.lock().unwrap().clone();
        String::from_utf8_lossy(&bytes).to_string()
    }
}

impl Drop for ProcessFixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Simple echo server for testing tunnel data flow.
struct EchoServer {
    addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl EchoServer {
    async fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_res = listener.accept() => {
                        let Ok((mut socket, _)) = accept_res else { break };
                        tokio::spawn(async move {
                            eprintln!("[EchoServer] connection accepted");
                            let mut buf = [0u8; 2048];
                            loop {
                                match socket.read(&mut buf).await {
                                    Ok(0) => {
                                        eprintln!("[EchoServer] read 0 (EOF), breaking loop and dropping socket");
                                        break;
                                    }
                                    Ok(n) => {
                                        eprintln!("[EchoServer] read {} bytes, echoing back", n);
                                        if socket.write_all(&buf[..n]).await.is_err() {
                                            eprintln!("[EchoServer] write_all failed");
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[EchoServer] read err: {e}");
                                        break;
                                    }
                                }
                            }
                            eprintln!("[EchoServer] connection task finished");
                        });
                    }
                }
            }
        });

        Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Blackhole server that accepts connections and holds them open indefinitely.
struct BlackholeServer {
    addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl BlackholeServer {
    async fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind blackhole");
        let addr = listener.local_addr().expect("blackhole addr");
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let mut clients = Vec::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((socket, _)) = accept_res {
                            clients.push(socket);
                        } else {
                            break;
                        }
                    }
                }
            }
        });

        Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
        }
    }
}

impl Drop for BlackholeServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Helper to execute SOCKS5 unauthenticated handshake to an IPv4 destination.
async fn socks5_handshake(
    stream: &mut TcpStream,
    target: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Client greeting: VER=5, NMETHODS=1, METHOD=0 (NO_AUTH)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await?;
    assert_eq!(
        method_resp,
        [0x05, 0x00],
        "SOCKS5 method negotiation failed"
    );

    // 2. Client CONNECT request: ATYP=0x01 (IPv4)
    let ip = match target.ip() {
        IpAddr::V4(v4) => v4.octets(),
        _ => panic!("Expected IPv4 for test target"),
    };
    let port = target.port();
    let req = [
        0x05,
        0x01,
        0x00,
        0x01,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        (port >> 8) as u8,
        (port & 0xFF) as u8,
    ];
    stream.write_all(&req).await?;

    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).await?;
    assert_eq!(resp[0], 0x05, "SOCKS5 reply version must be 5");
    assert_eq!(resp[1], 0x00, "SOCKS5 reply status must be 0x00 (SUCCESS)");

    Ok(())
}

/// Helper to execute HTTP CONNECT handshake to an IPv4 destination.
async fn http_connect_handshake(
    stream: &mut TcpStream,
    target: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        target.ip(),
        target.port(),
        target.ip(),
        target.port()
    );
    stream.write_all(req.as_bytes()).await?;

    let mut resp = Vec::new();
    let mut buf = [0u8; 1];
    while !resp.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err("EOF while reading HTTP CONNECT response".into());
        }
        resp.push(buf[0]);
    }

    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.starts_with("HTTP/1.1 200") || resp_str.starts_with("HTTP/1.0 200"),
        "Unexpected HTTP response: {}",
        resp_str
    );

    Ok(())
}

// ============================================================================
// Lifecycle & Signal Drain Empirical Tests
// ============================================================================

#[test]
#[cfg(unix)]
fn test_signal_before_connections_immediate_clean_exit() {
    let mut proc = ProcessFixture::spawn(&[]);

    // Send SIGTERM immediately before any connections are initiated
    proc.send_signal(SIGTERM);

    let status = proc
        .wait_with_timeout(Duration::from_secs(3))
        .expect("Process failed to exit within 3s upon SIGTERM");

    assert!(
        status.success(),
        "Expected clean exit code 0 when signal received with no connections, got {:?}",
        status.code()
    );

    let logs = proc.get_logs();
    assert!(
        logs.contains("Received termination signal, stopping listener and draining connections..."),
        "Expected shutdown notice in logs: {logs}"
    );
    assert!(
        logs.contains("All connections drained cleanly. Exiting."),
        "Expected clean drain confirmation in logs: {logs}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn test_signal_connections_draining_within_5s_clean_exit() {
    let echo = EchoServer::bind().await;
    let mut proc = ProcessFixture::spawn(&["--log-level", "trace"]);

    let mut stream = TcpStream::connect(proc.addr)
        .await
        .expect("connect to yachiyo");
    socks5_handshake(&mut stream, echo.addr)
        .await
        .expect("socks5 handshake");

    // Signal proxy via SIGINT while connection is active
    proc.send_signal(SIGINT);

    // Actively transfer data and cleanly close connection within ~100ms (< 5s)
    let payload = b"ActivePayloadDrainingCleanlyWithinDeadline";
    stream.write_all(payload).await.expect("write payload");
    let mut echo_buf = vec![0u8; payload.len()];
    stream
        .read_exact(&mut echo_buf)
        .await
        .expect("read echo payload");
    assert_eq!(&echo_buf, payload);

    // Shutdown write half to send FIN, then drop stream
    let _ = stream.shutdown().await;
    drop(stream);

    let status = match proc.wait_with_timeout_async(Duration::from_secs(5)).await {
        Ok(s) => s,
        Err(()) => {
            eprintln!("LOGS ON TIMEOUT:\n{}", proc.get_logs());
            panic!("Process failed to exit within 5s");
        }
    };

    let logs = proc.get_logs();

    assert_eq!(
        status.code(),
        Some(0),
        "Expected exit code 0 on clean connection drain"
    );
    assert!(
        logs.contains("All connections drained cleanly. Exiting."),
        "Expected clean drain log: {logs}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn test_signal_connections_stalled_beyond_5s_forced_abort() {
    let blackhole = BlackholeServer::bind().await;
    let mut proc = ProcessFixture::spawn(&[]);

    let mut held_stream = TcpStream::connect(proc.addr)
        .await
        .expect("connect to yachiyo");
    socks5_handshake(&mut held_stream, blackhole.addr)
        .await
        .expect("socks5 handshake to blackhole");

    // Signal proxy via SIGTERM while connection is stalled
    proc.send_signal(SIGTERM);

    // Keep held_stream alive and idle, refusing to drain
    // Wait for the 5-second drain timeout to expire (allow up to 7s)
    let status = proc
        .wait_with_timeout_async(Duration::from_secs(7))
        .await
        .expect("Process did not exit after drain timeout");

    assert_eq!(
        status.code(),
        Some(1),
        "Expected exit code 1 when connections exceed 5s drain timeout, got {:?}",
        status.code()
    );

    let logs = proc.get_logs();
    assert!(
        logs.contains("Drain timeout reached, 1 active connection(s) forcefully aborted."),
        "Expected forced abort log with count 1: {logs}"
    );

    drop(held_stream);
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn test_rejection_of_new_connections_after_signal() {
    let echo = EchoServer::bind().await;
    let mut proc = ProcessFixture::spawn(&[]);

    // Establish connection 1 to hold the proxy in drain state
    let mut held_stream = TcpStream::connect(proc.addr)
        .await
        .expect("connect connection 1");
    socks5_handshake(&mut held_stream, echo.addr)
        .await
        .expect("handshake 1");

    // Send SIGTERM to initiate drain and stop accept loop
    proc.send_signal(SIGTERM);

    // Give proxy ~100ms to process signal and close listener accept loop
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Attempt to establish a new connection (Client 2)
    // The listener socket MUST reject or close the incoming connection immediately
    let connect_res = TcpStream::connect(proc.addr).await;
    match connect_res {
        Err(e) => {
            // ConnectionRefused or ConnectionReset confirms accept loop closed
            assert!(
                e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.kind() == std::io::ErrorKind::ConnectionReset,
                "Expected ConnectionRefused or ConnectionReset, got {:?}",
                e
            );
        }
        Ok(mut stream) => {
            // If connection slipped into socket backlog right at signal time,
            // handshake must fail and socket must return EOF / close immediately
            let mut test_buf = [0u8; 1];
            let read_res = stream.read(&mut test_buf).await;
            assert!(
                read_res.is_err() || read_res.unwrap() == 0,
                "New connection after signal was not terminated immediately"
            );
        }
    }

    // Cleanly finish connection 1 so proxy can exit cleanly with code 0
    let _ = held_stream.shutdown().await;
    drop(held_stream);

    let status = proc
        .wait_with_timeout_async(Duration::from_secs(5))
        .await
        .expect("proxy exit");
    assert_eq!(
        status.code(),
        Some(0),
        "Expected clean exit code 0 after active connection drains"
    );
}

#[test]
#[cfg(unix)]
fn test_multiple_rapid_signals_handled_safely() {
    let mut proc = ProcessFixture::spawn(&[]);

    // Rapidly bombard the process with alternating signals
    proc.send_signal(SIGINT);
    proc.send_signal(SIGTERM);
    proc.send_signal(SIGINT);
    proc.send_signal(SIGTERM);

    let status = proc
        .wait_with_timeout(Duration::from_secs(3))
        .expect("Process failed to exit after multiple rapid signals");

    assert!(
        status.success(),
        "Expected clean exit code 0, got {:?}",
        status.code()
    );

    let logs = proc.get_logs();
    assert!(
        !logs.contains("panicked"),
        "Process must not panic on rapid signals"
    );
}

// ============================================================================
// Zero Payload Policy Leak Empirical Tests
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn test_zero_payload_policy_leak_test_high_volume_traffic_trace_level() {
    let echo = EchoServer::bind().await;
    // Launch proxy with --log-level trace for maximum verbosity audit
    let mut proc = ProcessFixture::spawn(&["--log-level", "trace"]);

    let canary_tokens = [
        "CANARY_SECRET_AUTH_HEADER_Bearer_eyJhbGciOiJIUzI1NiJ9",
        "CANARY_SECRET_PASSWORD_P@ssw0rd12345!#$",
        "CANARY_SOCKS5_PAYLOAD_CHUNK_XYZ_778899",
        "CANARY_HTTP_PIPELINED_DATA_TOP_SECRET_112233",
        "CANARY_CONFIDENTIAL_PAYLOAD_TOKEN_HEX_DEADBEEFCAFE",
    ];

    // 1. SOCKS5 traffic with canary tokens
    {
        let mut stream = TcpStream::connect(proc.addr).await.expect("socks5 connect");
        socks5_handshake(&mut stream, echo.addr)
            .await
            .expect("socks5 handshake");

        for token in &canary_tokens[0..2] {
            let msg = format!("SECURE_MESSAGE:{token}\n");
            stream
                .write_all(msg.as_bytes())
                .await
                .expect("write canary");
            let mut resp = vec![0u8; msg.len()];
            stream.read_exact(&mut resp).await.expect("read echo");
            assert_eq!(resp, msg.as_bytes());
        }
        let _ = stream.shutdown().await;
        drop(stream);
    }

    // 2. HTTP CONNECT traffic with canary tokens
    {
        let mut stream = TcpStream::connect(proc.addr).await.expect("http connect");
        http_connect_handshake(&mut stream, echo.addr)
            .await
            .expect("http handshake");

        for token in &canary_tokens[2..4] {
            let msg = format!("HTTP_PAYLOAD:{token}\n");
            stream
                .write_all(msg.as_bytes())
                .await
                .expect("write canary");
            let mut resp = vec![0u8; msg.len()];
            stream.read_exact(&mut resp).await.expect("read echo");
            assert_eq!(resp, msg.as_bytes());
        }
        let _ = stream.shutdown().await;
        drop(stream);
    }

    // 3. High-volume 64KB multi-chunk stream containing canary token 4
    {
        let mut stream = TcpStream::connect(proc.addr)
            .await
            .expect("high volume connect");
        socks5_handshake(&mut stream, echo.addr)
            .await
            .expect("socks5 handshake");

        let chunk = format!(
            "BLOCK_DATA_{}_CHUNK_FILLER_BYTES_1234567890\n",
            canary_tokens[4]
        );
        let chunk_bytes = chunk.as_bytes();

        for _ in 0..64 {
            stream.write_all(chunk_bytes).await.expect("write chunk");
            let mut resp = vec![0u8; chunk_bytes.len()];
            stream.read_exact(&mut resp).await.expect("read chunk");
            assert_eq!(resp, chunk_bytes);
        }
        let _ = stream.shutdown().await;
        drop(stream);
    }

    // Gracefully shut down proxy
    proc.send_signal(SIGINT);
    let status = proc
        .wait_with_timeout_async(Duration::from_secs(6))
        .await
        .expect("proxy exit");
    assert!(status.success());

    // Inspect captured logs
    let logs = proc.get_logs();
    assert!(
        !logs.is_empty(),
        "Captured logs must not be empty at TRACE level"
    );

    // Verify metadata IS recorded
    assert!(
        logs.contains(&echo.addr.port().to_string()),
        "Target port must appear in logs: {logs}"
    );

    // Verify ZERO canary tokens appear anywhere in the logs
    for token in &canary_tokens {
        assert!(
            !logs.contains(token),
            "CRITICAL SECURITY VIOLATION: Zero Payload Policy violated! Canary token found in log: {token}"
        );
    }

    // Also check partial prefixes to ensure no buffer slice fragments leaked
    let canary_prefixes = [
        "CANARY_SECRET_AUTH",
        "CANARY_SECRET_PASSWORD",
        "CANARY_SOCKS5_PAYLOAD",
        "CANARY_HTTP_PIPELINED",
        "CANARY_CONFIDENTIAL",
    ];
    for prefix in &canary_prefixes {
        assert!(
            !logs.contains(prefix),
            "CRITICAL SECURITY VIOLATION: Canary prefix fragment '{prefix}' found in logs!"
        );
    }
}

// ============================================================================
// Direct In-Process Concurrency Stress Tests
// ============================================================================

#[tokio::test]
async fn test_drain_coordinator_rapid_cancellation_and_concurrent_guards() {
    let (tx, rx) = watch::channel(false);
    let tracker = ConnectionTracker::new(100);

    // Acquire 10 guards
    let mut guards = Vec::new();
    for _ in 0..10 {
        guards.push(tracker.try_acquire().expect("acquire guard"));
    }
    assert_eq!(tracker.active_count(), 10);

    // Spawn drain task in background
    let tracker_clone = tracker.clone();
    let tx_clone = tx.clone();
    let drain_handle = tokio::spawn(async move {
        drain_connections(&tx_clone, &tracker_clone, Duration::from_millis(500)).await
    });

    // Concurrently drop guards gradually
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(*rx.borrow(), "shutdown signal must be set immediately");

    // Drop 5 guards
    guards.truncate(5);
    assert_eq!(tracker.active_count(), 5);

    // Drop remaining 5 guards before the 500ms deadline
    tokio::time::sleep(Duration::from_millis(50)).await;
    guards.clear();
    assert_eq!(tracker.active_count(), 0);

    let outcome = drain_handle.await.expect("join drain handle");
    assert_eq!(outcome, ShutdownOutcome::Clean);
    assert_eq!(outcome.exit_code(), std::process::ExitCode::SUCCESS);
    assert_eq!(outcome.remaining_count(), 0);
    assert!(outcome.is_clean());
}

#[tokio::test]
async fn test_drain_coordinator_stalled_guards_timeout_remaining_count() {
    let (tx, _rx) = watch::channel(false);
    let tracker = ConnectionTracker::new(100);

    let g1 = tracker.try_acquire().expect("acquire guard 1");
    let g2 = tracker.try_acquire().expect("acquire guard 2");
    let g3 = tracker.try_acquire().expect("acquire guard 3");
    assert_eq!(tracker.active_count(), 3);

    // Drain with very short timeout of 50ms while keeping 3 guards active
    let outcome = drain_connections(&tx, &tracker, Duration::from_millis(50)).await;

    assert_eq!(outcome, ShutdownOutcome::ForcedTimeout { remaining: 3 });
    assert_eq!(outcome.exit_code(), std::process::ExitCode::FAILURE);
    assert_eq!(outcome.remaining_count(), 3);
    assert!(!outcome.is_clean());

    drop((g1, g2, g3));
    assert_eq!(tracker.active_count(), 0);
}
