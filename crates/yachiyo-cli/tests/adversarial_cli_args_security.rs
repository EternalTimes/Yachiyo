// SPDX-License-Identifier: AGPL-3.0-only

//! Empirical Adversarial & Security Stress Test Suite for `crates/yachiyo-cli`.
//!
//! Stress-tests:
//! 1. Loopback Security Evasion Attempts (IPv4, IPv6, mapped IPv6, LAN, public, broadcast).
//! 2. `--allow-lan` pre-flight authorization and binding permissions.
//! 3. Listener Isolation Edge Cases (independent --socks, independent --http, combined, isolation from default mixed).
//! 4. Malformed CLI Arguments and Bounds Checking (syntax, port limits, conflicting flags, log directives).
//! 5. Process Lifecycle, Signal Coordination (clean 0 vs forced abort 1), and Zero-Payload Logging Audit.

use clap::Parser;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use yachiyo_cli::args::{CliArgs, DEFAULT_MIXED_ADDR, is_loopback_addr};

// =========================================================================
// Test Fixtures & Utilities
// =========================================================================

/// Locates the compiled `yachiyo` CLI binary.
fn yachiyo_bin() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_yachiyo") {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }
    let candidates = [
        "../../target/debug/yachiyo",
        "../target/debug/yachiyo",
        "target/debug/yachiyo",
    ];
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return p.canonicalize().unwrap_or(p);
        }
    }
    if let Ok(mut exe) = std::env::current_exe() {
        exe.pop(); // test runner binary
        if exe.ends_with("deps") {
            exe.pop();
        }
        exe.push("yachiyo");
        if exe.exists() {
            return exe;
        }
    }
    panic!("yachiyo binary not found; please build with `cargo build --bin yachiyo`");
}

/// Finds an available ephemeral port on loopback.
fn get_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
    listener
        .local_addr()
        .expect("Failed to get local addr")
        .port()
}

/// Helper RAII guard that manages child proxy processes and ensures cleanup.
struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    /// Sends a POSIX signal to the child process via the OS `kill` command.
    fn send_signal(&self, signal_flag: &str) -> Result<(), std::io::Error> {
        if let Some(ref child) = self.child {
            let pid = child.id();
            let status = Command::new("kill")
                .args([signal_flag, &pid.to_string()])
                .status()?;
            if status.success() {
                return Ok(());
            }
        }
        Err(std::io::Error::other("failed to deliver signal to child"))
    }

    /// Awaits process exit and returns its exit status.
    async fn wait_exit(mut self) -> std::process::ExitStatus {
        let mut child = self.child.take().expect("child process exists");
        tokio::task::spawn_blocking(move || child.wait().expect("failed to wait on child process"))
            .await
            .expect("spawn_blocking panicked")
    }

    /// Takes the child process out of the guard, for instance to read its output.
    fn take_child(&mut self) -> Option<Child> {
        self.child.take()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Waits for a given socket address to accept TCP connections.
async fn wait_for_port(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    Err(format!(
        "Timed out waiting for port {addr} to become reachable within {timeout:?}"
    ))
}

/// Runs the CLI binary expecting it to exit immediately with an error.
async fn run_binary_expecting_error(args: &[&str]) -> (i32, String, String) {
    let bin = yachiyo_bin();
    let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(&bin)
            .args(&args_owned)
            .output()
            .unwrap_or_else(|e| panic!("Failed to run binary {bin:?}: {e}"))
    })
    .await
    .expect("spawn_blocking panicked");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

// =========================================================================
// Suite 1: Loopback Security Evasion Stress-Testing
// =========================================================================

#[test]
fn test_adversarial_is_loopback_classification() {
    // Valid IPv4 loopback (127.0.0.0/8)
    assert!(is_loopback_addr(&"127.0.0.1:18484".parse().unwrap()));
    assert!(is_loopback_addr(&"127.0.0.254:1080".parse().unwrap()));
    assert!(is_loopback_addr(&"127.123.45.67:8080".parse().unwrap()));
    assert!(is_loopback_addr(&"127.255.255.254:18484".parse().unwrap()));

    // Valid IPv6 loopback (::1)
    assert!(is_loopback_addr(&"[::1]:18484".parse().unwrap()));

    // IPv4-mapped IPv6 loopback (::ffff:127.x.x.x)
    assert!(is_loopback_addr(
        &"[::ffff:127.0.0.1]:18484".parse().unwrap()
    ));
    assert!(is_loopback_addr(
        &"[::ffff:127.255.255.254]:1080".parse().unwrap()
    ));

    // Adversarial non-loopback IPv4 evasion candidates
    assert!(!is_loopback_addr(&"0.0.0.0:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"192.168.1.1:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"10.0.0.1:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"172.16.0.1:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"1.1.1.1:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"8.8.8.8:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"169.254.1.1:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"224.0.0.1:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"255.255.255.255:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"100.64.0.1:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"240.0.0.1:18484".parse().unwrap()));

    // Adversarial non-loopback IPv6 evasion candidates
    assert!(!is_loopback_addr(&"[::]:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"[fe80::1]:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"[fd00::1]:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"[fc00::1]:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"[ff02::1]:18484".parse().unwrap()));
    assert!(!is_loopback_addr(&"[2001:db8::1]:18484".parse().unwrap()));
    assert!(!is_loopback_addr(
        &"[2606:4700:4700::1111]:18484".parse().unwrap()
    ));

    // Adversarial IPv4-mapped IPv6 non-loopback evasion attempts
    assert!(!is_loopback_addr(
        &"[::ffff:0.0.0.0]:18484".parse().unwrap()
    ));
    assert!(!is_loopback_addr(
        &"[::ffff:192.168.1.1]:18484".parse().unwrap()
    ));
    assert!(!is_loopback_addr(
        &"[::ffff:8.8.8.8]:18484".parse().unwrap()
    ));
}

#[tokio::test]
async fn test_adversarial_binary_rejects_unspecified_ipv4_exit_code_1() {
    let (code, stdout, stderr) = run_binary_expecting_error(&["--mixed", "0.0.0.0:18484"]).await;
    assert_eq!(
        code, 1,
        "Binding to 0.0.0.0 without --allow-lan must exit with code 1. Stdout: {stdout}, Stderr: {stderr}"
    );
    assert!(
        stderr.contains("pre-flight security validation failed")
            || stderr.contains("Security error"),
        "Expected security validation failure in stderr: {stderr}"
    );
    assert!(
        stderr.contains("--allow-lan"),
        "Error message must instruct user to provide --allow-lan: {stderr}"
    );
}

#[tokio::test]
async fn test_adversarial_binary_rejects_unspecified_ipv6_exit_code_1() {
    let (code, _stdout, stderr) = run_binary_expecting_error(&["--mixed", "[::]:18484"]).await;
    assert_eq!(
        code, 1,
        "Binding to [::] without --allow-lan must exit with code 1"
    );
    assert!(
        stderr.contains("pre-flight security validation failed")
            || stderr.contains("Security error")
    );
    assert!(stderr.contains("--allow-lan"));
}

#[tokio::test]
async fn test_adversarial_binary_rejects_lan_ips_exit_code_1() {
    let lan_addrs = [
        "192.168.1.1:18484",
        "10.0.0.1:18484",
        "172.16.0.1:18484",
        "192.168.100.254:18484",
    ];

    for addr in lan_addrs {
        let (code, _stdout, stderr) = run_binary_expecting_error(&["--mixed", addr]).await;
        assert_eq!(
            code, 1,
            "Binding to LAN address {addr} without --allow-lan must exit with code 1"
        );
        assert!(
            stderr.contains("must specify --allow-lan"),
            "Stderr should enforce --allow-lan requirement: {stderr}"
        );
    }
}

#[tokio::test]
async fn test_adversarial_binary_rejects_ipv6_link_local_exit_code_1() {
    let (code, _stdout, stderr) = run_binary_expecting_error(&["--mixed", "[fe80::1]:18484"]).await;
    assert_eq!(
        code, 1,
        "Binding to [fe80::1] link-local without --allow-lan must exit with code 1"
    );
    assert!(stderr.contains("must specify --allow-lan"));
}

#[tokio::test]
async fn test_adversarial_binary_rejects_mapped_ipv6_evasion_exit_code_1() {
    // Evasion attempt: prefixing non-loopback IPv4 with IPv4-mapped IPv6 syntax ::ffff:
    let mapped_evasion_addrs = [
        "[::ffff:0.0.0.0]:18484",
        "[::ffff:192.168.1.1]:18484",
        "[::ffff:10.0.0.1]:18484",
        "[::ffff:8.8.8.8]:18484",
    ];

    for addr in mapped_evasion_addrs {
        let (code, _stdout, stderr) = run_binary_expecting_error(&["--mixed", addr]).await;
        assert_eq!(
            code, 1,
            "Binding to mapped non-loopback {addr} without --allow-lan must exit with code 1"
        );
        assert!(stderr.contains("must specify --allow-lan"));
    }
}

#[tokio::test]
async fn test_adversarial_binary_rejects_dedicated_flags_without_allow_lan() {
    // Dedicated --socks
    let (code, _stdout, stderr) = run_binary_expecting_error(&["--socks", "0.0.0.0:1080"]).await;
    assert_eq!(code, 1);
    assert!(stderr.contains("--socks"));
    assert!(stderr.contains("must specify --allow-lan"));

    // Dedicated --http
    let (code, _stdout, stderr) = run_binary_expecting_error(&["--http", "[::]:8080"]).await;
    assert_eq!(code, 1);
    assert!(stderr.contains("--http"));
    assert!(stderr.contains("must specify --allow-lan"));

    // Combination: one valid loopback socks + one non-loopback http
    let (code, _stdout, stderr) =
        run_binary_expecting_error(&["--socks", "127.0.0.1:1080", "--http", "192.168.1.50:8080"])
            .await;
    assert_eq!(
        code, 1,
        "Partial non-loopback combination must fail pre-flight validation"
    );
    assert!(stderr.contains("--http"));
}

#[tokio::test]
async fn test_adversarial_allow_lan_permits_binding_unspecified() {
    let port = get_available_port();
    let bin = yachiyo_bin();

    // Spawning proxy on 0.0.0.0 WITH --allow-lan
    let mut cmd = Command::new(&bin);
    cmd.args(["--allow-lan", "--mixed", &format!("0.0.0.0:{port}")]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd
        .spawn()
        .expect("failed to spawn yachiyo with --allow-lan");
    let guard = ChildGuard::new(child);

    // Verify socket becomes reachable over loopback
    let target = format!("127.0.0.1:{port}").parse().unwrap();
    let wait_res = wait_for_port(target, Duration::from_secs(5)).await;
    assert!(
        wait_res.is_ok(),
        "Proxy should successfully bind 0.0.0.0 with --allow-lan and accept connections: {wait_res:?}"
    );

    // Gracefully terminate child
    guard.send_signal("-TERM").expect("send SIGTERM");
    let status = guard.wait_exit().await;
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn test_adversarial_allow_lan_flag_permits_mapped_loopback() {
    let port = get_available_port();
    let bin = yachiyo_bin();

    // Loopback mapped address [::ffff:127.0.0.1] should be permitted even without --allow-lan
    let mut cmd = Command::new(&bin);
    cmd.args(["--mixed", &format!("[::ffff:127.0.0.1]:{port}")]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().expect("failed to spawn yachiyo");
    let guard = ChildGuard::new(child);

    let target = format!("127.0.0.1:{port}").parse().unwrap();
    let wait_res = wait_for_port(target, Duration::from_secs(5)).await;
    assert!(
        wait_res.is_ok(),
        "Proxy should bind [::ffff:127.0.0.1] without --allow-lan: {wait_res:?}"
    );

    guard.send_signal("-TERM").expect("send SIGTERM");
    let status = guard.wait_exit().await;
    assert_eq!(status.code(), Some(0));
}

// =========================================================================
// Suite 2: Listener Configuration & Isolation Edge Cases
// =========================================================================

#[tokio::test]
async fn test_adversarial_socks_only_disables_mixed() {
    let socks_port = get_available_port();
    let bin = yachiyo_bin();

    let mut cmd = Command::new(&bin);
    cmd.args(["--socks", &format!("127.0.0.1:{socks_port}")]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().expect("spawn yachiyo --socks");
    let guard = ChildGuard::new(child);

    let socks_addr: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    wait_for_port(socks_addr, Duration::from_secs(5))
        .await
        .expect("socks port ready");

    // 1. Verify default mixed port (18484) is NOT bound
    let default_mixed: SocketAddr = DEFAULT_MIXED_ADDR.parse().unwrap();
    let mixed_connect = tokio::net::TcpStream::connect(default_mixed).await;
    assert!(
        mixed_connect.is_err(),
        "Default mixed 127.0.0.1:18484 must NOT be bound when --socks is independently set!"
    );

    // 2. Verify dedicated SOCKS port accepts SOCKS5 greeting
    let mut stream = tokio::net::TcpStream::connect(socks_addr).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // SOCKS5, 1 auth method, NO AUTH
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "SOCKS5 auth negotiation succeeded");
    drop(stream); // Explicitly close client connection so connection counter drops to 0

    // 3. Verify dedicated SOCKS port rejects raw HTTP CONNECT method
    let mut stream2 = tokio::net::TcpStream::connect(socks_addr).await.unwrap();
    stream2
        .write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 10];
    let n = stream2.read(&mut buf).await.unwrap_or(0);
    // SOCKS5 parser receives 'C' (0x43), detects invalid version, and closes connection
    assert_eq!(
        n, 0,
        "Dedicated SOCKS port must reject non-SOCKS HTTP traffic immediately"
    );
    drop(stream2);

    tokio::time::sleep(Duration::from_millis(50)).await;

    guard.send_signal("-TERM").expect("send SIGTERM");
    let status = guard.wait_exit().await;
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn test_adversarial_http_only_disables_mixed() {
    let http_port = get_available_port();
    let bin = yachiyo_bin();

    let mut cmd = Command::new(&bin);
    cmd.args(["--http", &format!("127.0.0.1:{http_port}")]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().expect("spawn yachiyo --http");
    let guard = ChildGuard::new(child);

    let http_addr: SocketAddr = format!("127.0.0.1:{http_port}").parse().unwrap();
    wait_for_port(http_addr, Duration::from_secs(5))
        .await
        .expect("http port ready");

    // 1. Verify default mixed port (18484) is NOT bound
    let default_mixed: SocketAddr = DEFAULT_MIXED_ADDR.parse().unwrap();
    let mixed_connect = tokio::net::TcpStream::connect(default_mixed).await;
    assert!(
        mixed_connect.is_err(),
        "Default mixed 127.0.0.1:18484 must NOT be bound when --http is independently set!"
    );

    // 2. Verify dedicated HTTP port handles HTTP CONNECT
    let mut stream = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    // Connect to invalid target that will trigger HTTP 502/504 or rejection
    stream
        .write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    assert!(n > 0, "HTTP listener must respond to HTTP CONNECT line");
    let resp_str = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp_str.starts_with("HTTP/1.1 "),
        "Must respond with HTTP protocol header: {resp_str}"
    );
    drop(stream);

    // 3. Verify dedicated HTTP port rejects SOCKS5 handshake (method byte 0x05)
    let mut stream2 = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    stream2.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf2 = [0u8; 64];
    let n2 = stream2.read(&mut buf2).await.unwrap_or(0);
    if n2 > 0 {
        let resp2 = String::from_utf8_lossy(&buf2[..n2]);
        assert!(
            resp2.contains("405") || resp2.contains("400"),
            "HTTP port must reject SOCKS5 byte greeting with 405 or 400: {resp2}"
        );
    }
    drop(stream2);

    tokio::time::sleep(Duration::from_millis(50)).await;

    guard.send_signal("-TERM").expect("send SIGTERM");
    let status = guard.wait_exit().await;
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn test_adversarial_socks_and_http_independent_disables_mixed() {
    let socks_port = get_available_port();
    let http_port = get_available_port();
    let bin = yachiyo_bin();

    let mut cmd = Command::new(&bin);
    cmd.args([
        "--socks",
        &format!("127.0.0.1:{socks_port}"),
        "--http",
        &format!("127.0.0.1:{http_port}"),
    ]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().expect("spawn yachiyo with socks and http");
    let guard = ChildGuard::new(child);

    let socks_addr: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let http_addr: SocketAddr = format!("127.0.0.1:{http_port}").parse().unwrap();

    wait_for_port(socks_addr, Duration::from_secs(5))
        .await
        .expect("socks ready");
    wait_for_port(http_addr, Duration::from_secs(5))
        .await
        .expect("http ready");

    // Default mixed must NOT be bound
    let default_mixed: SocketAddr = DEFAULT_MIXED_ADDR.parse().unwrap();
    assert!(
        tokio::net::TcpStream::connect(default_mixed).await.is_err(),
        "Default mixed must not be bound when both --socks and --http are specified"
    );

    // Both endpoints are operational
    let mut s_stream = tokio::net::TcpStream::connect(socks_addr).await.unwrap();
    s_stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut s_resp = [0u8; 2];
    s_stream.read_exact(&mut s_resp).await.unwrap();
    assert_eq!(s_resp, [0x05, 0x00]);
    drop(s_stream);

    let mut h_stream = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    h_stream
        .write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut h_resp = [0u8; 16];
    let n = h_stream.read(&mut h_resp).await.unwrap_or(0);
    assert!(n > 0);
    drop(h_stream);

    tokio::time::sleep(Duration::from_millis(50)).await;

    guard.send_signal("-TERM").expect("send SIGTERM");
    let status = guard.wait_exit().await;
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn test_adversarial_combined_mixed_socks_and_http_all_bound() {
    let mixed_port = get_available_port();
    let socks_port = get_available_port();
    let http_port = get_available_port();
    let bin = yachiyo_bin();

    let mut cmd = Command::new(&bin);
    cmd.args([
        "--mixed",
        &format!("127.0.0.1:{mixed_port}"),
        "--socks",
        &format!("127.0.0.1:{socks_port}"),
        "--http",
        &format!("127.0.0.1:{http_port}"),
    ]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().expect("spawn yachiyo with all three");
    let guard = ChildGuard::new(child);

    let m_addr: SocketAddr = format!("127.0.0.1:{mixed_port}").parse().unwrap();
    let s_addr: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let h_addr: SocketAddr = format!("127.0.0.1:{http_port}").parse().unwrap();

    wait_for_port(m_addr, Duration::from_secs(5)).await.unwrap();
    wait_for_port(s_addr, Duration::from_secs(5)).await.unwrap();
    wait_for_port(h_addr, Duration::from_secs(5)).await.unwrap();

    // Mixed accepts both SOCKS5 and HTTP
    let mut m_socks = tokio::net::TcpStream::connect(m_addr).await.unwrap();
    m_socks.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut m_resp = [0u8; 2];
    m_socks.read_exact(&mut m_resp).await.unwrap();
    assert_eq!(m_resp, [0x05, 0x00]);
    drop(m_socks);

    tokio::time::sleep(Duration::from_millis(50)).await;

    guard.send_signal("-TERM").expect("send SIGTERM");
    let status = guard.wait_exit().await;
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn test_adversarial_port_collision_duplicate_bind_fails() {
    let port = get_available_port();
    let addr = format!("127.0.0.1:{port}");

    // Providing identical port for both mixed and socks
    let (code, _stdout, stderr) =
        run_binary_expecting_error(&["--mixed", &addr, "--socks", &addr]).await;

    assert_eq!(code, 1, "Binding duplicate port must exit with code 1");
    assert!(
        stderr.contains("failed to bind inbound listener sockets")
            || stderr.contains("Address already in use"),
        "Expected address in use error: {stderr}"
    );
}

// =========================================================================
// Suite 3: Malformed Arguments & Bounds Stress-Testing
// =========================================================================

#[tokio::test]
async fn test_adversarial_malformed_arguments_clap_exit_code_2() {
    let invalid_invocations: &[&[&str]] = &[
        // Non-numeric port
        &["--mixed", "127.0.0.1:abc"],
        // Missing port
        &["--mixed", "127.0.0.1"],
        // Missing IP
        &["--mixed", ":18484"],
        // Non-IP hostname (DNS strings are not accepted on CLI bind endpoints)
        &["--mixed", "localhost:18484"],
        // Port out of u16 range
        &["--mixed", "127.0.0.1:65536"],
        &["--mixed", "127.0.0.1:999999"],
        // Negative port
        &["--mixed", "127.0.0.1:-1"],
        // Malformed IPv6 literal
        &["--mixed", "[:::1]:18484"],
        &["--mixed", "::1:18484"],
        // Unknown argument
        &["--nonexistent-flag-xyz"],
        // Negative timeouts
        &["--handshake-timeout", "-10"],
        &["--connect-timeout", "-5"],
        &["--idle-timeout", "-300"],
        &["--max-connections", "-1"],
    ];

    for args in invalid_invocations {
        let (code, _stdout, stderr) = run_binary_expecting_error(args).await;
        assert_eq!(
            code, 2,
            "Malformed argument {args:?} must trigger Clap exit code 2. Got code {code}, stderr: {stderr}"
        );
        assert!(
            stderr.contains("error:") || stderr.contains("Usage:"),
            "Expected clap error formatting in stderr: {stderr}"
        );
    }
}

#[tokio::test]
async fn test_adversarial_zero_and_boundary_timeouts() {
    // 0 values for timeouts and concurrency limits should be accepted by parser
    let args = CliArgs::try_parse_from([
        "yachiyo",
        "--handshake-timeout",
        "0",
        "--connect-timeout",
        "0",
        "--idle-timeout",
        "0",
        "--max-connections",
        "0",
    ])
    .expect("parsing 0-valued boundary flags must succeed");

    assert_eq!(args.handshake_timeout, 0);
    assert_eq!(args.connect_timeout, 0);
    assert_eq!(args.idle_timeout, 0);
    assert_eq!(args.max_connections, 0);

    let inbound = args.to_inbound_config().expect("convert config");
    assert_eq!(inbound.handshake_timeout, Duration::ZERO);
    assert_eq!(inbound.connect_timeout, Duration::ZERO);
    assert_eq!(inbound.idle_timeout, Duration::ZERO);
}

#[tokio::test]
async fn test_adversarial_invalid_logging_filter_directive_exit_code_1() {
    // Malformed log filter syntax must fail during logging setup with exit code 1
    let (code, _stdout, stderr) =
        run_binary_expecting_error(&["--log-level", "invalid===directive,,,"]).await;
    assert_eq!(
        code, 1,
        "Invalid logging directive must exit with code 1. Stderr: {stderr}"
    );
    assert!(
        stderr.contains("Error initializing logging"),
        "Expected error initializing logging in stderr: {stderr}"
    );
}

// =========================================================================
// Suite 4: Lifecycle Coordination & Zero-Payload Logging Audit
// =========================================================================

#[tokio::test]
async fn test_adversarial_lifecycle_clean_sigint_drain() {
    let port = get_available_port();
    let bin = yachiyo_bin();

    let mut cmd = Command::new(&bin);
    cmd.args(["--mixed", &format!("127.0.0.1:{port}")]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().expect("spawn yachiyo");
    let guard = ChildGuard::new(child);

    let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    wait_for_port(target, Duration::from_secs(5)).await.unwrap();

    // Trigger SIGINT (Ctrl+C)
    guard.send_signal("-INT").expect("send SIGINT");
    let status = guard.wait_exit().await;
    assert_eq!(
        status.code(),
        Some(0),
        "Clean SIGINT drain with zero active connections must exit with code 0"
    );
}

#[tokio::test]
async fn test_adversarial_lifecycle_forced_timeout_when_active_connections_held() {
    let port = get_available_port();
    let bin = yachiyo_bin();

    let mut cmd = Command::new(&bin);
    cmd.args(["--mixed", &format!("127.0.0.1:{port}")]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().expect("spawn yachiyo");
    let guard = ChildGuard::new(child);

    let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    wait_for_port(target, Duration::from_secs(5)).await.unwrap();

    // Establish an active connection and keep it open (do not drop or close)
    let mut held_conn = tokio::net::TcpStream::connect(target).await.unwrap();
    held_conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    held_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // Send SIGTERM while held_conn is still active
    guard.send_signal("-TERM").expect("send SIGTERM");

    // The proxy should wait up to 5 seconds and exit with code 1 (forced timeout)
    let status = guard.wait_exit().await;
    assert_eq!(
        status.code(),
        Some(1),
        "Forced abort on drain timeout with active connection must exit with code 1"
    );

    drop(held_conn);
}

#[tokio::test]
async fn test_adversarial_zero_payload_logging_audit() {
    let port = get_available_port();
    let bin = yachiyo_bin();

    let mut cmd = Command::new(&bin);
    cmd.args([
        "--mixed",
        &format!("127.0.0.1:{port}"),
        "--log-level",
        "trace", // Maximum log verbosity
    ]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().expect("spawn yachiyo");
    let mut guard = ChildGuard::new(child);

    let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    wait_for_port(target, Duration::from_secs(5)).await.unwrap();

    // Send sensitive canary strings in HTTP and SOCKS requests
    let canary_password = "CONFIDENTIAL_CANARY_SECRET_AUTH_TOKEN_778899";
    let canary_payload = "HIGH_ENTROPY_USER_PAYLOAD_BYTES_X1Y2Z3";

    if let Ok(mut stream) = tokio::net::TcpStream::connect(target).await {
        let http_req = format!(
            "CONNECT 127.0.0.1:1 HTTP/1.1\r\nProxy-Authorization: Basic {canary_password}\r\nPayload: {canary_payload}\r\n\r\n"
        );
        let _ = stream.write_all(http_req.as_bytes()).await;
        let mut buf = [0u8; 64];
        let _ = stream.read(&mut buf).await;
        drop(stream);
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Stop proxy
    guard.send_signal("-TERM").expect("send SIGTERM");

    let child = guard.take_child().expect("take child");
    let output =
        tokio::task::spawn_blocking(move || child.wait_with_output().expect("wait output"))
            .await
            .expect("spawn_blocking panicked");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let all_logs = format!("{stdout}\n{stderr}");

    assert!(
        !all_logs.contains(canary_password),
        "SECURITY VIOLATION: Zero payload policy violated! Log contained secret password token: {all_logs}"
    );
    assert!(
        !all_logs.contains(canary_payload),
        "SECURITY VIOLATION: Zero payload policy violated! Log contained sensitive user payload: {all_logs}"
    );
}
