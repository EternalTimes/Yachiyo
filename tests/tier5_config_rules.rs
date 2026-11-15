// SPDX-License-Identifier: AGPL-3.0-only

//! Tier 5 E2E Tests: Native YAML configuration, sequential rule evaluation, and REJECT behavior.

use std::fs;
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;

use yachiyo_e2e::client::{
    TargetDestination, http_connect, read_http_response, socks5_connect, socks5_handshake_raw,
    socks5_send_raw_request, verify_bidirectional_echo,
};
use yachiyo_e2e::echo::{EchoMode, EchoServer};
use yachiyo_e2e::proxy::{ProxyConfig, ProxyProcess};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn write_temp_config(name: &str, content: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("yachiyo_test_{name}_{pid}_{nanos}.yaml"));
    fs::write(&path, content).expect("failed to write temp config");
    path
}

async fn run_cli(args: &[&str]) -> std::process::Output {
    let bin = if std::path::Path::new("target/debug/yachiyo").is_file() {
        "target/debug/yachiyo"
    } else if std::path::Path::new("../target/debug/yachiyo").is_file() {
        "../target/debug/yachiyo"
    } else {
        panic!("yachiyo binary not found; build with `cargo build -p yachiyo-cli`");
    };

    Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("failed to execute yachiyo binary")
}

#[tokio::test]
async fn test_config_check_valid_and_invalid_exit_codes() {
    let valid_yaml = r#"
schema_version: 1
listeners:
  mixed: 127.0.0.1:18484
  allow_lan: false
rules:
  - DOMAIN,ads.example.com,REJECT
  - DOMAIN-SUFFIX,blocked.example.org,REJECT
  - IP-CIDR,192.0.2.0/24,REJECT,no-resolve
  - IP-CIDR,2001:db8::/32,REJECT,no-resolve
  - MATCH,DIRECT
"#;
    let valid_path = write_temp_config("valid", valid_yaml);
    let out = run_cli(&["--config", valid_path.to_str().unwrap(), "--check"]).await;
    let _ = fs::remove_file(&valid_path);
    assert!(
        out.status.success(),
        "valid config --check should exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let unknown_field_yaml = r#"
schema_version: 1
unsupported_option: true
rules:
  - MATCH,DIRECT
"#;
    let bad_path = write_temp_config("unknown_field", unknown_field_yaml);
    let out = run_cli(&["--config", bad_path.to_str().unwrap(), "--check"]).await;
    let _ = fs::remove_file(&bad_path);
    assert!(!out.status.success(), "unknown field must be rejected");

    let missing_match_yaml = r#"
schema_version: 1
rules:
  - DOMAIN,ads.example.com,REJECT
"#;
    let no_match_path = write_temp_config("no_match", missing_match_yaml);
    let out = run_cli(&["--config", no_match_path.to_str().unwrap(), "--check"]).await;
    let _ = fs::remove_file(&no_match_path);
    assert!(!out.status.success(), "missing MATCH must be rejected");

    let non_loopback_yaml = r#"
schema_version: 1
listeners:
  mixed: 0.0.0.0:18484
rules:
  - MATCH,DIRECT
"#;
    let lan_path = write_temp_config("non_loopback", non_loopback_yaml);
    let out = run_cli(&["--config", lan_path.to_str().unwrap(), "--check"]).await;
    let _ = fs::remove_file(&lan_path);
    assert!(
        !out.status.success(),
        "non-loopback without allow_lan must be rejected"
    );
}

#[tokio::test]
async fn test_config_driven_rules_and_reject_for_socks5_and_http() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let echo_v6 = EchoServer::bind_ipv6(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_v6_addr = echo_v6.addr();

    let proxy_addr = ProxyProcess::get_available_addr();
    let yaml = format!(
        r#"
schema_version: 1
listeners:
  mixed: {proxy_addr}
  allow_lan: false
rules:
  - DOMAIN,blocked.example.com,REJECT
  - DOMAIN-SUFFIX,blocked-suffix.example.org,REJECT
  - IP-CIDR,{echo_v6_ip}/128,REJECT,no-resolve
  - MATCH,DIRECT
"#,
        echo_v6_ip = echo_v6_addr.ip()
    );
    let cfg_path = write_temp_config("rules_e2e", &yaml);

    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        extra_args: vec![
            "--config".to_string(),
            cfg_path.to_string_lossy().to_string(),
        ],
        ..Default::default()
    })
    .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            let _ = fs::remove_file(&cfg_path);
            return;
        }
        Err(e) => {
            let _ = fs::remove_file(&cfg_path);
            panic!("failed to start proxy with --config: {e}");
        }
    };

    // 1. SOCKS5: DOMAIN match -> REJECT (REP = 0x02)
    {
        let mut s = TcpStream::connect(proxy_addr).await.unwrap();
        let auth = socks5_handshake_raw(&mut s, &[0x00]).await.unwrap();
        assert_eq!(auth, [0x05, 0x00]);
        let domain = b"blocked.example.com";
        let mut addr = Vec::with_capacity(1 + domain.len());
        addr.push(domain.len() as u8);
        addr.extend_from_slice(domain);
        let rep = socks5_send_raw_request(&mut s, 0x05, 0x01, 0x00, 0x03, &addr, 443)
            .await
            .unwrap();
        assert_eq!(
            rep.rep, 0x02,
            "expected SOCKS5 REP=0x02 ConnectionNotAllowed"
        );
    }

    // 2. HTTP CONNECT: DOMAIN-SUFFIX match -> 403 Forbidden
    {
        let mut s = TcpStream::connect(proxy_addr).await.unwrap();
        let req = "CONNECT sub.blocked-suffix.example.org:443 HTTP/1.1\r\nHost: sub.blocked-suffix.example.org:443\r\n\r\n";
        s.write_all(req.as_bytes()).await.unwrap();
        let (status, _, _) = read_http_response(&mut s).await.unwrap();
        assert_eq!(status, 403, "expected HTTP 403 Forbidden on REJECT rule");
    }

    // 3. HTTP CONNECT: IPv6 CIDR match -> 403 Forbidden
    {
        let mut s = TcpStream::connect(proxy_addr).await.unwrap();
        let authority = format!("[{}]:{}", echo_v6_addr.ip(), echo_v6_addr.port());
        let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let (status, _, _) = read_http_response(&mut s).await.unwrap();
        assert_eq!(
            status, 403,
            "expected HTTP 403 Forbidden on IPv6 CIDR REJECT"
        );
    }

    // 4. SOCKS5 & HTTP CONNECT: non-matching target falls through to MATCH,DIRECT
    let target = TargetDestination::from_socket_addr(echo_addr);
    let socks_stream = socks5_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();
    verify_bidirectional_echo(socks_stream, b"Direct via config MATCH")
        .await
        .unwrap();

    let http_stream = http_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();
    verify_bidirectional_echo(http_stream, b"HTTP Direct via config MATCH")
        .await
        .unwrap();

    // 5. Domain suffix boundary: `notblocked-suffix.example.org` should NOT match `blocked-suffix.example.org`,
    //    and `localhost` should fall through to MATCH,DIRECT.
    let local_target = TargetDestination::Domain("localhost".to_string(), echo_addr.port());
    let mut s = http_connect(proxy_addr, &local_target, TEST_TIMEOUT)
        .await
        .unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    drop(proxy);
    let _ = fs::remove_file(&cfg_path);
}

#[tokio::test]
async fn test_config_ipv4_cidr_rule_rejects_local_echo() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr: SocketAddr = echo.addr();

    let proxy_addr = ProxyProcess::get_available_addr();
    let yaml = format!(
        r#"
schema_version: 1
listeners:
  mixed: {proxy_addr}
rules:
  - IP-CIDR,127.0.0.0/8,REJECT
  - MATCH,DIRECT
"#
    );
    let cfg_path = write_temp_config("ipv4_cidr_reject", &yaml);

    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        extra_args: vec![
            "--config".to_string(),
            cfg_path.to_string_lossy().to_string(),
        ],
        ..Default::default()
    })
    .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            let _ = fs::remove_file(&cfg_path);
            return;
        }
        Err(e) => {
            let _ = fs::remove_file(&cfg_path);
            panic!("failed to start proxy with --config: {e}");
        }
    };

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let (status, _, _) = read_http_response(&mut s).await.unwrap();
    assert_eq!(status, 403);

    drop(proxy);
    let _ = fs::remove_file(&cfg_path);
}
