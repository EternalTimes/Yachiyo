// SPDX-License-Identifier: AGPL-3.0-only

//! Tier 4: Real-World Scenarios & CLI Integration Test Suite.
//!
//! Covers:
//! 1. Real `curl` CLI client over SOCKS5 (`--socks5-hostname`)
//! 2. Real `curl` CLI client over HTTP CONNECT (`-x http://`)
//! 3. Large data streaming with real clients
//! 4. Raw pipelined stream (netcat simulation)
//! 5. Multithreaded client stress test
//! 6. Zero-payload logging audit (confirming host:port recorded, zero payload recorded)

use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yachiyo_e2e::client::{
    TargetDestination, http_connect, socks5_connect, verify_bidirectional_echo,
};
use yachiyo_e2e::echo::{EchoMode, EchoServer};
use yachiyo_e2e::proxy::{ProxyConfig, ProxyProcess};

const TIMEOUT: Duration = Duration::from_secs(10);

fn curl_installed() -> bool {
    Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn test_curl_socks5_hostname_http_get() {
    if !curl_installed() {
        eprintln!("[INFO] curl not found, skipping real curl test");
        return;
    }

    let expected_body = "HelloFromRealCurlViaSOCKS5";
    let echo = EchoServer::bind_ipv4(EchoMode::HttpServer {
        body: expected_body.to_string(),
    })
    .await
    .unwrap();
    let echo_port = echo.port();

    let proxy_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let url = format!("http://localhost:{}/", echo_port);

    let output = tokio::process::Command::new("curl")
        .args([
            "-s",
            "-S",
            "--socks5-hostname",
            &proxy_addr.to_string(),
            &url,
        ])
        .output()
        .await
        .expect("Failed to execute curl command");

    assert!(
        output.status.success(),
        "curl failed with stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = String::from_utf8_lossy(&output.stdout);
    assert_eq!(body.trim(), expected_body);

    drop(proxy);
}

#[tokio::test]
async fn test_curl_http_connect_get() {
    if !curl_installed() {
        eprintln!("[INFO] curl not found, skipping real curl test");
        return;
    }

    let expected_body = "HelloFromRealCurlViaHTTPConnect";
    let echo = EchoServer::bind_ipv4(EchoMode::HttpServer {
        body: expected_body.to_string(),
    })
    .await
    .unwrap();
    let echo_port = echo.port();

    let proxy_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let url = format!("http://127.0.0.1:{}/", echo_port);
    let proxy_url = format!("http://{}", proxy_addr);

    let output = tokio::process::Command::new("curl")
        .args(["-s", "-S", "-p", "-x", &proxy_url, &url])
        .output()
        .await
        .expect("Failed to execute curl command");

    assert!(
        output.status.success(),
        "curl failed with stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = String::from_utf8_lossy(&output.stdout);
    assert_eq!(body.trim(), expected_body);

    drop(proxy);
}

#[tokio::test]
async fn test_curl_large_file_download() {
    if !curl_installed() {
        return;
    }

    // 1 MB repeating text
    let large_body = "A".repeat(1024 * 1024);
    let echo = EchoServer::bind_ipv4(EchoMode::HttpServer {
        body: large_body.clone(),
    })
    .await
    .unwrap();
    let echo_port = echo.port();

    let proxy_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let url = format!("http://127.0.0.1:{}/", echo_port);
    let proxy_url = format!("http://{}", proxy_addr);

    let output = tokio::process::Command::new("curl")
        .args(["-s", "-S", "-p", "-x", &proxy_url, &url])
        .output()
        .await
        .expect("Failed to execute curl command");

    assert!(output.status.success());
    assert_eq!(output.stdout.len(), large_body.len());

    drop(proxy);
}

#[tokio::test]
async fn test_netcat_pipelined_stream() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let proxy_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    // Raw TCP connection simulating netcat: writes CONNECT request and continuous stream
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!("CONNECT {} HTTP/1.1\r\n\r\n", echo_addr);
    stream.write_all(req.as_bytes()).await.unwrap();

    let (status, _, _) = yachiyo_e2e::client::read_http_response(&mut stream)
        .await
        .unwrap();
    assert_eq!(status, 200);

    // Stream 10 sequential messages
    for i in 1..=10 {
        let line = format!("Netcat Stream Line #{}\n", i);
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; line.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, line.as_bytes());
    }

    drop(proxy);
}

#[tokio::test]
async fn test_tokio_multithreaded_clients() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let proxy_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let target = TargetDestination::from_socket_addr(echo_addr);

    let mut tasks = Vec::new();
    for i in 0..20 {
        let t = target.clone();
        let task = tokio::spawn(async move {
            let stream = if i % 2 == 0 {
                socks5_connect(proxy_addr, &t, TIMEOUT).await.unwrap()
            } else {
                http_connect(proxy_addr, &t, TIMEOUT).await.unwrap()
            };

            let payload = format!("Worker #{} Payload Content", i);
            verify_bidirectional_echo(stream, payload.as_bytes())
                .await
                .unwrap();
        });
        tasks.push(task);
    }

    for t in tasks {
        t.await.unwrap();
    }

    drop(proxy);
}

#[tokio::test]
async fn test_zero_payload_logging_audit() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let proxy_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let target = TargetDestination::from_socket_addr(echo_addr);

    // Send sensitive token payload over SOCKS5
    let socks_stream = socks5_connect(proxy_addr, &target, TIMEOUT).await.unwrap();
    let secret_payload_1 = "SUPER_SECRET_TOKEN_XYZ_98765";
    verify_bidirectional_echo(socks_stream, secret_payload_1.as_bytes())
        .await
        .unwrap();

    // Send sensitive header / payload over HTTP CONNECT
    let mut http_stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let secret_header = "Authorization: Bearer SECRET_JWT_TOKEN_12345";
    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n{}\r\n\r\n",
        target.to_http_authority(),
        target.to_http_authority(),
        secret_header
    );
    http_stream.write_all(req.as_bytes()).await.unwrap();
    let (status, _, _) = yachiyo_e2e::client::read_http_response(&mut http_stream)
        .await
        .unwrap();
    assert_eq!(status, 200);

    let secret_payload_2 = "CONFIDENTIAL_FINANCIAL_RECORD_DATA";
    verify_bidirectional_echo(http_stream, secret_payload_2.as_bytes())
        .await
        .unwrap();

    // Audit logs:
    // Proxy logs MUST NOT contain any of the secret payload or sensitive header bytes!
    proxy
        .assert_zero_payload_logging(&[
            secret_payload_1,
            "SECRET_JWT_TOKEN_12345",
            secret_payload_2,
        ])
        .await;

    drop(proxy);
}
