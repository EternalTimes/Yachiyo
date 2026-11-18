// SPDX-License-Identifier: AGPL-3.0-only

//! Tier 3: Cross-Feature Combinations Test Suite.
//!
//! Covers:
//! 1. TCP Half-Close propagation (Client FIN to Target, Target FIN to Client)
//! 2. Mixed-Port demux under concurrent half-close
//! 3. Concurrency limit rejection under load
//! 4. Graceful shutdown with 5s drain coordinator (Clean exit code 0 vs Forced exit code 1)

use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yachiyo_e2e::client::{TargetDestination, http_connect, socks5_connect};
use yachiyo_e2e::echo::{EchoMode, EchoServer};
use yachiyo_e2e::proxy::{ProxyConfig, ProxyProcess};

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn test_tcp_half_close_client_to_target() {
    let echo = EchoServer::bind_ipv4(EchoMode::HalfCloseClientFin)
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
    let mut stream = socks5_connect(proxy_addr, &target, TIMEOUT).await.unwrap();

    let payload = b"ClientHalfCloseData123";
    stream.write_all(payload).await.unwrap();

    // Client half-closes write half (FIN)
    stream.shutdown().await.unwrap();

    // Target should detect half-close, write response, and client should read response
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();

    let expected = b"HALF_CLOSE_ACK:ClientHalfCloseData123";
    assert_eq!(&response, expected);
    assert!(echo.stats().half_close_detected.load(Ordering::SeqCst));

    drop(proxy);
}

#[tokio::test]
async fn test_tcp_half_close_target_to_client() {
    let echo = EchoServer::bind_ipv4(EchoMode::HalfCloseServerFin)
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
    let mut stream = http_connect(proxy_addr, &target, TIMEOUT).await.unwrap();

    // Client writes initial greeting
    stream.write_all(b"HelloTarget").await.unwrap();

    // Target writes SERVER_FIN_ACK and shuts down write half
    let mut ack_buf = [0u8; 14];
    stream.read_exact(&mut ack_buf).await.unwrap();
    assert_eq!(&ack_buf, b"SERVER_FIN_ACK");

    // Client detects server FIN on subsequent read
    let mut eof_buf = [0u8; 1];
    let n = stream.read(&mut eof_buf).await.unwrap();
    assert_eq!(n, 0, "Expected EOF from target server FIN");

    // Client write half is still open: client sends remaining data to target
    let followup = b"ClientFollowupStreamData";
    stream.write_all(followup).await.unwrap();
    stream.shutdown().await.unwrap();

    // Give echo server a moment to finish drain
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(echo.stats().half_close_detected.load(Ordering::SeqCst));

    drop(proxy);
}

#[tokio::test]
async fn test_mixed_port_under_concurrent_half_close() {
    let echo = EchoServer::bind_ipv4(EchoMode::HalfCloseClientFin)
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
    for i in 0..8 {
        let t = target.clone();
        let task = tokio::spawn(async move {
            let mut stream = if i % 2 == 0 {
                socks5_connect(proxy_addr, &t, TIMEOUT).await.unwrap()
            } else {
                http_connect(proxy_addr, &t, TIMEOUT).await.unwrap()
            };

            let payload = format!("Payload#{}", i);
            stream.write_all(payload.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();

            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            let expected = format!("HALF_CLOSE_ACK:{}", payload);
            assert_eq!(&resp, expected.as_bytes());
        });
        tasks.push(task);
    }

    for t in tasks {
        t.await.unwrap();
    }

    drop(proxy);
}

#[tokio::test]
async fn test_concurrency_limit_rejection() {
    let echo = EchoServer::bind_ipv4(EchoMode::Blackhole).await.unwrap();
    let echo_addr = echo.addr();

    let proxy_addr = ProxyProcess::get_available_addr();
    // Test with low limit for test execution speed
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        extra_args: vec!["--max-connections".to_string(), "10".to_string()],
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let target = TargetDestination::from_socket_addr(echo_addr);

    // Fill up connections up to limit
    let mut held_connections = Vec::new();
    for _ in 0..10 {
        if let Ok(stream) = socks5_connect(proxy_addr, &target, Duration::from_secs(2)).await {
            held_connections.push(stream);
        }
    }

    // Next connection exceeding limit must be rejected or dropped
    let overflow_res = socks5_connect(proxy_addr, &target, Duration::from_secs(2)).await;
    assert!(
        overflow_res.is_err(),
        "Expected connection exceeding concurrency limit to be rejected"
    );

    // Release held connections
    drop(held_connections);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now new connection should succeed again
    let echo_active = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let active_target = TargetDestination::from_socket_addr(echo_active.addr());
    let recovered = socks5_connect(proxy_addr, &active_target, Duration::from_secs(2)).await;
    assert!(
        recovered.is_ok(),
        "Expected recovery after connections drained"
    );

    drop(proxy);
}

#[tokio::test]
async fn test_graceful_shutdown_clean_drain_within_5s() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let proxy_addr = ProxyProcess::get_available_addr();
    let mut proxy = match ProxyProcess::start_or_skip(ProxyConfig {
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
    let mut stream = socks5_connect(proxy_addr, &target, TIMEOUT).await.unwrap();

    // Trigger graceful shutdown via SIGINT
    #[cfg(unix)]
    proxy.send_sigint().unwrap();

    // Complete the in-flight transfer quickly (< 1s)
    let payload = b"DrainMeCleanlyWithin5s";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // Close client connection to finish drain
    drop(stream);

    // Proxy must exit with code 0 (clean drain) within 5s
    let status = proxy
        .wait_with_timeout(Duration::from_secs(6))
        .await
        .unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "Expected clean exit code 0 on drain"
    );
}

#[tokio::test]
async fn test_graceful_shutdown_forced_exit_after_5s() {
    let echo = EchoServer::bind_ipv4(EchoMode::Blackhole).await.unwrap();
    let echo_addr = echo.addr();

    let proxy_addr = ProxyProcess::get_available_addr();
    let mut proxy = match ProxyProcess::start_or_skip(ProxyConfig {
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
    // Open connection and keep it open (simulating stalled transfer)
    let held_stream = socks5_connect(proxy_addr, &target, TIMEOUT).await.unwrap();

    #[cfg(unix)]
    proxy.send_sigterm().unwrap();

    // Wait for the 5s forced drain timeout
    let status = proxy
        .wait_with_timeout(Duration::from_secs(7))
        .await
        .unwrap();

    // Must exit with code 1 indicating forced exit due to un-drained connections
    assert_eq!(
        status.code(),
        Some(1),
        "Expected exit code 1 when drain timeout exceeded"
    );

    drop(held_stream);
}
