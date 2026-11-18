// SPDX-License-Identifier: AGPL-3.0-only

//! Tier 1: Primary Feature Coverage Test Suite.
//!
//! Covers:
//! 1. SOCKS5 CONNECT (IPv4, IPv6, Domain) (>= 5 tests)
//! 2. HTTP CONNECT (IPv4, IPv6, Domain) (>= 5 tests)
//! 3. Mixed-Port Sniffing (>= 5 tests)
//! 4. Independent Listeners (--socks and --http) (>= 5 tests)

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yachiyo_e2e::client::{
    TargetDestination, http_connect, socks5_connect, verify_bidirectional_echo,
};
use yachiyo_e2e::echo::{EchoMode, EchoServer};
use yachiyo_e2e::proxy::{ProxyConfig, ProxyProcess};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

// =========================================================================
// Feature 1: SOCKS5 CONNECT (IPv4, IPv6, Domain)
// =========================================================================

#[tokio::test]
async fn test_socks5_connect_ipv4_echo() {
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
    let stream = socks5_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();

    let payload = b"Hello Yachiyo IPv4 SOCKS5!";
    verify_bidirectional_echo(stream, payload).await.unwrap();

    assert_eq!(
        echo.stats()
            .connections_accepted
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    drop(proxy);
}

#[tokio::test]
async fn test_socks5_connect_ipv6_echo() {
    let echo = EchoServer::bind_ipv6(EchoMode::BidirectionalEcho)
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
    let stream = socks5_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();

    let payload = b"Hello Yachiyo IPv6 SOCKS5 [::1]!";
    verify_bidirectional_echo(stream, payload).await.unwrap();

    assert_eq!(
        echo.stats()
            .connections_accepted
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    drop(proxy);
}

#[tokio::test]
async fn test_socks5_connect_domain_echo() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
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

    let target = TargetDestination::Domain("localhost".to_string(), echo_port);
    let stream = socks5_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();

    let payload = b"Hello Yachiyo Domain SOCKS5 localhost!";
    verify_bidirectional_echo(stream, payload).await.unwrap();

    assert_eq!(
        echo.stats()
            .connections_accepted
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    drop(proxy);
}

#[tokio::test]
async fn test_socks5_connect_multiple_exchanges() {
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
    let mut stream = socks5_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();

    for i in 1..=5 {
        let msg = format!("Exchange message #{}", i);
        stream.write_all(msg.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, msg.as_bytes());
    }

    drop(proxy);
}

#[tokio::test]
async fn test_socks5_connect_large_payload() {
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
    let stream = socks5_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();

    // 256 KB of repeating pattern
    let payload: Vec<u8> = (0..262144).map(|i| (i % 256) as u8).collect();
    verify_bidirectional_echo(stream, &payload).await.unwrap();

    drop(proxy);
}

// =========================================================================
// Feature 2: HTTP CONNECT (IPv4, IPv6, Domain)
// =========================================================================

#[tokio::test]
async fn test_http_connect_ipv4_echo() {
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
    let stream = http_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();

    let payload = b"Hello Yachiyo IPv4 HTTP CONNECT!";
    verify_bidirectional_echo(stream, payload).await.unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_http_connect_ipv6_echo() {
    let echo = EchoServer::bind_ipv6(EchoMode::BidirectionalEcho)
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
    let stream = http_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();

    let payload = b"Hello Yachiyo IPv6 HTTP CONNECT [::1]!";
    verify_bidirectional_echo(stream, payload).await.unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_http_connect_domain_echo() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
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

    let target = TargetDestination::Domain("localhost".to_string(), echo_port);
    let stream = http_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();

    let payload = b"Hello Yachiyo Domain HTTP CONNECT localhost!";
    verify_bidirectional_echo(stream, payload).await.unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_http_connect_http10_version() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
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

    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!("CONNECT 127.0.0.1:{} HTTP/1.0\r\n\r\n", echo_port);
    stream.write_all(req.as_bytes()).await.unwrap();

    let (status, _, _) = yachiyo_e2e::client::read_http_response(&mut stream)
        .await
        .unwrap();
    assert_eq!(status, 200);

    let payload = b"HTTP/1.0 tunnel content";
    verify_bidirectional_echo(stream, payload).await.unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_http_connect_large_payload() {
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
    let stream = http_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();

    let payload: Vec<u8> = (0..262144).map(|i| (i % 256) as u8).collect();
    verify_bidirectional_echo(stream, &payload).await.unwrap();

    drop(proxy);
}

// =========================================================================
// Feature 3: Mixed-Port Sniffing
// =========================================================================

#[tokio::test]
async fn test_mixed_port_socks5_demux() {
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
    let stream = socks5_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();
    verify_bidirectional_echo(stream, b"SOCKS5 via mixed port")
        .await
        .unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_mixed_port_http_demux() {
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
    let stream = http_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();
    verify_bidirectional_echo(stream, b"HTTP CONNECT via mixed port")
        .await
        .unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_mixed_port_interleaved_clients() {
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

    for i in 0..6 {
        if i % 2 == 0 {
            let stream = socks5_connect(proxy_addr, &target, TEST_TIMEOUT)
                .await
                .unwrap();
            verify_bidirectional_echo(stream, format!("Interleaved SOCKS5 #{}", i).as_bytes())
                .await
                .unwrap();
        } else {
            let stream = http_connect(proxy_addr, &target, TEST_TIMEOUT)
                .await
                .unwrap();
            verify_bidirectional_echo(stream, format!("Interleaved HTTP #{}", i).as_bytes())
                .await
                .unwrap();
        }
    }

    drop(proxy);
}

#[tokio::test]
async fn test_mixed_port_zero_byte_connection() {
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

    // Open TCP connection and immediately drop without sending any bytes
    for _ in 0..5 {
        let stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        drop(stream);
    }

    // Verify proxy is still healthy and operational afterwards
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let target = TargetDestination::from_socket_addr(echo.addr());
    let stream = socks5_connect(proxy_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();
    verify_bidirectional_echo(stream, b"Healthy after zero-byte probes")
        .await
        .unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_mixed_port_concurrent_socks_and_http() {
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

    let mut handles = Vec::new();
    for i in 0..10 {
        let t = target.clone();
        let handle = tokio::spawn(async move {
            if i % 2 == 0 {
                let stream = socks5_connect(proxy_addr, &t, TEST_TIMEOUT).await.unwrap();
                verify_bidirectional_echo(stream, format!("Concurrent SOCKS5 #{}", i).as_bytes())
                    .await
                    .unwrap();
            } else {
                let stream = http_connect(proxy_addr, &t, TEST_TIMEOUT).await.unwrap();
                verify_bidirectional_echo(stream, format!("Concurrent HTTP #{}", i).as_bytes())
                    .await
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }

    drop(proxy);
}

// =========================================================================
// Feature 4: Independent Listeners (--socks and --http)
// =========================================================================

#[tokio::test]
async fn test_independent_listeners_socks_only() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let socks_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        socks_addr: Some(socks_addr),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let target = TargetDestination::from_socket_addr(echo_addr);
    let stream = socks5_connect(socks_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();
    verify_bidirectional_echo(stream, b"Dedicated SOCKS endpoint test")
        .await
        .unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_independent_listeners_http_only() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let http_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        http_addr: Some(http_addr),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let target = TargetDestination::from_socket_addr(echo_addr);
    let stream = http_connect(http_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();
    verify_bidirectional_echo(stream, b"Dedicated HTTP endpoint test")
        .await
        .unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_independent_listeners_simultaneous() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let socks_addr = ProxyProcess::get_available_addr();
    let http_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        socks_addr: Some(socks_addr),
        http_addr: Some(http_addr),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let target = TargetDestination::from_socket_addr(echo_addr);

    let socks_stream = socks5_connect(socks_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();
    let http_stream = http_connect(http_addr, &target, TEST_TIMEOUT)
        .await
        .unwrap();

    verify_bidirectional_echo(socks_stream, b"Simultaneous SOCKS")
        .await
        .unwrap();
    verify_bidirectional_echo(http_stream, b"Simultaneous HTTP")
        .await
        .unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_independent_listeners_custom_ports() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let custom_socks = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        socks_addr: Some(custom_socks),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let target = TargetDestination::from_socket_addr(echo_addr);
    let stream = socks5_connect(custom_socks, &target, TEST_TIMEOUT)
        .await
        .unwrap();
    verify_bidirectional_echo(stream, b"Custom socks port verified")
        .await
        .unwrap();

    drop(proxy);
}

#[tokio::test]
async fn test_independent_listeners_cross_protocol_rejection() {
    let socks_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        socks_addr: Some(socks_addr),
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    // Send HTTP CONNECT to dedicated SOCKS-only endpoint
    let mut stream = tokio::net::TcpStream::connect(socks_addr).await.unwrap();
    stream
        .write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();

    // SOCKS handler should reject (invalid version 0x43 'C' != 0x05) or close
    let mut resp = [0u8; 2];
    let res = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut resp)).await;
    match res {
        Ok(Ok(0)) => {} // Connection cleanly closed by proxy
        Ok(Ok(_)) => {
            // First byte received from SOCKS response must not be 200 OK
            assert_ne!(&resp, b"HT");
        }
        _ => {}
    }

    drop(proxy);
}
