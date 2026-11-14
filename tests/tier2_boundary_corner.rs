// SPDX-License-Identifier: AGPL-3.0-only

//! Tier 2: Boundary & Corner Cases Test Suite.
//!
//! Covers:
//! 1. SOCKS5 Boundary & Protocol Error Handling (>= 5 tests)
//! 2. HTTP CONNECT Boundary & Protocol Error Handling (>= 5 tests)
//! 3. HTTP Pipelined Data Preservation (>= 5 tests)
//! 4. Timeouts & Security Loopback Bindings (>= 5 tests)

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yachiyo_e2e::client::{
    TargetDestination, http_connect_with_pipeline, read_http_response, socks5_constants,
    socks5_handshake_raw, socks5_send_raw_request,
};
use yachiyo_e2e::echo::{ConnectBlackhole, EchoMode, EchoServer};
use yachiyo_e2e::proxy::{ProxyConfig, ProxyProcess};

// =========================================================================
// Feature 1: SOCKS5 Boundary & Error Handling
// =========================================================================

#[tokio::test]
async fn test_socks5_auth_unsupported_method() {
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

    // Client only offers method 0x02 (Username/Password), proxy only accepts 0x00 (NO AUTH)
    let resp = socks5_handshake_raw(&mut stream, &[0x02]).await.unwrap();
    assert_eq!(resp[0], socks5_constants::VERSION);
    assert_eq!(resp[1], socks5_constants::METHOD_NO_ACCEPTABLE); // 0xFF

    // Connection must be closed
    let mut check_buf = [0u8; 1];
    let n = stream.read(&mut check_buf).await.unwrap_or(0);
    assert_eq!(n, 0);

    drop(proxy);
}

#[tokio::test]
async fn test_socks5_unsupported_cmd_bind() {
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
    let auth = socks5_handshake_raw(&mut stream, &[socks5_constants::METHOD_NO_AUTH])
        .await
        .unwrap();
    assert_eq!(auth[1], socks5_constants::METHOD_NO_AUTH);

    // Send CMD 0x02 (BIND)
    let reply = socks5_send_raw_request(
        &mut stream,
        socks5_constants::VERSION,
        socks5_constants::CMD_BIND,
        0x00,
        socks5_constants::ATYP_IPV4,
        &[127, 0, 0, 1],
        8080,
    )
    .await
    .unwrap();

    assert_eq!(reply.ver, socks5_constants::VERSION);
    assert_eq!(reply.rep, socks5_constants::REP_COMMAND_NOT_SUPPORTED); // 0x07

    drop(proxy);
}

#[tokio::test]
async fn test_socks5_unsupported_cmd_udp() {
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
    let _ = socks5_handshake_raw(&mut stream, &[socks5_constants::METHOD_NO_AUTH])
        .await
        .unwrap();

    // Send CMD 0x03 (UDP ASSOCIATE)
    let reply = socks5_send_raw_request(
        &mut stream,
        socks5_constants::VERSION,
        socks5_constants::CMD_UDP_ASSOCIATE,
        0x00,
        socks5_constants::ATYP_IPV4,
        &[127, 0, 0, 1],
        8080,
    )
    .await
    .unwrap();

    assert_eq!(reply.rep, socks5_constants::REP_COMMAND_NOT_SUPPORTED); // 0x07

    drop(proxy);
}

#[tokio::test]
async fn test_socks5_unsupported_atyp() {
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
    let _ = socks5_handshake_raw(&mut stream, &[socks5_constants::METHOD_NO_AUTH])
        .await
        .unwrap();

    // Send invalid ATYP 0x02
    let reply = socks5_send_raw_request(
        &mut stream,
        socks5_constants::VERSION,
        socks5_constants::CMD_CONNECT,
        0x00,
        0x02, // Unsupported ATYP
        &[127, 0, 0, 1],
        8080,
    )
    .await
    .unwrap();

    assert_eq!(reply.rep, socks5_constants::REP_ADDRESS_TYPE_NOT_SUPPORTED); // 0x08

    drop(proxy);
}

#[tokio::test]
async fn test_socks5_invalid_version_in_auth() {
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

    // Send version 0x04 instead of 0x05
    stream.write_all(&[0x04, 0x01, 0x00]).await.unwrap();

    let mut resp = [0u8; 2];
    let res = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut resp)).await;
    match res {
        Ok(Ok(0)) => {} // Cleanly dropped
        Ok(Ok(_)) => {
            // Must not accept
            assert_ne!(resp[0], 0x05);
        }
        _ => {}
    }

    drop(proxy);
}

#[tokio::test]
async fn test_socks5_destination_unreachable() {
    // Pick an unused port on localhost where no server is listening
    let unused_port = ProxyProcess::get_available_port();

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
    let _ = socks5_handshake_raw(&mut stream, &[socks5_constants::METHOD_NO_AUTH])
        .await
        .unwrap();

    let reply = socks5_send_raw_request(
        &mut stream,
        socks5_constants::VERSION,
        socks5_constants::CMD_CONNECT,
        0x00,
        socks5_constants::ATYP_IPV4,
        &[127, 0, 0, 1],
        unused_port,
    )
    .await
    .unwrap();

    // Must return Connection refused (0x05), Host unreachable (0x04), or General failure (0x01)
    assert!(
        reply.rep == socks5_constants::REP_CONNECTION_REFUSED
            || reply.rep == socks5_constants::REP_HOST_UNREACHABLE
            || reply.rep == socks5_constants::REP_GENERAL_FAILURE,
        "Expected unreachable/refused REP code, got 0x{:02x}",
        reply.rep
    );

    drop(proxy);
}

// =========================================================================
// Feature 2: HTTP CONNECT Boundary & Error Handling
// =========================================================================

#[tokio::test]
async fn test_http_connect_missing_port() {
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
    // Missing :port
    stream
        .write_all(b"CONNECT 127.0.0.1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();

    let (status, _, _) = read_http_response(&mut stream).await.unwrap();
    assert_eq!(status, 400, "Expected 400 Bad Request for missing port");

    drop(proxy);
}

#[tokio::test]
async fn test_http_connect_invalid_method() {
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
    // Non-CONNECT HTTP method
    stream
        .write_all(b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();

    let (status, _, _) = read_http_response(&mut stream).await.unwrap();
    assert_eq!(
        status, 405,
        "Expected 405 Method Not Allowed for GET request"
    );

    drop(proxy);
}

#[tokio::test]
async fn test_http_connect_invalid_ipv6_syntax() {
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
    // Missing brackets around IPv6 literal
    stream
        .write_all(b"CONNECT ::1:8080 HTTP/1.1\r\nHost: ::1:8080\r\n\r\n")
        .await
        .unwrap();

    let (status, _, _) = read_http_response(&mut stream).await.unwrap();
    assert_eq!(
        status, 400,
        "Expected 400 Bad Request for unbracketed IPv6 literal"
    );

    drop(proxy);
}

#[tokio::test]
async fn test_http_connect_header_exceeds_8kb() {
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

    // Send 9KB of headers without \r\n\r\n
    let mut bad_request = b"CONNECT 127.0.0.1:8080 HTTP/1.1\r\nX-Padding: ".to_vec();
    bad_request.resize(9216, b'A');
    bad_request.extend_from_slice(b"\r\n\r\n");

    stream.write_all(&bad_request).await.unwrap();

    let res = read_http_response(&mut stream).await;
    match res {
        Ok((status, _, _)) => {
            assert!(
                status == 431 || status == 400,
                "Expected 431 Request Header Fields Too Large or 400, got {}",
                status
            );
        }
        Err(_) => {
            // Proxy closed connection directly upon exceeding 8KB
        }
    }

    drop(proxy);
}

#[tokio::test]
async fn test_http_connect_invalid_http_version() {
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
    stream
        .write_all(b"CONNECT 127.0.0.1:8080 HTTP/9.9\r\n\r\n")
        .await
        .unwrap();

    let res = read_http_response(&mut stream).await;
    if let Ok((status, _, _)) = res {
        assert!(
            status >= 400,
            "Expected 4xx or 5xx error for invalid HTTP version"
        );
    }

    drop(proxy);
}

#[tokio::test]
async fn test_http_connect_unreachable_target() {
    let unused_port = ProxyProcess::get_available_port();

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
    let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", unused_port);
    stream.write_all(req.as_bytes()).await.unwrap();

    let (status, _, _) = read_http_response(&mut stream).await.unwrap();
    assert!(
        status == 502 || status == 504,
        "Expected 502 Bad Gateway or 504 Gateway Timeout, got {}",
        status
    );

    drop(proxy);
}

// =========================================================================
// Feature 3: HTTP Pipelined Data Preservation
// =========================================================================

#[tokio::test]
async fn test_http_pipelined_simple_payload() {
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
    let pipelined = b"EarlyArrivalData";

    let mut stream =
        http_connect_with_pipeline(proxy_addr, &target, pipelined, Duration::from_secs(5))
            .await
            .unwrap();

    // Echo server should have received the pipelined data and replied immediately!
    let mut echo_buf = vec![0u8; pipelined.len()];
    stream.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, pipelined);

    drop(proxy);
}

#[tokio::test]
async fn test_http_pipelined_large_payload() {
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
    let pipelined: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

    let mut stream =
        http_connect_with_pipeline(proxy_addr, &target, &pipelined, Duration::from_secs(5))
            .await
            .unwrap();

    let mut echo_buf = vec![0u8; pipelined.len()];
    stream.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, &pipelined);

    drop(proxy);
}

#[tokio::test]
async fn test_http_pipelined_binary_data() {
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
    let pipelined: Vec<u8> = (0..=255).collect();

    let mut stream =
        http_connect_with_pipeline(proxy_addr, &target, &pipelined, Duration::from_secs(5))
            .await
            .unwrap();

    let mut echo_buf = vec![0u8; pipelined.len()];
    stream.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, &pipelined);

    drop(proxy);
}

#[tokio::test]
async fn test_http_pipelined_split_delimiter() {
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

    // First write ends in partial delimiter \r\n
    let part1 = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n",
        echo_port
    );
    stream.write_all(part1.as_bytes()).await.unwrap();

    // Small pause
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second write completes delimiter and adds pipelined payload
    let part2 = b"\r\nSplitDelimiterPayload";
    stream.write_all(part2).await.unwrap();

    let (status, _, _) = read_http_response(&mut stream).await.unwrap();
    assert_eq!(status, 200);

    let mut echo_buf = vec![0u8; b"SplitDelimiterPayload".len()];
    stream.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, b"SplitDelimiterPayload");

    drop(proxy);
}

#[tokio::test]
async fn test_http_pipelined_tls_client_hello() {
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
    // Synthetic TLS ClientHello record: 0x16 0x03 0x01 (ContentType=Handshake, Version=TLS 1.0)
    let fake_client_hello = [
        0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0xAA, 0xBB,
    ];

    let mut stream = http_connect_with_pipeline(
        proxy_addr,
        &target,
        &fake_client_hello,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let mut echo_buf = vec![0u8; fake_client_hello.len()];
    stream.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, &fake_client_hello);

    drop(proxy);
}

// =========================================================================
// Feature 4: Timeouts & Security Bindings
// =========================================================================

#[tokio::test]
async fn test_handshake_timeout_socks5() {
    let proxy_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        extra_args: vec!["--handshake-timeout".to_string(), "1".to_string()],
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

    // Sleep longer than handshake timeout without sending anything
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    assert_eq!(
        n, 0,
        "Proxy should have dropped connection after handshake timeout"
    );

    drop(proxy);
}

#[tokio::test]
async fn test_handshake_timeout_http() {
    let proxy_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        extra_args: vec!["--handshake-timeout".to_string(), "1".to_string()],
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    // Send partial line and stall
    stream.write_all(b"CONN").await.unwrap();

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    assert_eq!(
        n, 0,
        "Proxy should have closed connection after HTTP handshake timeout"
    );

    drop(proxy);
}

#[tokio::test]
async fn test_outbound_connect_timeout() {
    let blackhole = ConnectBlackhole::new().expect("Failed to create ConnectBlackhole");
    let blackhole_port = blackhole.port();

    let proxy_addr = ProxyProcess::get_available_addr();
    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(proxy_addr),
        extra_args: vec!["--connect-timeout".to_string(), "1".to_string()],
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let _ = socks5_handshake_raw(&mut stream, &[socks5_constants::METHOD_NO_AUTH])
        .await
        .unwrap();

    let start = std::time::Instant::now();
    let reply = socks5_send_raw_request(
        &mut stream,
        socks5_constants::VERSION,
        socks5_constants::CMD_CONNECT,
        0x00,
        socks5_constants::ATYP_IPV4,
        &[127, 0, 0, 1],
        blackhole_port,
    )
    .await;

    let elapsed = start.elapsed();
    // Either reply is returned indicating error or stream closed
    if let Ok(rep) = reply {
        assert_ne!(rep.rep, socks5_constants::REP_SUCCESS);
        assert_eq!(rep.rep, socks5_constants::REP_HOST_UNREACHABLE);
    }
    // Should fail around the 1s timeout, well before standard 60s OS timeout
    assert!(elapsed >= Duration::from_millis(900));
    assert!(elapsed < Duration::from_secs(5));

    drop(proxy);
    drop(blackhole);
}

#[tokio::test]
async fn test_loopback_binding_security_rejection() {
    if !yachiyo_e2e::proxy::binary_exists() && std::env::var("YACHIYO_BIN").is_err() {
        return;
    }

    // Binding to 0.0.0.0 without --allow-lan must fail immediately with exit code 1
    let output = ProxyProcess::run_expecting_failure(&["--mixed", "0.0.0.0:18484"])
        .await
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "Binding to non-loopback without --allow-lan must exit with code 1"
    );
}

#[tokio::test]
async fn test_loopback_binding_with_allow_lan() {
    let port = ProxyProcess::get_available_port();
    let non_loopback = format!("0.0.0.0:{}", port);

    let proxy = match ProxyProcess::start_or_skip(ProxyConfig {
        mixed_addr: Some(non_loopback.parse().unwrap()),
        allow_lan: true,
        ..Default::default()
    })
    .await
    .unwrap()
    {
        Some(p) => p,
        None => return,
    };

    drop(proxy);
}
