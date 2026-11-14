// SPDX-License-Identifier: AGPL-3.0-only

//! Empirical adversarial stress tests for Milestone 2:
//! - HTTP method validation: GET, POST, PUT, DELETE, OPTIONS, TRACE, PATCH, HEAD -> 405 Method Not Allowed
//! - Authority parsing stress: missing port, port 0, unbracketed IPv6, empty authority, invalid port -> 400 Bad Request
//! - Header limit bounding: > 8192 bytes -> 431 Request Header Fields Too Large, boundary at 8192
//! - Pipelined payload preservation: single write of CONNECT + early payload (e.g. TLS ClientHello) forwarded cleanly
//! - Multi-listener concurrency limit: > 1024 connections -> prompt rejection of 1025th connection, shared tracker

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use yachiyo_core::address::{TargetAddr, TargetHost};
use yachiyo_core::connection::ConnectionTracker;
use yachiyo_inbound::http::{
    HttpParseError, HttpVersion, MAX_HEADER_SIZE, parse_http_connect_request,
    read_http_connect_request,
};
use yachiyo_inbound::listener::{InboundConfig, InboundListener};

fn run_async<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio current-thread runtime")
        .block_on(f)
}

/// Starts an in-process local TCP echo server on loopback port.
async fn start_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo listener");
    let addr = listener.local_addr().expect("local addr");

    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    (addr, handle)
}

// ============================================================================
// 1. HTTP Method Validation Matrix
// ============================================================================

#[test]
fn test_http_method_matrix_parser_rejections() {
    let methods = [
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "POST /api/v1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
        "PUT /files/test.txt HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "DELETE /files/test.txt HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "PATCH /items/1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ];

    for raw in methods {
        let err = parse_http_connect_request(raw.as_bytes()).expect_err("must reject non-CONNECT");
        match err {
            HttpParseError::MethodNotAllowed(ref method) => {
                let expected_method = raw.split_whitespace().next().unwrap();
                assert_eq!(method, expected_method);
                assert_eq!(
                    err.response_bytes(),
                    Some(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n".as_slice())
                );
            }
            other => panic!("expected MethodNotAllowed for '{raw}', got: {other:?}"),
        }
    }
}

#[test]
fn test_http_method_matrix_live_listener_returns_405_and_closes() {
    run_async(async {
        let config = InboundConfig {
            mixed_addr: Some("127.0.0.1:0".parse().unwrap()),
            socks_addr: None,
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(100);
        let listener = InboundListener::bind(config, tracker).await.unwrap();

        let addrs = listener.local_addrs();
        let mixed_addr = addrs
            .iter()
            .find(|(k, _)| *k == yachiyo_inbound::ListenerKind::Mixed)
            .unwrap()
            .1;
        let http_addr = addrs
            .iter()
            .find(|(k, _)| *k == yachiyo_inbound::ListenerKind::Http)
            .unwrap()
            .1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        let methods = [
            "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH", "HEAD",
        ];

        for &target_endpoint in &[http_addr, mixed_addr] {
            for method in methods {
                let mut client = TcpStream::connect(target_endpoint).await.unwrap();
                let request = format!("{method} / HTTP/1.1\r\nHost: example.com\r\n\r\n");
                client.write_all(request.as_bytes()).await.unwrap();
                client.flush().await.unwrap();

                let mut resp_buf = vec![0u8; 1024];
                let n = client.read(&mut resp_buf).await.unwrap();
                assert!(n > 0, "server must respond with 405 for {method}");
                let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
                assert!(
                    resp_str.starts_with("HTTP/1.1 405 Method Not Allowed\r\n\r\n"),
                    "expected 405 reply for {method}, got: {resp_str}"
                );

                // Server should promptly close the connection after transmitting 405
                let next_read = client.read(&mut resp_buf).await.unwrap();
                assert_eq!(
                    next_read, 0,
                    "socket must be closed by server after 405 for {method}"
                );
            }
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 2. Malformed Request Lines and Lowercase Method Rejection
// ============================================================================

#[test]
fn test_http_malformed_request_line_and_methods() {
    run_async(async {
        let config = InboundConfig {
            mixed_addr: None,
            socks_addr: None,
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(100);
        let listener = InboundListener::bind(config, tracker).await.unwrap();
        let http_addr = listener.local_addrs()[0].1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        let bad_requests = [
            // Lowercase method
            "connect example.com:443 HTTP/1.1\r\n\r\n",
            // Invalid characters in method
            "CONNECT@ example.com:443 HTTP/1.1\r\n\r\n",
            // Too few tokens
            "CONNECT\r\n\r\n",
            "CONNECT example.com:443\r\n\r\n",
            // Too many tokens
            "CONNECT example.com:443 HTTP/1.1 EXTRA\r\n\r\n",
            // Unsupported versions
            "CONNECT example.com:443 HTTP/2.0\r\n\r\n",
            "CONNECT example.com:443 HTTP/0.9\r\n\r\n",
            "CONNECT example.com:443 HTTP/3.0\r\n\r\n",
        ];

        for req in bad_requests {
            let mut client = TcpStream::connect(http_addr).await.unwrap();
            client.write_all(req.as_bytes()).await.unwrap();

            let mut resp_buf = [0u8; 512];
            let n = client.read(&mut resp_buf).await.unwrap();
            assert!(n > 0, "server must respond for bad request: {req}");
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(
                resp_str.starts_with("HTTP/1.1 400 Bad Request\r\n\r\n"),
                "expected 400 Bad Request for {req}, got: {resp_str}"
            );

            // Server must close connection
            let n_after = client.read(&mut resp_buf).await.unwrap();
            assert_eq!(n_after, 0);
        }

        // Non-UTF-8 bytes in request line
        {
            let mut client = TcpStream::connect(http_addr).await.unwrap();
            let bad_bytes = b"CONNECT \xFF\xFE\xFD:443 HTTP/1.1\r\n\r\n";
            client.write_all(bad_bytes).await.unwrap();

            let mut resp_buf = [0u8; 512];
            let n = client.read(&mut resp_buf).await.unwrap();
            assert!(n > 0);
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(resp_str.starts_with("HTTP/1.1 400 Bad Request\r\n\r\n"));
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 3. Authority Parsing Stress
// ============================================================================

#[test]
fn test_http_authority_parsing_stress() {
    run_async(async {
        let config = InboundConfig {
            mixed_addr: None,
            socks_addr: None,
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(100);
        let listener = InboundListener::bind(config, tracker).await.unwrap();
        let http_addr = listener.local_addrs()[0].1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        let bad_authorities = [
            // 1. Missing port
            "CONNECT example.com HTTP/1.1\r\n\r\n",
            "CONNECT 127.0.0.1 HTTP/1.1\r\n\r\n",
            "CONNECT [::1] HTTP/1.1\r\n\r\n",
            // 2. Port 0
            "CONNECT example.com:0 HTTP/1.1\r\n\r\n",
            "CONNECT 127.0.0.1:0 HTTP/1.1\r\n\r\n",
            "CONNECT [::1]:0 HTTP/1.1\r\n\r\n",
            // 3. Unbracketed IPv6
            "CONNECT ::1:8080 HTTP/1.1\r\n\r\n",
            "CONNECT 2001:db8::1:443 HTTP/1.1\r\n\r\n",
            // 4. Malformed brackets in IPv6
            "CONNECT [::1:8080 HTTP/1.1\r\n\r\n",
            "CONNECT ::1]:8080 HTTP/1.1\r\n\r\n",
            "CONNECT []:8080 HTTP/1.1\r\n\r\n",
            // 5. Empty authority / host
            "CONNECT :8080 HTTP/1.1\r\n\r\n",
            // 6. Invalid port numbers
            "CONNECT example.com:65536 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:-1 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:abc HTTP/1.1\r\n\r\n",
        ];

        for req in bad_authorities {
            // Direct parser verification
            let parse_res = parse_http_connect_request(req.as_bytes());
            assert!(
                matches!(
                    parse_res,
                    Err(HttpParseError::InvalidAuthority(_)) | Err(HttpParseError::BadRequest(_))
                ),
                "parser should reject bad authority: {req}"
            );

            // Live socket verification
            let mut client = TcpStream::connect(http_addr).await.unwrap();
            client.write_all(req.as_bytes()).await.unwrap();

            let mut resp_buf = [0u8; 512];
            let n = client.read(&mut resp_buf).await.unwrap();
            assert!(n > 0, "server must respond for: {req}");
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(
                resp_str.starts_with("HTTP/1.1 400 Bad Request\r\n\r\n"),
                "expected 400 for {req}, got: {resp_str}"
            );
        }

        // Test valid IPv6 brackets parse properly
        let valid_v6 = b"CONNECT [::1]:8080 HTTP/1.1\r\n\r\n";
        let req = parse_http_connect_request(valid_v6).unwrap();
        assert_eq!(
            req.target,
            TargetAddr::new(TargetHost::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)), 8080)
        );

        let valid_v6_complex = b"CONNECT [2001:db8::1]:443 HTTP/1.0\r\n\r\n";
        let req2 = parse_http_connect_request(valid_v6_complex).unwrap();
        assert_eq!(req2.target.port, 443);
        assert_eq!(req2.version, HttpVersion::Http10);

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 4. Header Limit Bounding & Exact 8192 Boundary
// ============================================================================

#[test]
fn test_http_header_limit_bounding_8192() {
    run_async(async {
        let config = InboundConfig {
            mixed_addr: None,
            socks_addr: None,
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(100);
        let listener = InboundListener::bind(config, tracker).await.unwrap();
        let http_addr = listener.local_addrs()[0].1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        // Sub-test A: Header block > 8192 bytes without delimiter
        {
            let mut client = TcpStream::connect(http_addr).await.unwrap();
            let mut oversized = b"CONNECT example.com:443 HTTP/1.1\r\nX-Padding: ".to_vec();
            oversized.extend(vec![b'A'; 8300]);
            oversized.extend_from_slice(b"\r\n"); // not ending in double CRLF

            client.write_all(&oversized).await.unwrap();
            let mut resp_buf = [0u8; 512];
            let n = client.read(&mut resp_buf).await.unwrap();
            assert!(n > 0);
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(
                resp_str.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n"),
                "expected 431 for oversized headers, got: {resp_str}"
            );

            // Server must close socket (either EOF 0 or ConnectionReset due to unread excess bytes)
            let n_after = client.read(&mut resp_buf).await;
            assert!(
                matches!(n_after, Ok(0) | Err(_)),
                "socket must be closed by server, got: {n_after:?}"
            );
        }

        // Sub-test B: Header block > 8192 bytes with delimiter placed beyond 8192
        {
            let mut client = TcpStream::connect(http_addr).await.unwrap();
            let mut oversized = b"CONNECT example.com:443 HTTP/1.1\r\nX-Padding: ".to_vec();
            oversized.extend(vec![b'B'; 8300]);
            oversized.extend_from_slice(b"\r\n\r\n");

            client.write_all(&oversized).await.unwrap();
            let mut resp_buf = [0u8; 512];
            let n = client.read(&mut resp_buf).await.unwrap();
            assert!(n > 0);
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(
                resp_str.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n"),
                "expected 431 for oversized headers with distant delimiter, got: {resp_str}"
            );
        }

        // Sub-test C: Exact boundary test in parser
        // 1. Header of exactly 8188 bytes + 4 bytes "\r\n\r\n" = MAX_HEADER_SIZE (8192 bytes total)
        {
            assert_eq!(MAX_HEADER_SIZE, 8192);
            let prefix = b"CONNECT example.com:443 HTTP/1.1\r\nX-Padding: ";
            let target_delim_pos = 8188;
            let pad_len = target_delim_pos - prefix.len();
            let mut exact_buf = prefix.to_vec();
            exact_buf.extend(vec![b'C'; pad_len]);
            assert_eq!(exact_buf.len(), 8188);
            exact_buf.extend_from_slice(b"\r\n\r\n");
            assert_eq!(exact_buf.len(), MAX_HEADER_SIZE);

            let parsed = parse_http_connect_request(&exact_buf);
            assert!(
                parsed.is_ok(),
                "header with delimiter at 8188 (total 8192) must parse Ok"
            );

            // Also verify via read_http_connect_request
            let mut cursor = std::io::Cursor::new(exact_buf);
            let read_req = read_http_connect_request(&mut cursor, None).await.unwrap();
            assert_eq!(read_req.target.port, 443);
        }

        // 2. Delimiter starts at 8193 -> must return HeaderTooLarge
        {
            let prefix = b"CONNECT example.com:443 HTTP/1.1\r\nX-Padding: ";
            let target_delim_pos = 8193;
            let pad_len = target_delim_pos - prefix.len();
            let mut over_buf = prefix.to_vec();
            over_buf.extend(vec![b'D'; pad_len]);
            assert_eq!(over_buf.len(), 8193);
            over_buf.extend_from_slice(b"\r\n\r\n");

            let parsed = parse_http_connect_request(&over_buf);
            assert_eq!(parsed.unwrap_err(), HttpParseError::HeaderTooLarge);
        }

        // Sub-test D: Chunked slow-drip delivery of oversized headers
        {
            let mut client = TcpStream::connect(http_addr).await.unwrap();
            let chunk = vec![b'Z'; 256];
            let mut total_sent = 0;

            // Stream chunks until server responds with 431 or closes
            let mut resp_buf = [0u8; 512];
            let mut responded = false;

            for _ in 0..40 {
                // Up to 10240 bytes
                if client.write_all(&chunk).await.is_err() {
                    responded = true;
                    break;
                }
                total_sent += chunk.len();
                tokio::time::sleep(Duration::from_millis(5)).await;

                // Try non-blocking peek or small read
                let mut check_buf = [0u8; 512];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(5), client.read(&mut check_buf))
                        .await
                {
                    if n > 0 {
                        resp_buf[..n].copy_from_slice(&check_buf[..n]);
                        responded = true;
                        break;
                    }
                }
            }

            if !responded {
                let n = client.read(&mut resp_buf).await.unwrap();
                assert!(n > 0);
            }

            let resp_str = String::from_utf8_lossy(&resp_buf);
            assert!(
                resp_str.contains("431 Request Header Fields Too Large"),
                "chunked overflow must trigger 431, sent {total_sent} bytes, got: {resp_str}"
            );
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 5. Pipelined Early Payload Preservation
// ============================================================================

#[test]
fn test_http_pipelined_payload_preservation_echo() {
    run_async(async {
        // 1. Start echo server target
        let (echo_addr, echo_handle) = start_echo_server().await;

        // 2. Start inbound listener
        let config = InboundConfig {
            mixed_addr: Some("127.0.0.1:0".parse().unwrap()),
            socks_addr: None,
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(100);
        let listener = InboundListener::bind(config, tracker).await.unwrap();
        let http_addr = listener
            .local_addrs()
            .iter()
            .find(|(k, _)| *k == yachiyo_inbound::ListenerKind::Http)
            .unwrap()
            .1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        // Case A: Small pipelined payload (256 bytes TLS ClientHello simulation)
        {
            let mut client = TcpStream::connect(http_addr).await.unwrap();

            // Construct synthetic TLS ClientHello
            let mut payload = vec![0x16, 0x03, 0x01]; // TLS Handshake
            payload.extend((0..253).map(|i| (i % 256) as u8));

            let connect_req = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                echo_addr.ip(),
                echo_addr.port(),
                echo_addr.ip(),
                echo_addr.port()
            );

            // Single atomic write of CONNECT request + pipelined payload
            let mut combined = connect_req.into_bytes();
            combined.extend_from_slice(&payload);
            client.write_all(&combined).await.unwrap();
            client.flush().await.unwrap();

            // Read HTTP 200 response
            let mut resp_buf = [0u8; 39]; // "HTTP/1.1 200 Connection Established\r\n\r\n" is 39 bytes
            client.read_exact(&mut resp_buf).await.unwrap();
            assert_eq!(
                &resp_buf, b"HTTP/1.1 200 Connection Established\r\n\r\n",
                "must receive 200 Connection Established"
            );

            // Read echoed payload back from echo server
            let mut echoed = vec![0u8; payload.len()];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(
                echoed, payload,
                "pipelined TLS payload was not preserved or corrupted"
            );

            // Now send additional application data over established tunnel
            let app_data = b"APPLICATION_DATA_OVER_ESTABLISHED_TUNNEL";
            client.write_all(app_data).await.unwrap();
            client.flush().await.unwrap();

            let mut echo_app = vec![0u8; app_data.len()];
            client.read_exact(&mut echo_app).await.unwrap();
            assert_eq!(&echo_app, app_data);

            // Verify half-close propagation
            client.shutdown().await.unwrap();
        }

        // Case B: Large pipelined payload (4096 bytes)
        {
            let mut client = TcpStream::connect(http_addr).await.unwrap();
            let large_payload: Vec<u8> = (0..4096).map(|i| (i * 7 % 256) as u8).collect();

            let connect_req = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                echo_addr.ip(),
                echo_addr.port(),
                echo_addr.ip(),
                echo_addr.port()
            );

            let mut combined = connect_req.into_bytes();
            combined.extend_from_slice(&large_payload);
            client.write_all(&combined).await.unwrap();
            client.flush().await.unwrap();

            let mut resp_buf = [0u8; 39];
            client.read_exact(&mut resp_buf).await.unwrap();
            assert_eq!(&resp_buf, b"HTTP/1.1 200 Connection Established\r\n\r\n");

            let mut echoed = vec![0u8; large_payload.len()];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(
                echoed, large_payload,
                "large pipelined payload (4096 bytes) mismatch"
            );
        }

        let _ = shutdown_tx.send(true);
        echo_handle.abort();
        let _ = server_task.await;
    });
}

// ============================================================================
// 6. Concurrency Limiting Stress (1024 Limit & Multi-Listener)
// ============================================================================

#[test]
fn test_concurrency_limit_1024_connections() {
    run_async(async {
        // Concurrency limit strictly set to 1024 per specification
        let tracker = ConnectionTracker::new(1024);
        assert_eq!(tracker.limit(), 1024);
        assert_eq!(tracker.active_count(), 0);

        let config = InboundConfig {
            mixed_addr: Some("127.0.0.1:0".parse().unwrap()),
            socks_addr: None,
            http_addr: None,
            ..Default::default()
        };
        let listener = InboundListener::bind(config, tracker.clone())
            .await
            .unwrap();
        let mixed_addr = listener.local_addrs()[0].1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        // 1. Establish 1024 active connections
        let mut connections = Vec::with_capacity(1024);
        for i in 0..1024 {
            let client = TcpStream::connect(mixed_addr).await.unwrap_or_else(|e| {
                panic!("failed to connect client {i} before reaching limit 1024: {e}")
            });
            connections.push(client);
        }

        // Allow accept loop to process incoming connections and acquire guards
        for _ in 0..50 {
            if tracker.active_count() == 1024 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(
            tracker.active_count(),
            1024,
            "must reach exactly 1024 active connections"
        );

        // 2. Attempt connection #1025 -> Must be rejected immediately!
        let mut rejected_client = TcpStream::connect(mixed_addr).await.unwrap();
        let mut buf = [0u8; 1];

        // The server drops connection 1025 immediately without acquiring a guard.
        // Therefore, reading must return Ok(0) (EOF) or an I/O error promptly.
        let read_res = tokio::time::timeout(Duration::from_secs(1), rejected_client.read(&mut buf))
            .await
            .expect("connection #1025 rejection must be prompt, not hung");

        assert!(
            matches!(read_res, Ok(0) | Err(_)),
            "connection #1025 must be immediately closed by server, got: {read_res:?}"
        );

        // Active count remains exactly 1024
        assert_eq!(tracker.active_count(), 1024);

        // 3. Drop 10 connections -> active count drops to 1014
        connections.truncate(1014);

        for _ in 0..50 {
            if tracker.active_count() == 1014 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(
            tracker.active_count(),
            1014,
            "active count should decrement after dropping connections"
        );

        // 4. Establish 10 new connections -> fills back to 1024
        for _ in 0..10 {
            let new_client = TcpStream::connect(mixed_addr).await.unwrap();
            connections.push(new_client);
        }

        for _ in 0..50 {
            if tracker.active_count() == 1024 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(tracker.active_count(), 1024);

        // 5. Clean teardown
        let _ = shutdown_tx.send(true);
        drop(connections);
        let _ = server_task.await;
    });
}

#[test]
fn test_multi_listener_shared_concurrency_limit() {
    run_async(async {
        // Multi-listener configuration: mixed, socks, and http listeners bound simultaneously
        let limit = 15;
        let tracker = ConnectionTracker::new(limit);

        let config = InboundConfig {
            mixed_addr: Some("127.0.0.1:0".parse().unwrap()),
            socks_addr: Some("127.0.0.1:0".parse().unwrap()),
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let listener = InboundListener::bind(config, tracker.clone())
            .await
            .unwrap();

        let addrs = listener.local_addrs();
        let mixed_addr = addrs
            .iter()
            .find(|(k, _)| *k == yachiyo_inbound::ListenerKind::Mixed)
            .unwrap()
            .1;
        let socks_addr = addrs
            .iter()
            .find(|(k, _)| *k == yachiyo_inbound::ListenerKind::Socks5)
            .unwrap()
            .1;
        let http_addr = addrs
            .iter()
            .find(|(k, _)| *k == yachiyo_inbound::ListenerKind::Http)
            .unwrap()
            .1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        let mut conns = Vec::new();
        // Connect 5 to mixed, 5 to socks, 5 to http -> total 15
        for _ in 0..5 {
            conns.push(TcpStream::connect(mixed_addr).await.unwrap());
            conns.push(TcpStream::connect(socks_addr).await.unwrap());
            conns.push(TcpStream::connect(http_addr).await.unwrap());
        }

        for _ in 0..50 {
            if tracker.active_count() == 15 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(tracker.active_count(), 15);

        // Connection #16 on HTTP port -> rejected!
        let mut rej_http = TcpStream::connect(http_addr).await.unwrap();
        let mut buf = [0u8; 1];
        let res_http =
            tokio::time::timeout(Duration::from_millis(500), rej_http.read(&mut buf)).await;
        assert!(matches!(res_http, Ok(Ok(0)) | Ok(Err(_))));

        // Connection #17 on SOCKS port -> rejected!
        let mut rej_socks = TcpStream::connect(socks_addr).await.unwrap();
        let res_socks =
            tokio::time::timeout(Duration::from_millis(500), rej_socks.read(&mut buf)).await;
        assert!(matches!(res_socks, Ok(Ok(0)) | Ok(Err(_))));

        // Connection #18 on Mixed port -> rejected!
        let mut rej_mixed = TcpStream::connect(mixed_addr).await.unwrap();
        let res_mixed =
            tokio::time::timeout(Duration::from_millis(500), rej_mixed.read(&mut buf)).await;
        assert!(matches!(res_mixed, Ok(Ok(0)) | Ok(Err(_))));

        // Close 1 connection
        conns.pop();
        for _ in 0..50 {
            if tracker.active_count() == 14 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(tracker.active_count(), 14);

        // Now new connection on HTTP port succeeds!
        let new_c = TcpStream::connect(http_addr).await.unwrap();
        conns.push(new_c);
        for _ in 0..50 {
            if tracker.active_count() == 15 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(tracker.active_count(), 15);

        let _ = shutdown_tx.send(true);
        drop(conns);
        let _ = server_task.await;
    });
}

// ============================================================================
// 7. Advanced Edge Cases & Deep Adversarial Stress Tests
// ============================================================================

#[test]
fn test_http_pipelined_payload_containing_nested_http_request() {
    run_async(async {
        let (echo_addr, echo_handle) = start_echo_server().await;

        let config = InboundConfig {
            mixed_addr: None,
            socks_addr: None,
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(100);
        let listener = InboundListener::bind(config, tracker).await.unwrap();
        let http_addr = listener.local_addrs()[0].1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        let mut client = TcpStream::connect(http_addr).await.unwrap();

        // Pipelined payload that looks like an HTTP GET request
        let nested_http = b"GET /internal/secret HTTP/1.1\r\nHost: internal\r\nAuthorization: Bearer secret\r\n\r\n";
        let connect_req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            echo_addr.ip(),
            echo_addr.port(),
            echo_addr.ip(),
            echo_addr.port()
        );

        let mut combined = connect_req.into_bytes();
        combined.extend_from_slice(nested_http);

        client.write_all(&combined).await.unwrap();
        client.flush().await.unwrap();

        // Read HTTP 200 Connection Established
        let mut resp_buf = [0u8; 39];
        client.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(&resp_buf, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        // Verify that the nested HTTP request was NOT intercepted by the proxy,
        // but was passed cleanly through to the target echo server
        let mut echoed = vec![0u8; nested_http.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, nested_http);

        let _ = shutdown_tx.send(true);
        echo_handle.abort();
        let _ = server_task.await;
    });
}

#[test]
fn test_http_pipelined_payload_http10() {
    run_async(async {
        let (echo_addr, echo_handle) = start_echo_server().await;

        let config = InboundConfig {
            mixed_addr: None,
            socks_addr: None,
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(100);
        let listener = InboundListener::bind(config, tracker).await.unwrap();
        let http_addr = listener.local_addrs()[0].1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        let mut client = TcpStream::connect(http_addr).await.unwrap();

        let binary_payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42];
        let connect_req = format!(
            "CONNECT {}:{} HTTP/1.0\r\n\r\n",
            echo_addr.ip(),
            echo_addr.port()
        );

        let mut combined = connect_req.into_bytes();
        combined.extend_from_slice(&binary_payload);

        client.write_all(&combined).await.unwrap();
        client.flush().await.unwrap();

        let mut resp_buf = [0u8; 39];
        client.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(&resp_buf, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        let mut echoed = vec![0u8; binary_payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, binary_payload);

        let _ = shutdown_tx.send(true);
        echo_handle.abort();
        let _ = server_task.await;
    });
}

#[test]
fn test_http_authority_fqdn_and_scheme_rejection() {
    // Scheme in authority (http:// or https://) must be rejected with 400
    let scheme_http = b"CONNECT http://example.com:443 HTTP/1.1\r\n\r\n";
    let err_http = parse_http_connect_request(scheme_http).unwrap_err();
    assert_eq!(
        err_http.response_bytes(),
        Some(b"HTTP/1.1 400 Bad Request\r\n\r\n".as_slice())
    );

    let scheme_https = b"CONNECT https://example.com:443 HTTP/1.1\r\n\r\n";
    let err_https = parse_http_connect_request(scheme_https).unwrap_err();
    assert_eq!(
        err_https.response_bytes(),
        Some(b"HTTP/1.1 400 Bad Request\r\n\r\n".as_slice())
    );

    // FQDN with trailing dot is valid RFC 1123 domain
    let fqdn = b"CONNECT example.com.:443 HTTP/1.1\r\n\r\n";
    let parsed_fqdn = parse_http_connect_request(fqdn).unwrap();
    assert_eq!(
        parsed_fqdn.target.host,
        TargetHost::Domain("example.com.".into())
    );
    assert_eq!(parsed_fqdn.target.port, 443);

    // Domain label > 63 chars must be rejected
    let long_label = "a".repeat(64);
    let bad_label_req = format!("CONNECT {long_label}.com:443 HTTP/1.1\r\n\r\n");
    let err_label = parse_http_connect_request(bad_label_req.as_bytes()).unwrap_err();
    assert_eq!(
        err_label.response_bytes(),
        Some(b"HTTP/1.1 400 Bad Request\r\n\r\n".as_slice())
    );

    // Total domain > 253 chars must be rejected
    let long_domain = format!(
        "{}.{}.{}.{}.{}.com",
        "a".repeat(60),
        "b".repeat(60),
        "c".repeat(60),
        "d".repeat(60),
        "e".repeat(60)
    );
    assert!(long_domain.len() > 253);
    let bad_domain_req = format!("CONNECT {long_domain}:443 HTTP/1.1\r\n\r\n");
    let err_domain = parse_http_connect_request(bad_domain_req.as_bytes()).unwrap_err();
    assert_eq!(
        err_domain.response_bytes(),
        Some(b"HTTP/1.1 400 Bad Request\r\n\r\n".as_slice())
    );
}

#[test]
fn test_mixed_port_demuxing_socks5_http_connect_and_http_get() {
    run_async(async {
        let (echo_addr, echo_handle) = start_echo_server().await;

        let config = InboundConfig {
            mixed_addr: Some("127.0.0.1:0".parse().unwrap()),
            socks_addr: None,
            http_addr: None,
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(100);
        let listener = InboundListener::bind(config, tracker).await.unwrap();
        let mixed_addr = listener.local_addrs()[0].1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        // 1. SOCKS5 Client on mixed port
        {
            let mut client = TcpStream::connect(mixed_addr).await.unwrap();
            // Auth negotiation: SOCKS5 (0x05), 1 method (0x01), NO AUTH (0x00)
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            client.flush().await.unwrap();

            let mut auth_resp = [0u8; 2];
            client.read_exact(&mut auth_resp).await.unwrap();
            assert_eq!(
                auth_resp,
                [0x05, 0x00],
                "SOCKS5 auth negotiation must succeed on mixed port"
            );
        }

        // 2. HTTP CONNECT Client on mixed port
        {
            let mut client = TcpStream::connect(mixed_addr).await.unwrap();
            let connect_req = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                echo_addr.ip(),
                echo_addr.port(),
                echo_addr.ip(),
                echo_addr.port()
            );
            client.write_all(connect_req.as_bytes()).await.unwrap();
            client.flush().await.unwrap();

            let mut resp_buf = [0u8; 39];
            client.read_exact(&mut resp_buf).await.unwrap();
            assert_eq!(&resp_buf, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        }

        // 3. HTTP GET Client on mixed port -> immediate 405
        {
            let mut client = TcpStream::connect(mixed_addr).await.unwrap();
            client
                .write_all(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await
                .unwrap();
            client.flush().await.unwrap();

            let mut resp_buf = [0u8; 512];
            let n = client.read(&mut resp_buf).await.unwrap();
            assert!(n > 0);
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(resp_str.starts_with("HTTP/1.1 405 Method Not Allowed\r\n\r\n"));
        }

        // 4. Malformed Authority on mixed port -> immediate 400
        {
            let mut client = TcpStream::connect(mixed_addr).await.unwrap();
            client
                .write_all(b"CONNECT :8080 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            client.flush().await.unwrap();

            let mut resp_buf = [0u8; 512];
            let n = client.read(&mut resp_buf).await.unwrap();
            assert!(n > 0);
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(resp_str.starts_with("HTTP/1.1 400 Bad Request\r\n\r\n"));
        }

        let _ = shutdown_tx.send(true);
        echo_handle.abort();
        let _ = server_task.await;
    });
}

#[test]
fn test_concurrency_limit_burst_rejection_at_capacity() {
    run_async(async {
        let tracker = ConnectionTracker::new(1024);
        let config = InboundConfig {
            mixed_addr: Some("127.0.0.1:0".parse().unwrap()),
            socks_addr: None,
            http_addr: None,
            ..Default::default()
        };
        let listener = InboundListener::bind(config, tracker.clone())
            .await
            .unwrap();
        let mixed_addr = listener.local_addrs()[0].1;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = listener.run(shutdown_rx).await;
        });

        // Fill to capacity (1024 connections)
        let mut connections = Vec::with_capacity(1024);
        for _ in 0..1024 {
            let c = TcpStream::connect(mixed_addr).await.unwrap();
            connections.push(c);
        }

        for _ in 0..50 {
            if tracker.active_count() == 1024 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(tracker.active_count(), 1024);

        // Burst of 20 concurrent excess connections beyond limit
        for _ in 0..20 {
            let mut excess = TcpStream::connect(mixed_addr).await.unwrap();
            let mut buf = [0u8; 1];
            let res = tokio::time::timeout(Duration::from_secs(1), excess.read(&mut buf)).await;
            assert!(
                matches!(res, Ok(Ok(0)) | Ok(Err(_))),
                "burst excess connection must be rejected, got: {res:?}"
            );
        }

        // Active count must remain exactly 1024, never exceeding it
        assert_eq!(tracker.active_count(), 1024);

        let _ = shutdown_tx.send(true);
        drop(connections);
        let _ = server_task.await;
    });
}
