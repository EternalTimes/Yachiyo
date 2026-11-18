// SPDX-License-Identifier: AGPL-3.0-only

//! Empirical adversarial stress tests for Milestone 2 SOCKS5 and Sniffer:
//! - SOCKS5 Authentication negotiation edge cases (no auth omitted, nmethods = 0, multi-methods, max 255 methods, version mismatch)
//! - Unsupported commands matrix: BIND (0x02), UDP ASSOCIATE (0x03), unknown (0x00, 0x04, 0x7F, 0xFF) -> REP 0x07 (CommandNotSupported)
//! - Unsupported address types (ATYP) matrix: reserved (0x00, 0x02), unknown (0x05, 0x06, 0x7F, 0x80, 0xFF) -> REP 0x08 (AddressTypeNotSupported)
//! - SOCKS5 domain name length overflow / zero length / non-UTF8 / malformed label / max valid RFC length (253 chars)
//! - Reserved byte non-zero validation (RSV != 0x00) -> REP 0x01 (GeneralFailure)
//! - Sniffing edge cases:
//!   - Immediate 0-byte close (healthcheck probe / port scan) -> clean termination
//!   - 0x05 peek preservation -> SOCKS5 handshake succeeds
//!   - Non-0x05 byte peek preservation ('C' -> HTTP CONNECT 200, 'G' -> 405 Method Not Allowed, 0x16 -> 400 Bad Request)
//!   - Slow byte delivery (1-byte chunk delivery with delays)
//!   - Handshake timeout on idle probe
//! - SOCKS5 end-to-end proxying: IPv4, IPv6, Domain, echo verification
//! - SOCKS5 outbound error reply mapping: ConnectionRefused -> REP 0x05, HostUnreachable -> REP 0x04
//! - TCP half-close propagation through SOCKS5 tunnel

use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use yachiyo_core::connection::ConnectionTracker;
use yachiyo_inbound::listener::{InboundConfig, InboundListener, ListenerKind};
use yachiyo_inbound::socks5::{METHOD_NO_ACCEPTABLE, SOCKS_VERSION, Socks5Error, negotiate_auth};

fn run_async<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio current-thread runtime")
        .block_on(f)
}

/// Helper to verify that the server has terminated the connection (either clean FIN EOF or RST).
async fn assert_connection_closed(stream: &mut TcpStream, context: &str) {
    let mut buf = [0u8; 8];
    match stream.read(&mut buf).await {
        Ok(0) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::BrokenPipe => {}
        other => panic!("expected EOF or ConnectionReset/BrokenPipe for {context}, got: {other:?}"),
    }
}

/// Starts an in-process local TCP echo server on IPv4 loopback port.
async fn start_echo_server_ipv4() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind IPv4 echo listener");
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

/// Starts an in-process local TCP echo server on IPv6 loopback port.
async fn start_echo_server_ipv6() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("[::1]:0")
        .await
        .expect("bind IPv6 echo listener");
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

/// Starts a live InboundListener with mixed and SOCKS endpoints.
async fn start_test_listener(
    mixed: bool,
    socks: bool,
    handshake_timeout: Duration,
) -> (
    Option<SocketAddr>,
    Option<SocketAddr>,
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let config = InboundConfig {
        mixed_addr: if mixed {
            Some("127.0.0.1:0".parse().unwrap())
        } else {
            None
        },
        socks_addr: if socks {
            Some("127.0.0.1:0".parse().unwrap())
        } else {
            None
        },
        http_addr: None,
        handshake_timeout,
        connect_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(300),
        ..InboundConfig::default()
    };
    let tracker = ConnectionTracker::new(100);
    let listener = InboundListener::bind(config, tracker).await.unwrap();

    let mut mixed_addr = None;
    let mut socks_addr = None;
    for (kind, addr) in listener.local_addrs() {
        match kind {
            ListenerKind::Mixed => mixed_addr = Some(addr),
            ListenerKind::Socks5 => socks_addr = Some(addr),
            ListenerKind::Http => {}
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = listener.run(shutdown_rx).await;
    });

    (mixed_addr, socks_addr, shutdown_tx, server_task)
}

// ============================================================================
// 1. SOCKS5 Authentication Negotiation Stress & Edge Cases
// ============================================================================

#[test]
fn test_socks5_auth_methods_matrix_direct_duplex() {
    run_async(async {
        // Case A: nmethods = 0 -> [0x05, 0x00]
        {
            let (mut client, mut server) = tokio::io::duplex(64);
            let handle = tokio::spawn(async move { negotiate_auth(&mut server, None).await });

            client.write_all(&[SOCKS_VERSION, 0x00]).await.unwrap();
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [SOCKS_VERSION, METHOD_NO_ACCEPTABLE]);

            let res = handle.await.unwrap();
            assert!(matches!(res, Err(Socks5Error::NoAcceptableAuthMethod)));
        }

        // Case B: single unsupported method (e.g. 0x02 Username/Password)
        {
            let (mut client, mut server) = tokio::io::duplex(64);
            let handle = tokio::spawn(async move { negotiate_auth(&mut server, None).await });

            client
                .write_all(&[SOCKS_VERSION, 0x01, 0x02])
                .await
                .unwrap();
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [SOCKS_VERSION, METHOD_NO_ACCEPTABLE]);

            let res = handle.await.unwrap();
            assert!(matches!(res, Err(Socks5Error::NoAcceptableAuthMethod)));
        }

        // Case C: multiple unsupported methods without 0x00
        {
            let (mut client, mut server) = tokio::io::duplex(64);
            let handle = tokio::spawn(async move { negotiate_auth(&mut server, None).await });

            client
                .write_all(&[SOCKS_VERSION, 0x04, 0x01, 0x02, 0x03, 0x80])
                .await
                .unwrap();
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [SOCKS_VERSION, METHOD_NO_ACCEPTABLE]);

            let res = handle.await.unwrap();
            assert!(matches!(res, Err(Socks5Error::NoAcceptableAuthMethod)));
        }

        // Case D: maximum 255 unsupported methods (0x01 through 0xFF, omitting 0x00)
        {
            let (mut client, mut server) = tokio::io::duplex(512);
            let handle = tokio::spawn(async move { negotiate_auth(&mut server, None).await });

            let mut greeting = Vec::with_capacity(257);
            greeting.push(SOCKS_VERSION);
            greeting.push(255);
            for m in 1u8..=255 {
                greeting.push(m);
            }
            client.write_all(&greeting).await.unwrap();
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [SOCKS_VERSION, METHOD_NO_ACCEPTABLE]);

            let res = handle.await.unwrap();
            assert!(matches!(res, Err(Socks5Error::NoAcceptableAuthMethod)));
        }

        // Case E: invalid SOCKS version (e.g. SOCKS4 0x04 or unknown 0x06) -> immediate version error, NO reply
        for bad_ver in [0x04, 0x06, 0x01, 0xFF] {
            let (mut client, mut server) = tokio::io::duplex(64);
            let handle = tokio::spawn(async move { negotiate_auth(&mut server, None).await });

            client.write_all(&[bad_ver, 0x01, 0x00]).await.unwrap();
            let res = handle.await.unwrap();
            assert!(matches!(res, Err(Socks5Error::InvalidVersion(v)) if v == bad_ver));

            let mut resp = [0u8; 2];
            let n = client.read(&mut resp).await.unwrap();
            assert_eq!(
                n, 0,
                "server must NOT transmit any reply on version mismatch"
            );
        }
    });
}

#[test]
fn test_socks5_auth_methods_matrix_live_listener() {
    run_async(async {
        let (mixed_addr, socks_addr, shutdown_tx, server_task) =
            start_test_listener(true, true, Duration::from_secs(5)).await;

        let test_endpoints = [mixed_addr.unwrap(), socks_addr.unwrap()];

        let malformed_greetings: Vec<(&str, Vec<u8>)> = vec![
            ("nmethods=0", vec![0x05, 0x00]),
            ("only-user-pass", vec![0x05, 0x01, 0x02]),
            ("gssapi-and-user-pass", vec![0x05, 0x02, 0x01, 0x02]),
            (
                "multi-unsupported",
                vec![0x05, 0x05, 0x01, 0x02, 0x03, 0x80, 0xFE],
            ),
        ];

        for &endpoint in &test_endpoints {
            for (label, greeting) in &malformed_greetings {
                let mut client = TcpStream::connect(endpoint).await.unwrap();
                client.write_all(greeting).await.unwrap();
                client.flush().await.unwrap();

                let mut resp = [0u8; 2];
                let n = client.read_exact(&mut resp).await.unwrap();
                assert_eq!(
                    n, 2,
                    "must receive 2-byte response for {label} on {endpoint}"
                );
                assert_eq!(
                    resp,
                    [0x05, 0xFF],
                    "must reply with 0x05, 0xFF for {label} on {endpoint}"
                );

                assert_connection_closed(&mut client, label).await;
            }
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 2. Unsupported SOCKS5 Commands Matrix (REP 0x07)
// ============================================================================

#[test]
fn test_socks5_unsupported_commands_matrix() {
    run_async(async {
        let (mixed_addr, socks_addr, shutdown_tx, server_task) =
            start_test_listener(true, true, Duration::from_secs(5)).await;

        let test_endpoints = [mixed_addr.unwrap(), socks_addr.unwrap()];

        // Unsupported commands to challenge:
        // 0x02: BIND
        // 0x03: UDP ASSOCIATE
        // 0x00: Unknown / reserved
        // 0x04: Unknown
        // 0x7F: Unknown
        // 0xFF: Unknown
        let unsupported_cmds = [
            ("BIND-0x02", 0x02),
            ("UDP_ASSOC-0x03", 0x03),
            ("ZERO-0x00", 0x00),
            ("CMD-0x04", 0x04),
            ("CMD-0x7F", 0x7F),
            ("CMD-0xFF", 0xFF),
        ];

        for &endpoint in &test_endpoints {
            for (label, cmd) in unsupported_cmds {
                let mut client = TcpStream::connect(endpoint).await.unwrap();

                // 1. Auth negotiation (NO AUTH 0x00)
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                client.flush().await.unwrap();

                let mut auth_resp = [0u8; 2];
                client.read_exact(&mut auth_resp).await.unwrap();
                assert_eq!(auth_resp, [0x05, 0x00], "auth negotiation should succeed");

                // 2. Send request with unsupported command (targeting 127.0.0.1:8080)
                let req = [
                    0x05, // VER
                    cmd,  // CMD
                    0x00, // RSV
                    0x01, // ATYP IPv4
                    127, 0, 0, 1, // DST.ADDR
                    0x1F, 0x90, // DST.PORT = 8080
                ];
                client.write_all(&req).await.unwrap();
                client.flush().await.unwrap();

                // 3. Server MUST reply with 10-byte SOCKS5 reply with REP 0x07 (Command not supported)
                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();

                assert_eq!(
                    reply[0], 0x05,
                    "reply VER must be 0x05 for {label} on {endpoint}"
                );
                assert_eq!(
                    reply[1], 0x07,
                    "reply REP must be 0x07 (CommandNotSupported) for {label} on {endpoint}, got 0x{:02x}",
                    reply[1]
                );
                assert_eq!(
                    reply[2], 0x00,
                    "reply RSV must be 0x00 for {label} on {endpoint}"
                );
                assert_eq!(
                    reply[3], 0x01,
                    "reply ATYP must be 0x01 for {label} on {endpoint}"
                );

                // 4. Server must terminate connection
                assert_connection_closed(&mut client, label).await;
            }
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 3. Unsupported Address Types (ATYP) Matrix (REP 0x08)
// ============================================================================

#[test]
fn test_socks5_unsupported_address_types_matrix() {
    run_async(async {
        let (mixed_addr, socks_addr, shutdown_tx, server_task) =
            start_test_listener(true, true, Duration::from_secs(5)).await;

        let test_endpoints = [mixed_addr.unwrap(), socks_addr.unwrap()];

        // Unsupported address types to challenge:
        // 0x00: Reserved
        // 0x02: Reserved
        // 0x05: Unknown
        // 0x06: Unknown
        // 0x7F: Unknown
        // 0x80: Unknown
        // 0xFF: Unknown
        let unsupported_atyps = [
            ("RESERVED-0x00", 0x00),
            ("RESERVED-0x02", 0x02),
            ("UNKNOWN-0x05", 0x05),
            ("UNKNOWN-0x06", 0x06),
            ("UNKNOWN-0x7F", 0x7F),
            ("UNKNOWN-0x80", 0x80),
            ("UNKNOWN-0xFF", 0xFF),
        ];

        for &endpoint in &test_endpoints {
            for (label, atyp) in unsupported_atyps {
                let mut client = TcpStream::connect(endpoint).await.unwrap();

                // 1. Auth negotiation (NO AUTH 0x00)
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                client.flush().await.unwrap();

                let mut auth_resp = [0u8; 2];
                client.read_exact(&mut auth_resp).await.unwrap();
                assert_eq!(auth_resp, [0x05, 0x00]);

                // 2. Send CONNECT request with unsupported ATYP
                let req = [
                    0x05, // VER
                    0x01, // CMD CONNECT
                    0x00, // RSV
                    atyp, // ATYP
                    127, 0, 0, 1, // Fake addr/port bytes
                    0x1F, 0x90,
                ];
                client.write_all(&req).await.unwrap();
                client.flush().await.unwrap();

                // 3. Server MUST reply with 10-byte SOCKS5 reply with REP 0x08 (Address type not supported)
                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();

                assert_eq!(
                    reply[0], 0x05,
                    "reply VER must be 0x05 for {label} on {endpoint}"
                );
                assert_eq!(
                    reply[1], 0x08,
                    "reply REP must be 0x08 (AddressTypeNotSupported) for {label} on {endpoint}, got 0x{:02x}",
                    reply[1]
                );
                assert_eq!(reply[2], 0x00, "reply RSV must be 0x00");
                assert_eq!(reply[3], 0x01, "reply ATYP must be 0x01");

                // 4. Server must terminate connection
                assert_connection_closed(&mut client, label).await;
            }
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 4. SOCKS5 Domain Name Length & Character Edge Cases
// ============================================================================

#[test]
fn test_socks5_domain_name_zero_length() {
    run_async(async {
        let (mixed_addr, socks_addr, shutdown_tx, server_task) =
            start_test_listener(true, true, Duration::from_secs(5)).await;

        for &endpoint in &[mixed_addr.unwrap(), socks_addr.unwrap()] {
            let mut client = TcpStream::connect(endpoint).await.unwrap();

            // 1. Auth negotiation
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut auth_resp = [0u8; 2];
            client.read_exact(&mut auth_resp).await.unwrap();
            assert_eq!(auth_resp, [0x05, 0x00]);

            // 2. CONNECT with ATYP 0x03, domain length = 0
            let req = [
                0x05, 0x01, 0x00, 0x03, // VER, CMD=CONNECT, RSV, ATYP=DOMAIN
                0x00, // Domain length = 0
                0x1F, 0x90, // Port 8080
            ];
            client.write_all(&req).await.unwrap();
            client.flush().await.unwrap();

            // 3. Must reply with REP 0x01 (General Failure)
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(
                reply[1], 0x01,
                "empty domain must return REP 0x01 (GeneralFailure)"
            );

            // 4. Clean connection termination
            assert_connection_closed(&mut client, "zero-length domain").await;
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

#[test]
fn test_socks5_domain_name_overflow_and_max_valid() {
    run_async(async {
        let (mixed_addr, _socks_addr, shutdown_tx, server_task) =
            start_test_listener(true, false, Duration::from_secs(5)).await;
        let endpoint = mixed_addr.unwrap();

        // Case A: Domain length = 255 (RFC 1035 max domain is 253 octets)
        {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut auth_resp = [0u8; 2];
            client.read_exact(&mut auth_resp).await.unwrap();
            assert_eq!(auth_resp, [0x05, 0x00]);

            let mut req = vec![0x05, 0x01, 0x00, 0x03, 255];
            req.extend(vec![b'a'; 255]);
            req.extend_from_slice(&8080u16.to_be_bytes());

            client.write_all(&req).await.unwrap();
            client.flush().await.unwrap();

            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(
                reply[1], 0x04,
                "domain > 253 characters must return REP 0x04 (HostUnreachable)"
            );

            assert_connection_closed(&mut client, "domain-overflow-255").await;
        }

        // Case B: Domain length = 254 (still exceeds 253 characters)
        {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut auth_resp = [0u8; 2];
            client.read_exact(&mut auth_resp).await.unwrap();
            assert_eq!(auth_resp, [0x05, 0x00]);

            let mut req = vec![0x05, 0x01, 0x00, 0x03, 254];
            req.extend(vec![b'b'; 254]);
            req.extend_from_slice(&8080u16.to_be_bytes());

            client.write_all(&req).await.unwrap();
            client.flush().await.unwrap();

            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(
                reply[1], 0x04,
                "domain > 253 characters must return REP 0x04 (HostUnreachable)"
            );

            assert_connection_closed(&mut client, "domain-overflow-254").await;
        }

        // Case C: Non-UTF8 domain name
        {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut auth_resp = [0u8; 2];
            client.read_exact(&mut auth_resp).await.unwrap();
            assert_eq!(auth_resp, [0x05, 0x00]);

            let non_utf8_domain = [0xFF, 0xFE, 0xFD, 0xFC];
            let mut req = vec![0x05, 0x01, 0x00, 0x03, non_utf8_domain.len() as u8];
            req.extend_from_slice(&non_utf8_domain);
            req.extend_from_slice(&8080u16.to_be_bytes());

            client.write_all(&req).await.unwrap();
            client.flush().await.unwrap();

            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(
                reply[1], 0x01,
                "non-UTF8 domain must return REP 0x01 (GeneralFailure)"
            );

            assert_connection_closed(&mut client, "non-utf8-domain").await;
        }

        // Case D: Domain with invalid label characters (e.g. empty label "foo..bar", space "foo bar.com")
        for bad_domain in &["foo..bar", "foo bar.com", "-foo.com", "foo-.com"] {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut auth_resp = [0u8; 2];
            client.read_exact(&mut auth_resp).await.unwrap();
            assert_eq!(auth_resp, [0x05, 0x00]);

            let mut req = vec![0x05, 0x01, 0x00, 0x03, bad_domain.len() as u8];
            req.extend_from_slice(bad_domain.as_bytes());
            req.extend_from_slice(&8080u16.to_be_bytes());

            client.write_all(&req).await.unwrap();
            client.flush().await.unwrap();

            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(
                reply[1], 0x04,
                "malformed domain label for '{bad_domain}' must return REP 0x04"
            );

            assert_connection_closed(&mut client, bad_domain).await;
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 5. Reserved Byte Validation (RSV != 0x00 -> REP 0x01)
// ============================================================================

#[test]
fn test_socks5_reserved_field_nonzero_rejection() {
    run_async(async {
        let (mixed_addr, socks_addr, shutdown_tx, server_task) =
            start_test_listener(true, true, Duration::from_secs(5)).await;

        let test_endpoints = [mixed_addr.unwrap(), socks_addr.unwrap()];

        for &endpoint in &test_endpoints {
            for bad_rsv in [0x01, 0x02, 0x7F, 0xFF] {
                let mut client = TcpStream::connect(endpoint).await.unwrap();

                // 1. Auth negotiation
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut auth_resp = [0u8; 2];
                client.read_exact(&mut auth_resp).await.unwrap();
                assert_eq!(auth_resp, [0x05, 0x00]);

                // 2. CONNECT with non-zero RSV
                let req = [
                    0x05,    // VER
                    0x01,    // CMD CONNECT
                    bad_rsv, // Non-zero RSV
                    0x01,    // ATYP IPv4
                    127, 0, 0, 1, // DST.ADDR
                    0x1F, 0x90, // DST.PORT = 8080
                ];
                client.write_all(&req).await.unwrap();
                client.flush().await.unwrap();

                // 3. Must return REP 0x01 (General Failure)
                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0], 0x05);
                assert_eq!(
                    reply[1], 0x01,
                    "non-zero RSV (0x{:02x}) must return REP 0x01 (GeneralFailure)",
                    bad_rsv
                );

                // 4. Must terminate connection
                assert_connection_closed(&mut client, "non-zero-rsv").await;
            }
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 6. Sniffer Edge Cases: Immediate 0-Byte Close, Peek Preservation, Slow Bytes
// ============================================================================

#[test]
fn test_sniffer_immediate_zero_byte_close_health_probes() {
    run_async(async {
        let (mixed_addr, _, shutdown_tx, server_task) =
            start_test_listener(true, false, Duration::from_secs(5)).await;
        let endpoint = mixed_addr.unwrap();

        // Simulate 20 rapid zero-byte healthcheck / port-scan probes
        for _ in 0..20 {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            // Client immediately shuts down write side and closes socket without sending any byte
            client.shutdown().await.unwrap();
            let mut buf = [0u8; 1];
            let n = client.read(&mut buf).await.unwrap();
            assert_eq!(
                n, 0,
                "server must cleanly close connection on immediate EOF"
            );
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

#[test]
fn test_sniffer_peek_preservation_matrix() {
    run_async(async {
        let (echo_addr, _echo_task) = start_echo_server_ipv4().await;
        let (mixed_addr, _, shutdown_tx, server_task) =
            start_test_listener(true, false, Duration::from_secs(5)).await;
        let endpoint = mixed_addr.unwrap();

        // 1. SOCKS5 peek preservation: first byte 0x05 must not be consumed by sniffer
        {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            client.flush().await.unwrap();

            let mut auth_resp = [0u8; 2];
            client.read_exact(&mut auth_resp).await.unwrap();
            assert_eq!(auth_resp, [0x05, 0x00]);

            let echo_port = echo_addr.port();
            let req = [
                0x05,
                0x01,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                (echo_port >> 8) as u8,
                (echo_port & 0xFF) as u8,
            ];
            client.write_all(&req).await.unwrap();
            client.flush().await.unwrap();

            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT should succeed");

            // Verify payload echo through SOCKS5 tunnel
            let test_payload = b"socks5-peek-preservation-verified";
            client.write_all(test_payload).await.unwrap();
            let mut echo_buf = vec![0u8; test_payload.len()];
            client.read_exact(&mut echo_buf).await.unwrap();
            assert_eq!(&echo_buf, test_payload);
        }

        // 2. HTTP CONNECT peek preservation: first byte 'C' (0x43) must be preserved
        {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            let connect_req = format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                echo_addr.port(),
                echo_addr.port()
            );
            client.write_all(connect_req.as_bytes()).await.unwrap();
            client.flush().await.unwrap();

            let mut resp_buf = vec![0u8; 256];
            let n = client.read(&mut resp_buf).await.unwrap();
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(
                resp_str.starts_with("HTTP/1.1 200 Connection Established\r\n\r\n"),
                "expected 200 Connection Established, got: {resp_str}"
            );

            let test_payload = b"http-connect-peek-preservation-verified";
            client.write_all(test_payload).await.unwrap();
            let mut echo_buf = vec![0u8; test_payload.len()];
            client.read_exact(&mut echo_buf).await.unwrap();
            assert_eq!(&echo_buf, test_payload);
        }

        // 3. HTTP GET peek preservation: first byte 'G' (0x47) must be preserved and parsed as 405 Method Not Allowed
        {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            let get_req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
            client.write_all(get_req.as_bytes()).await.unwrap();
            client.flush().await.unwrap();

            let mut resp_buf = vec![0u8; 256];
            let n = client.read(&mut resp_buf).await.unwrap();
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(
                resp_str.starts_with("HTTP/1.1 405 Method Not Allowed\r\n\r\n"),
                "expected 405 Method Not Allowed, got: {resp_str}"
            );
            assert_connection_closed(&mut client, "http-get-405").await;
        }

        // 4. Non-ASCII byte peek preservation: byte 0x16 (TLS ClientHello) followed by delimiter -> 400 Bad Request
        {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            let raw_tls_header = [0x16, 0x03, 0x01, 0x00, 0xA0, b'\r', b'\n', b'\r', b'\n'];
            client.write_all(&raw_tls_header).await.unwrap();
            client.flush().await.unwrap();

            let mut resp_buf = vec![0u8; 256];
            let n = client.read(&mut resp_buf).await.unwrap();
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(
                resp_str.starts_with("HTTP/1.1 400 Bad Request\r\n\r\n"),
                "expected 400 Bad Request for non-ASCII TLS probe, got: {resp_str}"
            );
            assert_connection_closed(&mut client, "tls-probe-400").await;
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

#[test]
fn test_sniffer_slow_byte_delivery_resilience() {
    run_async(async {
        let (echo_addr, _echo_task) = start_echo_server_ipv4().await;
        let (mixed_addr, _, shutdown_tx, server_task) =
            start_test_listener(true, false, Duration::from_secs(5)).await;
        let endpoint = mixed_addr.unwrap();

        let mut client = TcpStream::connect(endpoint).await.unwrap();

        // 1. Send first byte 0x05 after delay
        tokio::time::sleep(Duration::from_millis(30)).await;
        client.write_all(&[0x05]).await.unwrap();
        client.flush().await.unwrap();

        // 2. Send auth method negotiation one byte at a time
        tokio::time::sleep(Duration::from_millis(20)).await;
        client.write_all(&[0x01]).await.unwrap();
        client.flush().await.unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;
        client.write_all(&[0x00]).await.unwrap();
        client.flush().await.unwrap();

        let mut auth_resp = [0u8; 2];
        client.read_exact(&mut auth_resp).await.unwrap();
        assert_eq!(auth_resp, [0x05, 0x00]);

        // 3. Send CONNECT request 1 byte at a time with 10ms intervals
        let echo_port = echo_addr.port();
        let req = [
            0x05,
            0x01,
            0x00,
            0x01,
            127,
            0,
            0,
            1,
            (echo_port >> 8) as u8,
            (echo_port & 0xFF) as u8,
        ];
        for &byte in &req {
            tokio::time::sleep(Duration::from_millis(10)).await;
            client.write_all(&[byte]).await.unwrap();
            client.flush().await.unwrap();
        }

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00);

        // 4. Verify data echo through slow-negotiated tunnel
        let payload = b"slow-delivery-survived";
        client.write_all(payload).await.unwrap();
        let mut echo_buf = vec![0u8; payload.len()];
        client.read_exact(&mut echo_buf).await.unwrap();
        assert_eq!(&echo_buf, payload);

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

#[test]
fn test_sniffer_handshake_timeout_on_idle_client() {
    run_async(async {
        // Start listener with a very short 100ms handshake timeout
        let (mixed_addr, _, shutdown_tx, server_task) =
            start_test_listener(true, false, Duration::from_millis(100)).await;
        let endpoint = mixed_addr.unwrap();

        let mut client = TcpStream::connect(endpoint).await.unwrap();
        // Send nothing, wait 200ms
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut buf = [0u8; 1];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(
            n, 0,
            "server must close idle connection exceeding handshake timeout"
        );

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 7. SOCKS5 Full End-to-End Proxying: IPv4, IPv6, Domain
// ============================================================================

#[test]
fn test_socks5_full_proxying_ipv4_ipv6_domain() {
    run_async(async {
        let (echo_v4_addr, _echo_v4_task) = start_echo_server_ipv4().await;
        let (echo_v6_addr, _echo_v6_task) = start_echo_server_ipv6().await;
        let (mixed_addr, socks_addr, shutdown_tx, server_task) =
            start_test_listener(true, true, Duration::from_secs(5)).await;

        let test_endpoints = [mixed_addr.unwrap(), socks_addr.unwrap()];

        for &endpoint in &test_endpoints {
            // Case 1: IPv4 Target (ATYP 0x01)
            {
                let mut client = TcpStream::connect(endpoint).await.unwrap();
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut auth_resp = [0u8; 2];
                client.read_exact(&mut auth_resp).await.unwrap();
                assert_eq!(auth_resp, [0x05, 0x00]);

                let port = echo_v4_addr.port();
                let req = [
                    0x05,
                    0x01,
                    0x00,
                    0x01,
                    127,
                    0,
                    0,
                    1,
                    (port >> 8) as u8,
                    (port & 0xFF) as u8,
                ];
                client.write_all(&req).await.unwrap();
                client.flush().await.unwrap();

                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0], 0x05);
                assert_eq!(reply[1], 0x00, "IPv4 CONNECT should succeed");

                let msg = b"ping-ipv4-socks5-echo";
                client.write_all(msg).await.unwrap();
                let mut resp = vec![0u8; msg.len()];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(&resp, msg);
            }

            // Case 2: IPv6 Target (ATYP 0x04)
            {
                let mut client = TcpStream::connect(endpoint).await.unwrap();
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut auth_resp = [0u8; 2];
                client.read_exact(&mut auth_resp).await.unwrap();
                assert_eq!(auth_resp, [0x05, 0x00]);

                let port = echo_v6_addr.port();
                let mut req = vec![0x05, 0x01, 0x00, 0x04];
                req.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
                req.extend_from_slice(&port.to_be_bytes());

                client.write_all(&req).await.unwrap();
                client.flush().await.unwrap();

                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0], 0x05);
                assert_eq!(reply[1], 0x00, "IPv6 CONNECT should succeed");

                let msg = b"ping-ipv6-socks5-echo";
                client.write_all(msg).await.unwrap();
                let mut resp = vec![0u8; msg.len()];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(&resp, msg);
            }

            // Case 3: Domain Target "localhost" (ATYP 0x03)
            {
                let mut client = TcpStream::connect(endpoint).await.unwrap();
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut auth_resp = [0u8; 2];
                client.read_exact(&mut auth_resp).await.unwrap();
                assert_eq!(auth_resp, [0x05, 0x00]);

                let domain = "localhost";
                let port = echo_v4_addr.port();
                let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
                req.extend_from_slice(domain.as_bytes());
                req.extend_from_slice(&port.to_be_bytes());

                client.write_all(&req).await.unwrap();
                client.flush().await.unwrap();

                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0], 0x05);
                assert_eq!(reply[1], 0x00, "Domain 'localhost' CONNECT should succeed");

                let msg = b"ping-domain-localhost-echo";
                client.write_all(msg).await.unwrap();
                let mut resp = vec![0u8; msg.len()];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(&resp, msg);
            }
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 8. SOCKS5 Outbound Failure Error Reply Mapping (REP 0x05 & REP 0x04)
// ============================================================================

#[test]
fn test_socks5_outbound_failure_error_replies() {
    run_async(async {
        let (mixed_addr, socks_addr, shutdown_tx, server_task) =
            start_test_listener(true, true, Duration::from_secs(5)).await;

        let test_endpoints = [mixed_addr.unwrap(), socks_addr.unwrap()];

        for &endpoint in &test_endpoints {
            // Case 1: Connection Refused -> REP 0x05
            // Find an unused loopback port by binding and immediately dropping listener
            let unused_port = {
                let temp = TcpListener::bind("127.0.0.1:0").await.unwrap();
                temp.local_addr().unwrap().port()
            };

            let mut client = TcpStream::connect(endpoint).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut auth_resp = [0u8; 2];
            client.read_exact(&mut auth_resp).await.unwrap();
            assert_eq!(auth_resp, [0x05, 0x00]);

            let req = [
                0x05,
                0x01,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                (unused_port >> 8) as u8,
                (unused_port & 0xFF) as u8,
            ];
            client.write_all(&req).await.unwrap();
            client.flush().await.unwrap();

            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(
                reply[1], 0x05,
                "connection refused must return REP 0x05 (ConnectionRefused)"
            );

            assert_connection_closed(&mut client, "connection-refused").await;

            // Case 2: Host Unreachable / DNS failure -> REP 0x04
            // Using a .local non-existent hostname which bypasses fake-ip wildcard proxies
            let non_existent_domain = "nonexistent-yachiyo-test.local";
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut auth_resp = [0u8; 2];
            client.read_exact(&mut auth_resp).await.unwrap();
            assert_eq!(auth_resp, [0x05, 0x00]);

            let mut req = vec![0x05, 0x01, 0x00, 0x03, non_existent_domain.len() as u8];
            req.extend_from_slice(non_existent_domain.as_bytes());
            req.extend_from_slice(&80u16.to_be_bytes());

            client.write_all(&req).await.unwrap();
            client.flush().await.unwrap();

            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(
                reply[1], 0x04,
                "DNS failure must return REP 0x04 (HostUnreachable)"
            );

            assert_connection_closed(&mut client, "dns-failure").await;
        }

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}

// ============================================================================
// 9. TCP Half-Close Propagation through SOCKS5 Tunnel
// ============================================================================

#[test]
fn test_socks5_half_close_propagation() {
    run_async(async {
        // Start a custom target server that specifically waits for half-close
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();

        let server_join = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // 1. Read client payload until EOF (half-close)
            let mut received = Vec::new();
            let mut buf = [0u8; 64];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            // 2. Write response back after client half-closed
            let response = format!("ECHO:{}", String::from_utf8_lossy(&received));
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
            // 3. Close write side
            socket.shutdown().await.unwrap();
        });

        let (mixed_addr, _, shutdown_tx, server_task) =
            start_test_listener(true, false, Duration::from_secs(5)).await;
        let endpoint = mixed_addr.unwrap();

        let mut client = TcpStream::connect(endpoint).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth_resp = [0u8; 2];
        client.read_exact(&mut auth_resp).await.unwrap();
        assert_eq!(auth_resp, [0x05, 0x00]);

        let port = target_addr.port();
        let req = [
            0x05,
            0x01,
            0x00,
            0x01,
            127,
            0,
            0,
            1,
            (port >> 8) as u8,
            (port & 0xFF) as u8,
        ];
        client.write_all(&req).await.unwrap();
        client.flush().await.unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00);

        // Client writes payload and calls shutdown(Write) to half-close
        let payload = b"half-close-test-data";
        client.write_all(payload).await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();

        // Client should still be able to read target response after client write shutdown
        let mut resp_buf = Vec::new();
        let mut chunk = [0u8; 64];
        loop {
            let n = client.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            resp_buf.extend_from_slice(&chunk[..n]);
        }

        assert_eq!(resp_buf, b"ECHO:half-close-test-data");

        server_join.await.unwrap();
        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    });
}
