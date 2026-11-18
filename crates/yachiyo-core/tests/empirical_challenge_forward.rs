// SPDX-License-Identifier: AGPL-3.0-only

//! Empirical Adversarial Verification Suite for `crates/yachiyo-core`:
//! - `forward.rs`: Bidirectional forwarding kernel, dual-simplex half-close asymmetric FIN,
//!   pipelined initial data exactness (64KB+), idle timeout resets and triggering.
//! - `outbound.rs`: Direct dialer, multi-IP fallback, connect timeout bounds, error normalization.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use yachiyo_core::address::TargetAddr;
use yachiyo_core::forward::{
    DEFAULT_BUFFER_SIZE, DEFAULT_IDLE_TIMEOUT, copy_bidirectional_with_idle_timeout,
};
use yachiyo_core::outbound::{DirectDialer, dial_direct};

/// Helper: run an async future in a single-threaded Tokio runtime.
fn run_async<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// Helper: create a connected pair of local TCP streams over loopback.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = accept_task.await.unwrap();
    (client, server)
}

/// Helper: establish proxy test harness.
/// Returns: (client_side, proxy_client, proxy_remote, remote_side)
async fn proxy_harness() -> (TcpStream, TcpStream, TcpStream, TcpStream) {
    let (client_side, proxy_client) = tcp_pair().await;
    let (proxy_remote, remote_side) = tcp_pair().await;
    (client_side, proxy_client, proxy_remote, remote_side)
}

/// Generate deterministic pseudo-random binary data with arbitrary byte patterns.
fn generate_binary_payload(size: usize, seed: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut state = seed as u32;
    for _ in 0..size {
        // Linear Congruential Generator for fast, reproducible arbitrary byte sequences
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push((state >> 16) as u8);
    }
    data
}

// ============================================================================
// AREA 1: HALF-CLOSE ASYMMETRIC FIN STRESS TESTS
// ============================================================================

/// 1.1 Asymmetric FIN: Client sends 1KB request, immediately executes `client.shutdown()` (sends FIN).
/// Target receives request and FIN (EOF), waits and responds with 5 delayed chunks of 16KB (total 80KB).
/// Target then sends FIN (`remote.shutdown()`). Client verifies complete 80KB payload and EOF.
#[test]
fn test_asymmetric_client_fin_multichunk_delayed_response() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(
                proxy_client,
                proxy_remote,
                Duration::from_secs(10),
                None,
            )
            .await
            .unwrap()
        });

        // 1. Client sends 1KB request and immediately sends FIN
        let request_payload = generate_binary_payload(1024, 0x11);
        client.write_all(&request_payload).await.unwrap();
        client.shutdown().await.unwrap(); // Client half-close: FIN sent, read half remains open

        // 2. Target reads until EOF, verifying client FIN propagation
        let mut target_received = Vec::new();
        let mut read_buf = [0u8; 256];
        loop {
            let n = remote.read(&mut read_buf).await.unwrap();
            if n == 0 {
                break; // EOF cleanly observed by target
            }
            target_received.extend_from_slice(&read_buf[..n]);
        }
        assert_eq!(target_received, request_payload);

        // 3. Target sends 5 distinct chunks of 16KB with delays (total 80KB)
        let total_chunks = 5;
        let chunk_size = 16 * 1024;
        let mut full_expected_response = Vec::with_capacity(total_chunks * chunk_size);

        for i in 0..total_chunks {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let chunk = generate_binary_payload(chunk_size, (0x20 + i) as u8);
            full_expected_response.extend_from_slice(&chunk);
            remote.write_all(&chunk).await.unwrap();
        }

        // 4. Target sends FIN
        remote.shutdown().await.unwrap();

        // 5. Client reads the entire response until EOF
        let mut client_received = Vec::new();
        let mut client_read_buf = [0u8; 4096];
        loop {
            let n = client.read(&mut client_read_buf).await.unwrap();
            if n == 0 {
                break; // EOF cleanly observed by client
            }
            client_received.extend_from_slice(&client_read_buf[..n]);
        }
        assert_eq!(client_received.len(), full_expected_response.len());
        assert_eq!(client_received, full_expected_response);

        // 6. Verify forward task completed cleanly with exact transfer metrics
        let stats = forward_task.await.unwrap();
        assert_eq!(stats.client_to_remote, 1024);
        assert_eq!(stats.remote_to_client, (total_chunks * chunk_size) as u64);
        assert_eq!(
            stats.total_bytes(),
            1024 + (total_chunks * chunk_size) as u64
        );
    });
}

/// 1.2 Asymmetric FIN: Client connects and immediately calls `shutdown()` without sending any bytes.
/// Target receives immediate EOF, then sends 32KB response data, then calls `shutdown()`.
/// Client reads all 32KB until EOF.
#[test]
fn test_asymmetric_client_fin_zero_byte_request() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(
                proxy_client,
                proxy_remote,
                Duration::from_secs(10),
                None,
            )
            .await
            .unwrap()
        });

        // Client immediately sends FIN with zero bytes transmitted
        client.shutdown().await.unwrap();

        // Target reads until EOF (must receive 0 bytes)
        let mut target_buf = [0u8; 64];
        let n = remote.read(&mut target_buf).await.unwrap();
        assert_eq!(n, 0, "Target must observe immediate EOF from client FIN");

        // Target responds with 32KB
        let response = generate_binary_payload(32768, 0x44);
        remote.write_all(&response).await.unwrap();
        remote.shutdown().await.unwrap();

        // Client reads all 32KB until EOF
        let mut client_received = Vec::new();
        let mut client_buf = [0u8; 4096];
        loop {
            let read_n = client.read(&mut client_buf).await.unwrap();
            if read_n == 0 {
                break;
            }
            client_received.extend_from_slice(&client_buf[..read_n]);
        }
        assert_eq!(client_received, response);

        let stats = forward_task.await.unwrap();
        assert_eq!(stats.client_to_remote, 0);
        assert_eq!(stats.remote_to_client, 32768);
    });
}

/// 1.3 Asymmetric FIN: Target sends 512-byte banner and immediately calls `remote.shutdown()`.
/// Client reads banner until EOF, then transmits 4 delayed chunks of 16KB (total 64KB) to target,
/// then calls `client.shutdown()`. Target reads full 64KB until EOF.
#[test]
fn test_asymmetric_remote_fin_delayed_client_stream() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(
                proxy_client,
                proxy_remote,
                Duration::from_secs(10),
                None,
            )
            .await
            .unwrap()
        });

        // Target sends banner and immediate FIN
        let banner = generate_binary_payload(512, 0x55);
        remote.write_all(&banner).await.unwrap();
        remote.shutdown().await.unwrap(); // Target write half closed

        // Client reads banner until EOF
        let mut client_received = Vec::new();
        let mut buf = [0u8; 128];
        loop {
            let n = client.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            client_received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(client_received, banner);

        // Client now transmits 4 delayed chunks of 16KB
        let total_chunks = 4;
        let chunk_size = 16 * 1024;
        let mut expected_client_data = Vec::with_capacity(total_chunks * chunk_size);

        for i in 0..total_chunks {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let chunk = generate_binary_payload(chunk_size, (0x60 + i) as u8);
            expected_client_data.extend_from_slice(&chunk);
            client.write_all(&chunk).await.unwrap();
        }
        client.shutdown().await.unwrap();

        // Target reads the 64KB stream until EOF
        let mut target_received = Vec::new();
        let mut target_buf = [0u8; 4096];
        loop {
            let n = remote.read(&mut target_buf).await.unwrap();
            if n == 0 {
                break;
            }
            target_received.extend_from_slice(&target_buf[..n]);
        }
        assert_eq!(target_received, expected_client_data);

        let stats = forward_task.await.unwrap();
        assert_eq!(stats.client_to_remote, (total_chunks * chunk_size) as u64);
        assert_eq!(stats.remote_to_client, 512);
    });
}

/// 1.4 Simultaneous FIN: Client and Target both transmit 4KB and immediately invoke `shutdown()`.
/// Both sides cleanly read 4KB until EOF without protocol or socket errors.
#[test]
fn test_simultaneous_fins_with_payload() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(
                proxy_client,
                proxy_remote,
                Duration::from_secs(10),
                None,
            )
            .await
            .unwrap()
        });

        let client_data = generate_binary_payload(4096, 0x77);
        let remote_data = generate_binary_payload(4096, 0x88);

        let client_task = tokio::spawn({
            let c_data = client_data.clone();
            async move {
                client.write_all(&c_data).await.unwrap();
                client.shutdown().await.unwrap();
                let mut recv = Vec::new();
                let mut buf = [0u8; 512];
                loop {
                    let n = client.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    recv.extend_from_slice(&buf[..n]);
                }
                recv
            }
        });

        let remote_task = tokio::spawn({
            let r_data = remote_data.clone();
            async move {
                remote.write_all(&r_data).await.unwrap();
                remote.shutdown().await.unwrap();
                let mut recv = Vec::new();
                let mut buf = [0u8; 512];
                loop {
                    let n = remote.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    recv.extend_from_slice(&buf[..n]);
                }
                recv
            }
        });

        let client_res = client_task.await.unwrap();
        let remote_res = remote_task.await.unwrap();
        assert_eq!(client_res, remote_data);
        assert_eq!(remote_res, client_data);

        let stats = forward_task.await.unwrap();
        assert_eq!(stats.client_to_remote, 4096);
        assert_eq!(stats.remote_to_client, 4096);
    });
}

// ============================================================================
// AREA 2: PIPELINED DATA INTEGRITY & BOUNDARY TESTS
// ============================================================================

/// 2.1 Pipelined Data: 64KB initial chunk containing arbitrary binary data is delivered upstream
/// before subsequent client stream reads, with exact byte fidelity.
#[test]
fn test_pipelined_initial_data_large_64kb() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let pipelined_chunk = generate_binary_payload(65536, 0xAB);

        let forward_task = tokio::spawn({
            let initial = pipelined_chunk.clone();
            async move {
                copy_bidirectional_with_idle_timeout(
                    proxy_client,
                    proxy_remote,
                    Duration::from_secs(10),
                    Some(&initial),
                )
                .await
                .unwrap()
            }
        });

        // 1. Remote's initial reads must receive exactly the 64KB pipelined data
        let mut first_received = vec![0u8; pipelined_chunk.len()];
        remote.read_exact(&mut first_received).await.unwrap();
        assert_eq!(first_received, pipelined_chunk);

        // 2. Client then sends another 16KB secondary chunk
        let secondary_chunk = generate_binary_payload(16384, 0xCD);
        client.write_all(&secondary_chunk).await.unwrap();

        let mut second_received = vec![0u8; secondary_chunk.len()];
        remote.read_exact(&mut second_received).await.unwrap();
        assert_eq!(second_received, secondary_chunk);

        // 3. Remote responds with 32KB
        let response_chunk = generate_binary_payload(32768, 0xEF);
        remote.write_all(&response_chunk).await.unwrap();

        let mut client_received = vec![0u8; response_chunk.len()];
        client.read_exact(&mut client_received).await.unwrap();
        assert_eq!(client_received, response_chunk);

        client.shutdown().await.unwrap();
        remote.shutdown().await.unwrap();

        let stats = forward_task.await.unwrap();
        assert_eq!(stats.client_to_remote, 65536 + 16384);
        assert_eq!(stats.remote_to_client, 32768);
    });
}

/// 2.2 Pipelined Data: 128KB chunk (16x DEFAULT_BUFFER_SIZE) stress-test.
#[test]
fn test_pipelined_initial_data_128kb_stress() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let big_chunk = generate_binary_payload(131072, 0x33);

        let forward_task = tokio::spawn({
            let initial = big_chunk.clone();
            async move {
                copy_bidirectional_with_idle_timeout(
                    proxy_client,
                    proxy_remote,
                    Duration::from_secs(10),
                    Some(&initial),
                )
                .await
                .unwrap()
            }
        });

        let mut remote_recv = vec![0u8; big_chunk.len()];
        remote.read_exact(&mut remote_recv).await.unwrap();
        assert_eq!(remote_recv, big_chunk);

        client.shutdown().await.unwrap();
        remote.shutdown().await.unwrap();

        let stats = forward_task.await.unwrap();
        assert_eq!(stats.client_to_remote, 131072);
        assert_eq!(stats.remote_to_client, 0);
    });
}

/// 2.3 Pipelined Data: Empty slice `Some(&[])` handled as no-op.
#[test]
fn test_pipelined_initial_data_empty_slice() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let empty: &[u8] = &[];
        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(
                proxy_client,
                proxy_remote,
                Duration::from_secs(10),
                Some(empty),
            )
            .await
            .unwrap()
        });

        client.write_all(b"HELLO").await.unwrap();
        let mut buf = [0u8; 5];
        remote.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HELLO");

        client.shutdown().await.unwrap();
        remote.shutdown().await.unwrap();

        let stats = forward_task.await.unwrap();
        assert_eq!(stats.client_to_remote, 5);
        assert_eq!(stats.remote_to_client, 0);
    });
}

// ============================================================================
// AREA 3: IDLE TIMEOUT & RESET STRESS TESTS
// ============================================================================

/// 3.1 Idle Timeout: Timer resets on client-to-remote transfers, then triggers on inactivity.
#[test]
fn test_idle_timeout_reset_client_direction() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let timeout = Duration::from_millis(80);
        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(proxy_client, proxy_remote, timeout, None).await
        });

        // 3 consecutive heartbeats at 40ms intervals (< 80ms timeout)
        for i in 0..3 {
            tokio::time::sleep(Duration::from_millis(40)).await;
            client.write_all(&[i]).await.unwrap();
            let mut b = [0u8; 1];
            remote.read_exact(&mut b).await.unwrap();
            assert_eq!(b[0], i);
        }

        // Total elapsed is 120ms (> 80ms initial timeout), task is still active!
        assert!(!forward_task.is_finished());

        // Inactivity of 100ms (> 80ms) triggers timeout
        tokio::time::sleep(Duration::from_millis(100)).await;
        let res = forward_task.await.unwrap();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    });
}

/// 3.2 Idle Timeout: Timer resets on remote-to-client transfers, then triggers on inactivity.
#[test]
fn test_idle_timeout_reset_remote_direction() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let timeout = Duration::from_millis(80);
        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(proxy_client, proxy_remote, timeout, None).await
        });

        // 3 consecutive remote heartbeats at 40ms intervals
        for i in 0..3 {
            tokio::time::sleep(Duration::from_millis(40)).await;
            remote.write_all(&[i]).await.unwrap();
            let mut b = [0u8; 1];
            client.read_exact(&mut b).await.unwrap();
            assert_eq!(b[0], i);
        }

        assert!(!forward_task.is_finished());

        // Inactivity of 100ms triggers timeout
        tokio::time::sleep(Duration::from_millis(100)).await;
        let res = forward_task.await.unwrap();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    });
}

/// 3.3 Idle Timeout during Half-Close: Client sends FIN; subsequent target transfers reset timer;
/// target inactivity then triggers timeout.
#[test]
fn test_idle_timeout_reset_during_client_half_close() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let timeout = Duration::from_millis(80);
        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(proxy_client, proxy_remote, timeout, None).await
        });

        // Client sends initial data and immediately shuts down write half
        client.write_all(b"PING").await.unwrap();
        client.shutdown().await.unwrap();

        let mut buf = [0u8; 4];
        remote.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PING");

        // Target sends periodic updates at 40ms intervals in the open half
        for i in 0..3 {
            tokio::time::sleep(Duration::from_millis(40)).await;
            remote.write_all(&[i]).await.unwrap();
            let mut b = [0u8; 1];
            client.read_exact(&mut b).await.unwrap();
            assert_eq!(b[0], i);
        }

        assert!(!forward_task.is_finished());

        // Target stops sending -> times out after 100ms
        tokio::time::sleep(Duration::from_millis(100)).await;
        let res = forward_task.await.unwrap();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    });
}

/// 3.4 Idle Timeout default value conformance check.
#[test]
fn test_idle_timeout_default_constant() {
    assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(300));
    assert_eq!(DEFAULT_BUFFER_SIZE, 8192);
}

// ============================================================================
// AREA 4: OUTBOUND DIALER STRESS TESTS
// ============================================================================

/// 4.1 DirectDialer dials IPv4 and IPv6 loopback addresses.
#[test]
fn test_direct_dial_ipv4_and_ipv6() {
    run_async(async {
        // IPv4
        let listener_v4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_v4 = listener_v4.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener_v4.accept().await.unwrap();
            s.write_all(b"v4").await.unwrap();
        });

        let target_v4 = TargetAddr::from(addr_v4);
        let dialer = DirectDialer::new(Duration::from_secs(2));
        let mut stream_v4 = dialer.dial(&target_v4).await.unwrap();
        let mut buf_v4 = [0u8; 2];
        stream_v4.read_exact(&mut buf_v4).await.unwrap();
        assert_eq!(&buf_v4, b"v4");

        // IPv6
        if let Ok(listener_v6) = TcpListener::bind("[::1]:0").await {
            let addr_v6 = listener_v6.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut s, _) = listener_v6.accept().await.unwrap();
                s.write_all(b"v6").await.unwrap();
            });

            let target_v6 = TargetAddr::from(addr_v6);
            let mut stream_v6 = dialer.dial(&target_v6).await.unwrap();
            let mut buf_v6 = [0u8; 2];
            stream_v6.read_exact(&mut buf_v6).await.unwrap();
            assert_eq!(&buf_v6, b"v6");
        }
    });
}

/// 4.2 DirectDialer domain resolution with localhost.
#[test]
fn test_direct_dial_domain_localhost() {
    run_async(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"ok_localhost").await.unwrap();
        });

        let target = TargetAddr::from_domain("localhost", port).unwrap();
        let mut stream = dial_direct(&target, Duration::from_secs(3)).await.unwrap();
        let mut buf = [0u8; 12];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok_localhost");
    });
}

/// 4.3 DirectDialer refuses connection on closed port.
#[test]
fn test_direct_dial_refused_closed_port() {
    run_async(async {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };

        let target = TargetAddr::from_ip(std::net::Ipv4Addr::LOCALHOST, port);
        let dialer = DirectDialer::new(Duration::from_secs(2));
        let res = dialer.dial(&target).await;
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionRefused
        );
    });
}

/// 4.4 DirectDialer connection timeout budget enforcement on unroutable IP (TEST-NET-2).
#[test]
fn test_direct_dial_unroutable_ip_timeout() {
    run_async(async {
        let target = TargetAddr::from_ip(std::net::Ipv4Addr::LOCALHOST, 18484);
        let dialer = DirectDialer::new(Duration::from_nanos(1));
        let res = dialer.dial(&target).await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    });
}

// ============================================================================
// AREA 5: HIGH-THROUGHPUT FULL-DUPLEX CONCURRENCY STRESS
// ============================================================================

/// 5.1 Full-Duplex simultaneous 256KB transfer in both directions.
#[test]
fn test_concurrent_full_duplex_large_stream() {
    run_async(async {
        let (client, proxy_client, proxy_remote, remote) = proxy_harness().await;

        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(
                proxy_client,
                proxy_remote,
                Duration::from_secs(15),
                None,
            )
            .await
            .unwrap()
        });

        let data_size = 256 * 1024; // 256 KB
        let client_send_data = generate_binary_payload(data_size, 0x12);
        let remote_send_data = generate_binary_payload(data_size, 0x34);

        let client_task = tokio::spawn({
            let send = client_send_data.clone();
            async move {
                let (mut r, mut w) = client.into_split();
                let send_task = tokio::spawn(async move {
                    w.write_all(&send).await.unwrap();
                    w.shutdown().await.unwrap();
                });
                let recv_task = tokio::spawn(async move {
                    let mut buf = vec![0u8; data_size];
                    r.read_exact(&mut buf).await.unwrap();
                    buf
                });
                send_task.await.unwrap();
                recv_task.await.unwrap()
            }
        });

        let remote_task = tokio::spawn({
            let send = remote_send_data.clone();
            async move {
                let (mut r, mut w) = remote.into_split();
                let send_task = tokio::spawn(async move {
                    w.write_all(&send).await.unwrap();
                    w.shutdown().await.unwrap();
                });
                let recv_task = tokio::spawn(async move {
                    let mut buf = vec![0u8; data_size];
                    r.read_exact(&mut buf).await.unwrap();
                    buf
                });
                send_task.await.unwrap();
                recv_task.await.unwrap()
            }
        });

        let client_recv = client_task.await.unwrap();
        let remote_recv = remote_task.await.unwrap();
        assert_eq!(client_recv, remote_send_data);
        assert_eq!(remote_recv, client_send_data);

        let stats = forward_task.await.unwrap();
        assert_eq!(stats.client_to_remote, data_size as u64);
        assert_eq!(stats.remote_to_client, data_size as u64);
        assert_eq!(stats.total_bytes(), (data_size * 2) as u64);
    });
}

/// 4.5 DirectDialer multi-IP fallback: Bind only to IPv4 loopback on dynamic port.
/// When dialing "localhost", if IPv6 candidate `[::1]:port` is returned first by system DNS,
/// it refuses, and the dialer must fall back to `127.0.0.1:port` within the timeout budget.
#[test]
fn test_direct_dial_multi_ip_fallback() {
    run_async(async {
        // Bind strictly to IPv4 127.0.0.1 (guaranteeing [::1] on this port will refuse connection)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"fallback_success").await.unwrap();
        });

        let target = TargetAddr::from_domain("localhost", port).unwrap();
        let dialer = DirectDialer::new(Duration::from_secs(5));
        let mut stream = dialer
            .dial(&target)
            .await
            .expect("Multi-IP dial must succeed via fallback");

        let mut buf = [0u8; 16];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"fallback_success");
    });
}

/// 3.5 Idle Timeout during Remote Half-Close: Target sends FIN; client transfers reset timer;
/// client inactivity then triggers timeout.
#[test]
fn test_idle_timeout_reset_during_remote_half_close() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let timeout = Duration::from_millis(80);
        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(proxy_client, proxy_remote, timeout, None).await
        });

        // Remote sends initial data and immediately shuts down write half
        remote.write_all(b"PONG").await.unwrap();
        remote.shutdown().await.unwrap();

        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PONG");

        // Client sends periodic updates at 40ms intervals in the open half
        for i in 0..3 {
            tokio::time::sleep(Duration::from_millis(40)).await;
            client.write_all(&[i]).await.unwrap();
            let mut b = [0u8; 1];
            remote.read_exact(&mut b).await.unwrap();
            assert_eq!(b[0], i);
        }

        assert!(!forward_task.is_finished());

        // Client stops sending -> times out after 100ms
        tokio::time::sleep(Duration::from_millis(100)).await;
        let res = forward_task.await.unwrap();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    });
}

/// 1.5 Abrupt Drop: Client writes data and drops socket immediately (simulating process crash/RST).
/// Remote detects EOF, forward task cleanly terminates without panic.
#[test]
fn test_abrupt_client_socket_drop() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(
                proxy_client,
                proxy_remote,
                Duration::from_secs(5),
                None,
            )
            .await
        });

        client.write_all(b"ABRUPT_DATA").await.unwrap();
        drop(client); // Abrupt TCP close

        let mut buf = [0u8; 64];
        let mut total = Vec::new();
        loop {
            let n = remote.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&total, b"ABRUPT_DATA");

        // Target also closes
        remote.shutdown().await.unwrap();

        let res = forward_task.await.unwrap();
        assert!(res.is_ok());
        let stats = res.unwrap();
        assert_eq!(stats.client_to_remote, 11);
    });
}

/// 1.6 Abrupt Drop: Remote writes banner and drops socket immediately.
/// Client detects EOF, forward task cleanly terminates without panic.
#[test]
fn test_abrupt_remote_socket_drop() {
    run_async(async {
        let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

        let forward_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(
                proxy_client,
                proxy_remote,
                Duration::from_secs(5),
                None,
            )
            .await
        });

        remote.write_all(b"REMOTE_ABRUPT").await.unwrap();
        drop(remote); // Abrupt TCP close

        let mut buf = [0u8; 64];
        let mut total = Vec::new();
        loop {
            let n = client.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&total, b"REMOTE_ABRUPT");

        client.shutdown().await.unwrap();

        let res = forward_task.await.unwrap();
        assert!(res.is_ok());
        let stats = res.unwrap();
        assert_eq!(stats.remote_to_client, 13);
    });
}
