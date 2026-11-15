// SPDX-License-Identifier: AGPL-3.0-only

//! Tier 8 E2E Tests: Outbound selection groups (`Selector`, `Fallback`, `UrlTest`) and health checking (M2).

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

use yachiyo_e2e::client::{TargetDestination, socks5_connect, verify_bidirectional_echo};
use yachiyo_e2e::echo::{EchoMode, EchoServer};
use yachiyo_e2e::proxy::{ProxyConfig, ProxyProcess};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn write_temp_config(name: &str, content: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("yachiyo_groups_e2e_{name}_{pid}_{nanos}.yaml"));
    fs::write(&path, content).expect("failed to write temp config");
    path
}

/// Spawns a minimal mock SOCKS5 upstream server.
async fn spawn_mock_socks5() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                if client.read_exact(&mut hdr).await.is_err() || hdr[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; hdr[1] as usize];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if client.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }

                let mut req = [0u8; 4];
                if client.read_exact(&mut req).await.is_err() || req[1] != 0x01 {
                    return;
                }

                let target_addr = match req[3] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        if client.read_exact(&mut ip).await.is_err() {
                            return;
                        }
                        let port = match client.read_u16().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        SocketAddr::from((ip, port))
                    }
                    _ => return,
                };

                let mut outbound = match TcpStream::connect(target_addr).await {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = client
                            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                        return;
                    }
                };

                let bound = outbound.local_addr().unwrap_or(target_addr);
                let ip_bytes = match bound.ip() {
                    std::net::IpAddr::V4(v4) => v4.octets(),
                    _ => [0, 0, 0, 0],
                };
                let mut reply = vec![0x05, 0x00, 0x00, 0x01];
                reply.extend_from_slice(&ip_bytes);
                reply.extend_from_slice(&bound.port().to_be_bytes());
                if client.write_all(&reply).await.is_err() {
                    return;
                }

                let _ = copy_bidirectional(&mut client, &mut outbound).await;
            });
        }
    });

    (addr, handle)
}

/// Spawns a minimal HTTP 204 health check server.
async fn spawn_mock_health_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = client.read(&mut buf).await;
                let resp = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                let _ = client.write_all(resp.as_bytes()).await;
            });
        }
    });

    (addr, handle)
}

#[tokio::test]
async fn test_selector_group_routes_to_selected_outbound() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();
    let (upstream_addr, _upstream_h) = spawn_mock_socks5().await;
    let mixed_addr = ProxyProcess::get_available_addr();

    let cfg_content = format!(
        r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
  allow_lan: false
outbounds:
  upstream_node:
    type: socks5
    server: {upstream_addr}
  my_selector:
    type: selector
    outbounds:
      - upstream_node
      - DIRECT
    selected: upstream_node
rules:
  - MATCH,my_selector
"#
    );
    let cfg_path = write_temp_config("selector", &cfg_content);

    let mut proxy = ProxyProcess::start(ProxyConfig {
        mixed_addr: Some(mixed_addr),
        extra_args: vec![
            "--config".to_string(),
            cfg_path.to_string_lossy().into_owned(),
        ],
        ..Default::default()
    })
    .await
    .expect("proxy should start");

    let target = TargetDestination::from_socket_addr(echo_addr);
    let conn = socks5_connect(mixed_addr, &target, TEST_TIMEOUT)
        .await
        .expect("should connect via selector group");
    verify_bidirectional_echo(conn, b"hello selector group")
        .await
        .unwrap();

    proxy.kill().await;
    let _ = fs::remove_file(&cfg_path);
}

#[tokio::test]
async fn test_fallback_group_selects_first_healthy() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();
    let (upstream_addr, _upstream_h) = spawn_mock_socks5().await;
    let (health_addr, _health_h) = spawn_mock_health_server().await;
    let mixed_addr = ProxyProcess::get_available_addr();

    // Use an unavailable port for primary candidate to simulate dead node
    let dead_port = ProxyProcess::get_available_port();

    let cfg_content = format!(
        r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
  allow_lan: false
outbounds:
  dead_node:
    type: socks5
    server: 127.0.0.1:{dead_port}
  live_node:
    type: socks5
    server: {upstream_addr}
  my_fallback:
    type: fallback
    outbounds:
      - dead_node
      - live_node
    url: http://{health_addr}/generate_204
    interval_secs: 10
    timeout_secs: 2
rules:
  - MATCH,my_fallback
"#
    );
    let cfg_path = write_temp_config("fallback", &cfg_content);

    let mut proxy = ProxyProcess::start(ProxyConfig {
        mixed_addr: Some(mixed_addr),
        extra_args: vec![
            "--config".to_string(),
            cfg_path.to_string_lossy().into_owned(),
        ],
        ..Default::default()
    })
    .await
    .expect("proxy should start");

    // Wait briefly for initial background health check to probe dead_node and live_node
    tokio::time::sleep(Duration::from_millis(150)).await;

    let target = TargetDestination::from_socket_addr(echo_addr);
    let conn = socks5_connect(mixed_addr, &target, TEST_TIMEOUT)
        .await
        .expect("should connect via fallback group");
    verify_bidirectional_echo(conn, b"hello fallback group")
        .await
        .unwrap();

    proxy.kill().await;
    let _ = fs::remove_file(&cfg_path);
}

#[tokio::test]
async fn test_url_test_group_selects_healthy_candidate() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();
    let (upstream_addr, _upstream_h) = spawn_mock_socks5().await;
    let (health_addr, _health_h) = spawn_mock_health_server().await;
    let mixed_addr = ProxyProcess::get_available_addr();

    let cfg_content = format!(
        r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
  allow_lan: false
outbounds:
  live_node:
    type: socks5
    server: {upstream_addr}
  direct_node:
    type: socks5
    server: {upstream_addr}
  my_url_test:
    type: url-test
    outbounds:
      - live_node
      - direct_node
    url: http://{health_addr}/generate_204
    interval_secs: 10
    timeout_secs: 2
    tolerance_ms: 50
rules:
  - MATCH,my_url_test
"#
    );
    let cfg_path = write_temp_config("url_test", &cfg_content);

    let mut proxy = ProxyProcess::start(ProxyConfig {
        mixed_addr: Some(mixed_addr),
        extra_args: vec![
            "--config".to_string(),
            cfg_path.to_string_lossy().into_owned(),
        ],
        ..Default::default()
    })
    .await
    .expect("proxy should start");

    tokio::time::sleep(Duration::from_millis(150)).await;

    let target = TargetDestination::from_socket_addr(echo_addr);
    let conn = socks5_connect(mixed_addr, &target, TEST_TIMEOUT)
        .await
        .expect("should connect via url-test group");
    verify_bidirectional_echo(conn, b"hello url-test group")
        .await
        .unwrap();

    proxy.kill().await;
    let _ = fs::remove_file(&cfg_path);
}
