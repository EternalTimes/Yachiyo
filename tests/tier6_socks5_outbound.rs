// SPDX-License-Identifier: AGPL-3.0-only

//! Tier 6 E2E Tests: SOCKS5 TCP outbound (no-auth and RFC 1929 username/password auth).

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

use yachiyo_e2e::client::{
    TargetDestination, http_connect, read_http_response, socks5_connect, verify_bidirectional_echo,
};
use yachiyo_e2e::echo::{EchoMode, EchoServer};
use yachiyo_e2e::proxy::{ProxyConfig, ProxyProcess};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
enum UpstreamAuth {
    None,
    UserPass { user: String, pass: String },
}

async fn spawn_upstream_socks5(auth: UpstreamAuth) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let auth = auth.clone();
            tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                if client.read_exact(&mut hdr).await.is_err() || hdr[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; hdr[1] as usize];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }

                match &auth {
                    UpstreamAuth::None => {
                        if !methods.contains(&0x00) {
                            let _ = client.write_all(&[0x05, 0xFF]).await;
                            return;
                        }
                        if client.write_all(&[0x05, 0x00]).await.is_err() {
                            return;
                        }
                    }
                    UpstreamAuth::UserPass { user, pass } => {
                        if !methods.contains(&0x02) {
                            let _ = client.write_all(&[0x05, 0xFF]).await;
                            return;
                        }
                        if client.write_all(&[0x05, 0x02]).await.is_err() {
                            return;
                        }
                        let mut sub = [0u8; 2];
                        if client.read_exact(&mut sub).await.is_err() || sub[0] != 0x01 {
                            return;
                        }
                        let mut u = vec![0u8; sub[1] as usize];
                        if client.read_exact(&mut u).await.is_err() {
                            return;
                        }
                        let plen = match client.read_u8().await {
                            Ok(n) => n as usize,
                            Err(_) => return,
                        };
                        let mut p = vec![0u8; plen];
                        if client.read_exact(&mut p).await.is_err() {
                            return;
                        }
                        if u == user.as_bytes() && p == pass.as_bytes() {
                            if client.write_all(&[0x01, 0x00]).await.is_err() {
                                return;
                            }
                        } else {
                            let _ = client.write_all(&[0x01, 0x01]).await;
                            return;
                        }
                    }
                }

                let mut req = [0u8; 4];
                if client.read_exact(&mut req).await.is_err() || req[0] != 0x05 || req[1] != 0x01 {
                    return;
                }
                let target = match req[3] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        if client.read_exact(&mut ip).await.is_err() {
                            return;
                        }
                        let port = match client.read_u16().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port).to_string()
                    }
                    0x04 => {
                        let mut ip = [0u8; 16];
                        if client.read_exact(&mut ip).await.is_err() {
                            return;
                        }
                        let port = match client.read_u16().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port).to_string()
                    }
                    0x03 => {
                        let len = match client.read_u8().await {
                            Ok(n) => n as usize,
                            Err(_) => return,
                        };
                        let mut dom = vec![0u8; len];
                        if client.read_exact(&mut dom).await.is_err() {
                            return;
                        }
                        let port = match client.read_u16().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        format!("{}:{port}", String::from_utf8_lossy(&dom))
                    }
                    _ => return,
                };

                match TcpStream::connect(&target).await {
                    Ok(mut remote) => {
                        let _ = client
                            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                        let _ = copy_bidirectional(&mut client, &mut remote).await;
                    }
                    Err(_) => {
                        let _ = client
                            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                    }
                }
            });
        }
    });

    addr
}

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

#[tokio::test]
async fn test_socks5_outbound_no_auth_and_userpass_e2e() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let upstream_noauth = spawn_upstream_socks5(UpstreamAuth::None).await;
    let upstream_auth = spawn_upstream_socks5(UpstreamAuth::UserPass {
        user: "test-user".to_string(),
        pass: "secret-fixture-pass".to_string(),
    })
    .await;

    let proxy_addr = ProxyProcess::get_available_addr();
    let yaml = format!(
        r#"
schema_version: 1
listeners:
  mixed: {proxy_addr}
logging:
  level: debug
outbounds:
  socks-noauth:
    type: socks5
    server: {upstream_noauth}
  socks-auth:
    type: socks5
    server: {upstream_auth}
    username: test-user
    password: secret-fixture-pass
rules:
  - DOMAIN,localhost,socks-auth
  - MATCH,socks-noauth
"#
    );
    let cfg_path = write_temp_config("socks5_outbound", &yaml);

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
            panic!("failed to start proxy: {e}");
        }
    };

    // 1. SOCKS5 inbound -> socks-noauth outbound -> IPv4 echo
    let target_ip = TargetDestination::from_socket_addr(echo_addr);
    let s1 = socks5_connect(proxy_addr, &target_ip, TEST_TIMEOUT)
        .await
        .unwrap();
    verify_bidirectional_echo(s1, b"Via SOCKS5 no-auth outbound")
        .await
        .unwrap();

    // 2. HTTP CONNECT inbound -> socks-auth outbound -> domain localhost echo
    let target_dom = TargetDestination::Domain("localhost".to_string(), echo_addr.port());
    let s2 = http_connect(proxy_addr, &target_dom, TEST_TIMEOUT)
        .await
        .unwrap();
    verify_bidirectional_echo(s2, b"Via SOCKS5 userpass outbound")
        .await
        .unwrap();

    // Verify password never appears in debug logs
    proxy
        .assert_zero_payload_logging(&["secret-fixture-pass"])
        .await;

    drop(proxy);
    let _ = fs::remove_file(&cfg_path);
}

#[tokio::test]
async fn test_socks5_outbound_wrong_password_returns_502() {
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let echo_addr = echo.addr();

    let upstream_auth = spawn_upstream_socks5(UpstreamAuth::UserPass {
        user: "test-user".to_string(),
        pass: "correct-pass".to_string(),
    })
    .await;

    let proxy_addr = ProxyProcess::get_available_addr();
    let yaml = format!(
        r#"
schema_version: 1
listeners:
  mixed: {proxy_addr}
outbounds:
  bad-auth:
    type: socks5
    server: {upstream_auth}
    username: test-user
    password: wrong-pass-never-logged
rules:
  - MATCH,bad-auth
"#
    );
    let cfg_path = write_temp_config("socks5_bad_auth", &yaml);

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
            panic!("failed to start proxy: {e}");
        }
    };

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let (status, _, _) = read_http_response(&mut s).await.unwrap();
    assert_eq!(status, 502);

    proxy
        .assert_zero_payload_logging(&["wrong-pass-never-logged"])
        .await;

    drop(proxy);
    let _ = fs::remove_file(&cfg_path);
}
