// SPDX-License-Identifier: AGPL-3.0-only

//! Tier 7 E2E Tests: Atomic configuration snapshot reload on SIGHUP (M2).

#[cfg(unix)]
mod unix_reload_tests {
    use std::fs;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use yachiyo_e2e::client::{
        TargetDestination, socks5_connect, socks5_handshake_raw, socks5_send_raw_request,
        verify_bidirectional_echo,
    };
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
        path.push(format!("yachiyo_reload_e2e_{name}_{pid}_{nanos}.yaml"));
        fs::write(&path, content).expect("failed to write temp config");
        path
    }

    async fn wait_for_log_substring(proxy: &ProxyProcess, needle: &str, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let logs = proxy.dump_logs().await;
            if logs.contains(needle) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for log '{needle}'; logs:\n{logs}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    #[tokio::test]
    async fn test_sighup_hot_reloads_rules_and_preserves_inflight_connection() {
        let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
            .await
            .unwrap();
        let echo_addr: SocketAddr = echo.addr();
        let mixed_addr = ProxyProcess::get_available_addr();

        let cfg_v1 = format!(
            r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
  allow_lan: false
rules:
  - MATCH,DIRECT
"#
        );
        let cfg_path = write_temp_config("hot_reload", &cfg_v1);

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

        // Open an in-flight SOCKS5 tunnel under generation 1
        let target = TargetDestination::from_socket_addr(echo_addr);
        let mut inflight = socks5_connect(mixed_addr, &target, TEST_TIMEOUT)
            .await
            .unwrap();
        inflight.write_all(b"before-reload").await.unwrap();
        let mut buf = [0u8; 32];
        let n = inflight.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"before-reload");

        // Update config to reject 127.0.0.1/32 and trigger SIGHUP
        let cfg_v2 = format!(
            r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
  allow_lan: false
rules:
  - IP-CIDR,127.0.0.1/32,REJECT,no-resolve
  - MATCH,DIRECT
"#
        );
        fs::write(&cfg_path, cfg_v2).unwrap();
        proxy.send_sighup().unwrap();
        wait_for_log_substring(&proxy, "configuration snapshot reloaded", TEST_TIMEOUT).await;

        // Existing in-flight connection continues on generation 1 snapshot
        inflight.write_all(b"after-reload").await.unwrap();
        let n = inflight.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"after-reload");
        drop(inflight);

        // New connection uses generation 2 snapshot and gets REJECT (REP = 0x02)
        let mut new_conn = TcpStream::connect(mixed_addr).await.unwrap();
        socks5_handshake_raw(&mut new_conn, &[0x00]).await.unwrap();
        let ip_octets = match echo_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            std::net::IpAddr::V6(_) => unreachable!(),
        };
        let reply = socks5_send_raw_request(
            &mut new_conn,
            0x05,
            0x01,
            0x00,
            0x01,
            &ip_octets,
            echo_addr.port(),
        )
        .await
        .unwrap();
        assert_eq!(reply.rep, 0x02, "expected REP=0x02 after SIGHUP reload");

        proxy.kill().await;
        let _ = fs::remove_file(&cfg_path);
    }

    #[tokio::test]
    async fn test_sighup_invalid_config_preserves_active_snapshot() {
        let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
            .await
            .unwrap();
        let echo_addr: SocketAddr = echo.addr();
        let mixed_addr = ProxyProcess::get_available_addr();

        let cfg_v1 = format!(
            r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
  allow_lan: false
rules:
  - MATCH,DIRECT
"#
        );
        let cfg_path = write_temp_config("invalid_reload", &cfg_v1);

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

        // Overwrite with invalid config (dangling outbound reference)
        let bad_cfg = format!(
            r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
rules:
  - DOMAIN,app.example.com,nonexistent_outbound
  - MATCH,DIRECT
"#
        );
        fs::write(&cfg_path, bad_cfg).unwrap();
        proxy.send_sighup().unwrap();
        wait_for_log_substring(
            &proxy,
            "configuration reload failed; preserving active snapshot",
            TEST_TIMEOUT,
        )
        .await;

        // Active snapshot remains functional
        let target = TargetDestination::from_socket_addr(echo_addr);
        let conn = socks5_connect(mixed_addr, &target, TEST_TIMEOUT)
            .await
            .unwrap();
        verify_bidirectional_echo(conn, b"still-alive-after-bad-reload")
            .await
            .unwrap();

        proxy.kill().await;
        let _ = fs::remove_file(&cfg_path);
    }
}
