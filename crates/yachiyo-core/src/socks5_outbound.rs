// SPDX-License-Identifier: AGPL-3.0-only

//! Outbound SOCKS5 TCP dialer (RFC 1928 & RFC 1929) and outbound registry.

use std::fmt;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::address::{TargetAddr, TargetHost};
use crate::outbound::DirectDialer;

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const USERPASS_SUBNEG_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Authentication configuration for an outbound SOCKS5 server.
#[derive(Clone, PartialEq, Eq)]
pub enum Socks5Auth {
    /// No authentication (`0x00`).
    None,
    /// Username/password authentication per RFC 1929 (`0x02`).
    UsernamePassword { username: String, password: String },
}

impl fmt::Debug for Socks5Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::UsernamePassword { username, .. } => f
                .debug_struct("UsernamePassword")
                .field("username", username)
                .field("password", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Configuration for a SOCKS5 TCP outbound node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5OutboundConfig {
    pub server: TargetAddr,
    pub auth: Socks5Auth,
}

pub use crate::group::{OutboundRegistry, OutboundTarget, ResolvedOutbound};

/// Outbound SOCKS5 TCP dialer (RFC 1928 + RFC 1929).
pub struct Socks5Dialer;

impl Socks5Dialer {
    /// Connects to `cfg.server`, performs SOCKS5 handshake/auth, and issues a `CONNECT`
    /// request for `target` within the total `connect_timeout` budget.
    pub async fn dial(
        cfg: &Socks5OutboundConfig,
        target: &TargetAddr,
        connect_timeout: Duration,
    ) -> Result<TcpStream, Error> {
        let deadline = Instant::now() + connect_timeout;

        match tokio::time::timeout_at(deadline, Self::dial_inner(cfg, target, deadline)).await {
            Ok(res) => res,
            Err(_) => Err(Error::new(
                ErrorKind::TimedOut,
                format!(
                    "SOCKS5 outbound dial to {target} via {} timed out after {:?}",
                    cfg.server, connect_timeout
                ),
            )),
        }
    }

    async fn dial_inner(
        cfg: &Socks5OutboundConfig,
        target: &TargetAddr,
        deadline: Instant,
    ) -> Result<TcpStream, Error> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut stream = DirectDialer::new(remaining).dial(&cfg.server).await?;

        // 1. Method negotiation
        let offered_method = match &cfg.auth {
            Socks5Auth::None => AUTH_NONE,
            Socks5Auth::UsernamePassword { .. } => AUTH_USER_PASS,
        };
        stream
            .write_all(&[SOCKS5_VERSION, 0x01, offered_method])
            .await?;

        let mut method_resp = [0u8; 2];
        stream.read_exact(&mut method_resp).await?;
        if method_resp[0] != SOCKS5_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unexpected SOCKS version 0x{:02x}", method_resp[0]),
            ));
        }
        if method_resp[1] == AUTH_NO_ACCEPTABLE || method_resp[1] != offered_method {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "SOCKS5 server rejected authentication method (selected 0x{:02x})",
                    method_resp[1]
                ),
            ));
        }

        // 2. RFC 1929 username/password subnegotiation if configured
        if let Socks5Auth::UsernamePassword { username, password } = &cfg.auth {
            let u_bytes = username.as_bytes();
            let p_bytes = password.as_bytes();
            if u_bytes.is_empty()
                || u_bytes.len() > 255
                || p_bytes.is_empty()
                || p_bytes.len() > 255
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "SOCKS5 username and password must each be 1..=255 bytes",
                ));
            }
            let mut auth_req = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
            auth_req.push(USERPASS_SUBNEG_VERSION);
            auth_req.push(u_bytes.len() as u8);
            auth_req.extend_from_slice(u_bytes);
            auth_req.push(p_bytes.len() as u8);
            auth_req.extend_from_slice(p_bytes);
            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[0] != USERPASS_SUBNEG_VERSION || auth_resp[1] != 0x00 {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "SOCKS5 username/password authentication failed",
                ));
            }
        }

        // 3. Send CONNECT request
        let mut req = Vec::with_capacity(32);
        req.push(SOCKS5_VERSION);
        req.push(CMD_CONNECT);
        req.push(0x00); // RSV
        match &target.host {
            TargetHost::Ip(IpAddr::V4(v4)) => {
                req.push(ATYP_IPV4);
                req.extend_from_slice(&v4.octets());
            }
            TargetHost::Ip(IpAddr::V6(v6)) => {
                req.push(ATYP_IPV6);
                req.extend_from_slice(&v6.octets());
            }
            TargetHost::Domain(domain) => {
                let d_bytes = domain.as_bytes();
                if d_bytes.is_empty() || d_bytes.len() > 255 {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("invalid SOCKS5 domain length: {}", d_bytes.len()),
                    ));
                }
                req.push(ATYP_DOMAIN);
                req.push(d_bytes.len() as u8);
                req.extend_from_slice(d_bytes);
            }
        }
        req.extend_from_slice(&target.port.to_be_bytes());
        stream.write_all(&req).await?;
        stream.flush().await?;

        // 4. Read CONNECT reply
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr).await?;
        if hdr[0] != SOCKS5_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unexpected SOCKS5 reply version 0x{:02x}", hdr[0]),
            ));
        }

        // Consume bound address regardless of rep so stream framing stays clean.
        match hdr[3] {
            ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                stream.read_exact(&mut skip).await?;
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                stream.read_exact(&mut skip).await?;
            }
            ATYP_DOMAIN => {
                let len = stream.read_u8().await? as usize;
                let mut skip = vec![0u8; len + 2];
                stream.read_exact(&mut skip).await?;
            }
            other => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("unexpected SOCKS5 reply ATYP 0x{other:02x}"),
                ));
            }
        }

        if hdr[1] != 0x00 {
            return Err(map_rep_to_io_error(hdr[1], target));
        }

        tracing::info!(
            target = %target,
            server = %cfg.server,
            "outbound SOCKS5 connection established"
        );
        Ok(stream)
    }
}

fn map_rep_to_io_error(rep: u8, target: &TargetAddr) -> Error {
    let kind = match rep {
        0x02 => ErrorKind::PermissionDenied,
        0x03 => ErrorKind::NetworkUnreachable,
        0x04 => ErrorKind::HostUnreachable,
        0x05 => ErrorKind::ConnectionRefused,
        0x06 => ErrorKind::TimedOut,
        _ => ErrorKind::Other,
    };
    Error::new(
        kind,
        format!("SOCKS5 outbound CONNECT to {target} failed with REP 0x{rep:02x}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn run_async<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn test_socks5_auth_debug_redacts_password() {
        let auth = Socks5Auth::UsernamePassword {
            username: "alice".to_string(),
            password: "super-secret-password".to_string(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("alice"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("super-secret-password"));
    }

    #[test]
    fn test_socks5_dialer_no_auth_and_domain_target() {
        run_async(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server_addr = listener.local_addr().unwrap();

            let server_task = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut auth_hdr = [0u8; 3];
                sock.read_exact(&mut auth_hdr).await.unwrap();
                assert_eq!(auth_hdr, [0x05, 0x01, 0x00]);
                sock.write_all(&[0x05, 0x00]).await.unwrap();

                let mut req_hdr = [0u8; 4];
                sock.read_exact(&mut req_hdr).await.unwrap();
                assert_eq!(req_hdr, [0x05, 0x01, 0x00, 0x03]);
                let len = sock.read_u8().await.unwrap() as usize;
                let mut dom = vec![0u8; len];
                sock.read_exact(&mut dom).await.unwrap();
                assert_eq!(dom, b"example.com");
                let mut port = [0u8; 2];
                sock.read_exact(&mut port).await.unwrap();
                assert_eq!(u16::from_be_bytes(port), 443);

                sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();

                let mut msg = [0u8; 4];
                sock.read_exact(&mut msg).await.unwrap();
                assert_eq!(&msg, b"ping");
                sock.write_all(b"pong").await.unwrap();
            });

            let cfg = Socks5OutboundConfig {
                server: TargetAddr::from(server_addr),
                auth: Socks5Auth::None,
            };
            let target = TargetAddr::new(TargetHost::Domain("example.com".to_string()), 443);
            let mut stream = Socks5Dialer::dial(&cfg, &target, Duration::from_secs(5))
                .await
                .unwrap();

            stream.write_all(b"ping").await.unwrap();
            let mut resp = [0u8; 4];
            stream.read_exact(&mut resp).await.unwrap();
            assert_eq!(&resp, b"pong");

            server_task.await.unwrap();
        });
    }

    #[test]
    fn test_socks5_dialer_userpass_auth_success_and_failure() {
        run_async(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server_addr = listener.local_addr().unwrap();

            let server_task = tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut sock, _) = listener.accept().await.unwrap();
                    let mut auth_hdr = [0u8; 3];
                    sock.read_exact(&mut auth_hdr).await.unwrap();
                    assert_eq!(auth_hdr, [0x05, 0x01, 0x02]);
                    sock.write_all(&[0x05, 0x02]).await.unwrap();

                    let ver = sock.read_u8().await.unwrap();
                    assert_eq!(ver, 0x01);
                    let ulen = sock.read_u8().await.unwrap() as usize;
                    let mut uname = vec![0u8; ulen];
                    sock.read_exact(&mut uname).await.unwrap();
                    let plen = sock.read_u8().await.unwrap() as usize;
                    let mut pass = vec![0u8; plen];
                    sock.read_exact(&mut pass).await.unwrap();

                    if uname == b"demo-user" && pass == b"demo-pass" {
                        sock.write_all(&[0x01, 0x00]).await.unwrap();
                        let mut req = [0u8; 10];
                        sock.read_exact(&mut req).await.unwrap();
                        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await
                            .unwrap();
                    } else {
                        sock.write_all(&[0x01, 0x01]).await.unwrap();
                    }
                }
            });

            let target: TargetAddr = "192.0.2.10:80".parse().unwrap();

            let good_cfg = Socks5OutboundConfig {
                server: TargetAddr::from(server_addr),
                auth: Socks5Auth::UsernamePassword {
                    username: "demo-user".to_string(),
                    password: "demo-pass".to_string(),
                },
            };
            assert!(
                Socks5Dialer::dial(&good_cfg, &target, Duration::from_secs(5))
                    .await
                    .is_ok()
            );

            let bad_cfg = Socks5OutboundConfig {
                server: TargetAddr::from(server_addr),
                auth: Socks5Auth::UsernamePassword {
                    username: "demo-user".to_string(),
                    password: "wrong-password".to_string(),
                },
            };
            let err = Socks5Dialer::dial(&bad_cfg, &target, Duration::from_secs(5))
                .await
                .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::PermissionDenied);

            server_task.await.unwrap();
        });
    }

    #[test]
    fn test_socks5_dialer_rep_error_mapping() {
        run_async(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server_addr = listener.local_addr().unwrap();

            let server_task = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut auth_hdr = [0u8; 3];
                sock.read_exact(&mut auth_hdr).await.unwrap();
                sock.write_all(&[0x05, 0x00]).await.unwrap();
                let mut req = [0u8; 10];
                sock.read_exact(&mut req).await.unwrap();
                // REP = 0x05 Connection Refused
                sock.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            });

            let cfg = Socks5OutboundConfig {
                server: TargetAddr::from(server_addr),
                auth: Socks5Auth::None,
            };
            let target: TargetAddr = "192.0.2.10:80".parse().unwrap();
            let err = Socks5Dialer::dial(&cfg, &target, Duration::from_secs(5))
                .await
                .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);

            server_task.await.unwrap();
        });
    }
}
