// SPDX-License-Identifier: AGPL-3.0-only

//! SOCKS Protocol Version 5 (RFC 1928) wire protocol handler.
//!
//! Handles:
//! - Authentication method negotiation (NO AUTHENTICATION REQUIRED `0x00`)
//! - SOCKS5 CONNECT request parsing (IPv4 `0x01`, Domain `0x03`, IPv6 `0x04`)
//! - Error reply mapping and fixed 10-byte response encoding
//! - Rejection of unsupported commands (BIND `0x02`, UDP ASSOCIATE `0x03`) and address types

use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yachiyo_core::{AddressParseError, TargetAddr, TargetHost};

/// SOCKS protocol version 5.
pub const SOCKS_VERSION: u8 = 0x05;

/// SOCKS5 authentication method: No authentication required.
pub const METHOD_NO_AUTH: u8 = 0x00;

/// SOCKS5 authentication method: No acceptable methods.
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// SOCKS5 command: CONNECT.
pub const CMD_CONNECT: u8 = 0x01;

/// SOCKS5 command: BIND (unsupported in M1).
pub const CMD_BIND: u8 = 0x02;

/// SOCKS5 command: UDP ASSOCIATE (unsupported in M1).
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// SOCKS5 address type: IPv4 address.
pub const ATYP_IPV4: u8 = 0x01;

/// SOCKS5 address type: Domain name.
pub const ATYP_DOMAIN: u8 = 0x03;

/// SOCKS5 address type: IPv6 address.
pub const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reserved field byte.
pub const RSV_RESERVED: u8 = 0x00;

/// SOCKS5 Reply Field status codes defined in RFC 1928 §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RepCode {
    /// 0x00: Success
    Success = 0x00,
    /// 0x01: General SOCKS server failure
    GeneralFailure = 0x01,
    /// 0x02: Connection not allowed by ruleset
    ConnectionNotAllowed = 0x02,
    /// 0x03: Network unreachable
    NetworkUnreachable = 0x03,
    /// 0x04: Host unreachable / DNS resolution failure / timeout
    HostUnreachable = 0x04,
    /// 0x05: Connection refused
    ConnectionRefused = 0x05,
    /// 0x06: TTL expired
    TtlExpired = 0x06,
    /// 0x07: Command not supported
    CommandNotSupported = 0x07,
    /// 0x08: Address type not supported
    AddressTypeNotSupported = 0x08,
}

impl RepCode {
    /// Return the raw byte representation of the reply code.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Map a standard `std::io::Error` to the most appropriate SOCKS5 `RepCode`.
    pub fn from_io_error(err: &std::io::Error) -> Self {
        match err.kind() {
            ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            ErrorKind::TimedOut => Self::HostUnreachable,
            ErrorKind::NotFound | ErrorKind::HostUnreachable => Self::HostUnreachable,
            ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            ErrorKind::PermissionDenied => Self::ConnectionNotAllowed,
            _ => Self::GeneralFailure,
        }
    }
}

impl fmt::Display for RepCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Success (0x00)"),
            Self::GeneralFailure => write!(f, "General SOCKS server failure (0x01)"),
            Self::ConnectionNotAllowed => write!(f, "Connection not allowed by ruleset (0x02)"),
            Self::NetworkUnreachable => write!(f, "Network unreachable (0x03)"),
            Self::HostUnreachable => write!(f, "Host unreachable (0x04)"),
            Self::ConnectionRefused => write!(f, "Connection refused (0x05)"),
            Self::TtlExpired => write!(f, "TTL expired (0x06)"),
            Self::CommandNotSupported => write!(f, "Command not supported (0x07)"),
            Self::AddressTypeNotSupported => write!(f, "Address type not supported (0x08)"),
        }
    }
}

/// Errors that can occur during SOCKS5 handshake and request parsing.
#[derive(Debug, Error)]
pub enum Socks5Error {
    #[error("I/O error during SOCKS5 exchange: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid SOCKS version: expected 5, got {0}")]
    InvalidVersion(u8),

    #[error("no acceptable authentication method offered by client")]
    NoAcceptableAuthMethod,

    #[error("unsupported SOCKS5 command: {0:#04x} (only CONNECT 0x01 is supported)")]
    UnsupportedCommand(u8),

    #[error("invalid reserved byte: expected 0x00, got {0:#04x}")]
    InvalidReserved(u8),

    #[error("unsupported address type: {0:#04x} (supported: IPv4 0x01, Domain 0x03, IPv6 0x04)")]
    UnsupportedAddressType(u8),

    #[error("invalid domain name: {0}")]
    InvalidDomain(String),

    #[error("address parsing error: {0}")]
    AddressParse(#[from] AddressParseError),
}

/// Encode a standard 10-byte SOCKS5 response frame.
///
/// Layout (RFC 1928 §5):
/// `+----+-----+-------+------+----------+----------+`
/// `|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |`
/// `+----+-----+-------+------+----------+----------+`
/// `| 1  |  1  | X'00' | 0x01 | 0,0,0,0  |   0, 0   |`
/// `+----+-----+-------+------+----------+----------+`
#[inline]
pub const fn encode_reply(rep: RepCode) -> [u8; 10] {
    [
        SOCKS_VERSION,
        rep.as_u8(),
        RSV_RESERVED,
        ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
}

/// Write a standard 10-byte SOCKS5 response frame to the stream and flush.
pub async fn write_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    rep: RepCode,
) -> Result<(), std::io::Error> {
    stream.write_all(&encode_reply(rep)).await?;
    stream.flush().await?;
    Ok(())
}

/// Write a SOCKS5 reply corresponding to an `std::io::Error` and flush.
pub async fn write_reply_for_io_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    err: &std::io::Error,
) -> Result<RepCode, std::io::Error> {
    let rep = RepCode::from_io_error(err);
    write_reply(stream, rep).await?;
    Ok(rep)
}

/// Negotiate authentication with client.
///
/// Accepts an optional `initial_byte` (e.g. from protocol sniffing on mixed port).
/// If `initial_byte` is `None`, reads the version byte from `stream`.
///
/// Checks that client requests SOCKS5 (`0x05`) and offers method `0x00` (NO AUTH).
/// - If `0x00` is offered, replies `[0x05, 0x00]` and returns `Ok(())`.
/// - If `0x00` is not offered, replies `[0x05, 0xFF]` and returns `Err(Socks5Error::NoAcceptableAuthMethod)`.
/// - If version is not `0x05`, returns `Err(Socks5Error::InvalidVersion)` without sending a reply.
pub async fn negotiate_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    initial_byte: Option<u8>,
) -> Result<(), Socks5Error> {
    let ver = match initial_byte {
        Some(b) => b,
        None => stream.read_u8().await?,
    };

    if ver != SOCKS_VERSION {
        return Err(Socks5Error::InvalidVersion(ver));
    }

    let nmethods = stream.read_u8().await?;
    if nmethods == 0 {
        let _ = stream
            .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
            .await;
        let _ = stream.flush().await;
        return Err(Socks5Error::NoAcceptableAuthMethod);
    }

    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    if methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        stream.flush().await?;
        Ok(())
    } else {
        let _ = stream
            .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
            .await;
        let _ = stream.flush().await;
        Err(Socks5Error::NoAcceptableAuthMethod)
    }
}

/// Parse SOCKS5 CONNECT request from client after authentication negotiation.
///
/// Reads the request header `[VER, CMD, RSV, ATYP]`:
/// - Checks `VER == 0x05`
/// - Checks `CMD == 0x01` (CONNECT). If CMD != 1, writes `REP 0x07` (Command not supported) and returns error.
/// - Checks `RSV == 0x00`. If RSV != 0, writes `REP 0x01` (General failure) and returns error.
/// - Parses destination address according to ATYP:
///   - `0x01` IPv4: reads 4 octets
///   - `0x03` Domain: reads 1 length octet L, then L ASCII octets
///   - `0x04` IPv6: reads 16 octets
///   - Other: writes `REP 0x08` (Address type not supported) and returns error.
/// - Parses destination port: big-endian 16-bit integer `u16`.
/// - Returns constructed `TargetAddr`.
pub async fn parse_connect_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<TargetAddr, Socks5Error> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    let [ver, cmd, rsv, atyp] = header;

    if ver != SOCKS_VERSION {
        return Err(Socks5Error::InvalidVersion(ver));
    }

    if cmd != CMD_CONNECT {
        let _ = write_reply(stream, RepCode::CommandNotSupported).await;
        return Err(Socks5Error::UnsupportedCommand(cmd));
    }

    if rsv != RSV_RESERVED {
        let _ = write_reply(stream, RepCode::GeneralFailure).await;
        return Err(Socks5Error::InvalidReserved(rsv));
    }

    let host = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            let ipv4 = Ipv4Addr::from(octets);
            TargetHost::Ip(IpAddr::V4(ipv4))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                let _ = write_reply(stream, RepCode::GeneralFailure).await;
                return Err(Socks5Error::InvalidDomain("empty domain name".to_string()));
            }
            let mut domain_buf = vec![0u8; len];
            stream.read_exact(&mut domain_buf).await?;
            let domain_str = match String::from_utf8(domain_buf) {
                Ok(s) => s,
                Err(e) => {
                    let _ = write_reply(stream, RepCode::GeneralFailure).await;
                    return Err(Socks5Error::InvalidDomain(format!("non-UTF8 domain: {e}")));
                }
            };
            match TargetHost::parse(&domain_str) {
                Ok(h) => h,
                Err(e) => {
                    let _ = write_reply(stream, RepCode::HostUnreachable).await;
                    return Err(Socks5Error::AddressParse(e));
                }
            }
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            let ipv6 = Ipv6Addr::from(octets);
            TargetHost::Ip(IpAddr::V6(ipv6))
        }
        other => {
            let _ = write_reply(stream, RepCode::AddressTypeNotSupported).await;
            return Err(Socks5Error::UnsupportedAddressType(other));
        }
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(TargetAddr::new(host, port))
}

/// Convenience function to execute full SOCKS5 handshake (auth negotiation + CONNECT request parsing).
///
/// If `initial_byte` is `Some(0x05)`, skips reading the version byte in auth negotiation.
/// Returns the parsed `TargetAddr` upon success.
pub async fn handle_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    initial_byte: Option<u8>,
) -> Result<TargetAddr, Socks5Error> {
    negotiate_auth(stream, initial_byte).await?;
    parse_connect_request(stream).await
}

/// Convenience wrapper for inbound listener to execute handshake without prior peeked byte.
#[inline]
pub async fn handshake_and_parse<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<TargetAddr, Socks5Error> {
    handle_handshake(stream, None).await
}

/// Convenience wrapper to transmit SOCKS5 success reply (REP 0x00).
#[inline]
pub async fn send_success_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<(), std::io::Error> {
    write_reply(stream, RepCode::Success).await
}

/// Convenience wrapper to transmit SOCKS5 error reply mapped from `std::io::Error`.
#[inline]
pub async fn send_error_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    err: &std::io::Error,
) -> Result<RepCode, std::io::Error> {
    write_reply_for_io_error(stream, err).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use tokio::io::duplex;

    fn run_async<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn test_encode_reply_formats() {
        assert_eq!(
            encode_reply(RepCode::Success),
            [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_reply(RepCode::GeneralFailure),
            [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_reply(RepCode::ConnectionNotAllowed),
            [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_reply(RepCode::NetworkUnreachable),
            [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_reply(RepCode::HostUnreachable),
            [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_reply(RepCode::ConnectionRefused),
            [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_reply(RepCode::TtlExpired),
            [0x05, 0x06, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_reply(RepCode::CommandNotSupported),
            [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_reply(RepCode::AddressTypeNotSupported),
            [0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_rep_code_from_io_error_mapping() {
        assert_eq!(
            RepCode::from_io_error(&std::io::Error::from(ErrorKind::ConnectionRefused)),
            RepCode::ConnectionRefused
        );
        assert_eq!(
            RepCode::from_io_error(&std::io::Error::from(ErrorKind::TimedOut)),
            RepCode::HostUnreachable
        );
        assert_eq!(
            RepCode::from_io_error(&std::io::Error::from(ErrorKind::NotFound)),
            RepCode::HostUnreachable
        );
        assert_eq!(
            RepCode::from_io_error(&std::io::Error::from(ErrorKind::HostUnreachable)),
            RepCode::HostUnreachable
        );
        assert_eq!(
            RepCode::from_io_error(&std::io::Error::from(ErrorKind::NetworkUnreachable)),
            RepCode::NetworkUnreachable
        );
        assert_eq!(
            RepCode::from_io_error(&std::io::Error::from(ErrorKind::PermissionDenied)),
            RepCode::ConnectionNotAllowed
        );
        assert_eq!(
            RepCode::from_io_error(&std::io::Error::from(ErrorKind::Other)),
            RepCode::GeneralFailure
        );
    }

    #[test]
    fn test_rep_code_display() {
        assert_eq!(format!("{}", RepCode::Success), "Success (0x00)");
        assert_eq!(
            format!("{}", RepCode::CommandNotSupported),
            "Command not supported (0x07)"
        );
    }

    #[test]
    fn test_auth_success_no_auth() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // Client sends VER 5, NMETHODS 1, METHOD 0x00
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut resp = [0u8; 2];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(resp, [0x05, 0x00]);
            });

            negotiate_auth(&mut server, None).await.unwrap();
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_auth_success_multiple_methods() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // Client offers GSSAPI (0x01), USER/PASS (0x02), NO AUTH (0x00)
                client
                    .write_all(&[0x05, 0x03, 0x01, 0x02, 0x00])
                    .await
                    .unwrap();
                let mut resp = [0u8; 2];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(resp, [0x05, 0x00]);
            });

            negotiate_auth(&mut server, None).await.unwrap();
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_auth_with_sniffed_initial_byte() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // First byte 0x05 already read by sniffer; client sent NMETHODS 1, METHOD 0x00
                client.write_all(&[0x01, 0x00]).await.unwrap();
                let mut resp = [0u8; 2];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(resp, [0x05, 0x00]);
            });

            negotiate_auth(&mut server, Some(0x05)).await.unwrap();
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_auth_rejection_no_acceptable_methods() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // Client offers USER/PASS only (0x02)
                client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
                let mut resp = [0u8; 2];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(resp, [0x05, 0xFF]);
            });

            let err = negotiate_auth(&mut server, None).await.unwrap_err();
            assert!(matches!(err, Socks5Error::NoAcceptableAuthMethod));
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_auth_zero_methods() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // Client sends NMETHODS 0
                client.write_all(&[0x05, 0x00]).await.unwrap();
                let mut resp = [0u8; 2];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(resp, [0x05, 0xFF]);
            });

            let err = negotiate_auth(&mut server, None).await.unwrap_err();
            assert!(matches!(err, Socks5Error::NoAcceptableAuthMethod));
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_auth_invalid_version() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // Client sends SOCKS4 version 0x04
                client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
            });

            let err = negotiate_auth(&mut server, None).await.unwrap_err();
            assert!(matches!(err, Socks5Error::InvalidVersion(4)));
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_parse_connect_ipv4() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            tokio::spawn(async move {
                // VER 5, CMD 1 (CONNECT), RSV 0, ATYP 1 (IPv4), 192.168.1.1, port 8080 (0x1F90)
                client
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x1F, 0x90])
                    .await
                    .unwrap();
            });

            let target = parse_connect_request(&mut server).await.unwrap();
            assert_eq!(
                target,
                TargetAddr::new(
                    TargetHost::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    8080
                )
            );
        });
    }

    #[test]
    fn test_parse_connect_domain() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            tokio::spawn(async move {
                // VER 5, CMD 1, RSV 0, ATYP 3 (Domain), len 11, "example.com", port 443 (0x01BB)
                client
                    .write_all(&[
                        0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
                        b'c', b'o', b'm', 0x01, 0xBB,
                    ])
                    .await
                    .unwrap();
            });

            let target = parse_connect_request(&mut server).await.unwrap();
            assert_eq!(
                target,
                TargetAddr::new(TargetHost::Domain("example.com".to_string()), 443)
            );
        });
    }

    #[test]
    fn test_parse_connect_ipv6() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            tokio::spawn(async move {
                // VER 5, CMD 1, RSV 0, ATYP 4 (IPv6), ::1 (16 bytes), port 80 (0x0050)
                let mut req = vec![0x05, 0x01, 0x00, 0x04];
                req.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
                req.extend_from_slice(&[0x00, 0x50]);
                client.write_all(&req).await.unwrap();
            });

            let target = parse_connect_request(&mut server).await.unwrap();
            assert_eq!(
                target,
                TargetAddr::new(
                    TargetHost::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
                    80
                )
            );
        });
    }

    #[test]
    fn test_parse_connect_unsupported_command_bind() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // CMD 2 (BIND)
                client
                    .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
                    .await
                    .unwrap();
                let mut resp = [0u8; 10];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(resp, encode_reply(RepCode::CommandNotSupported));
            });

            let err = parse_connect_request(&mut server).await.unwrap_err();
            assert!(matches!(err, Socks5Error::UnsupportedCommand(2)));
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_parse_connect_unsupported_command_udp() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // CMD 3 (UDP ASSOCIATE)
                client
                    .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
                    .await
                    .unwrap();
                let mut resp = [0u8; 10];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(resp, encode_reply(RepCode::CommandNotSupported));
            });

            let err = parse_connect_request(&mut server).await.unwrap_err();
            assert!(matches!(err, Socks5Error::UnsupportedCommand(3)));
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_parse_connect_unsupported_atyp() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // ATYP 0x02 (invalid)
                client
                    .write_all(&[0x05, 0x01, 0x00, 0x02, 127, 0, 0, 1, 0x00, 0x50])
                    .await
                    .unwrap();
                let mut resp = [0u8; 10];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(resp, encode_reply(RepCode::AddressTypeNotSupported));
            });

            let err = parse_connect_request(&mut server).await.unwrap_err();
            assert!(matches!(err, Socks5Error::UnsupportedAddressType(2)));
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_parse_connect_invalid_reserved() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // RSV 0xFF
                client
                    .write_all(&[0x05, 0x01, 0xFF, 0x01, 127, 0, 0, 1, 0x00, 0x50])
                    .await
                    .unwrap();
                let mut resp = [0u8; 10];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(resp, encode_reply(RepCode::GeneralFailure));
            });

            let err = parse_connect_request(&mut server).await.unwrap_err();
            assert!(matches!(err, Socks5Error::InvalidReserved(0xFF)));
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_parse_connect_empty_domain() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                // Domain length 0
                client
                    .write_all(&[0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50])
                    .await
                    .unwrap();
                let mut resp = [0u8; 10];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(resp, encode_reply(RepCode::GeneralFailure));
            });

            let err = parse_connect_request(&mut server).await.unwrap_err();
            assert!(matches!(err, Socks5Error::InvalidDomain(_)));
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_full_handshake_flow() {
        run_async(async {
            let (mut client, mut server) = duplex(128);

            let client_task = tokio::spawn(async move {
                // 1. Auth greeting
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut auth_resp = [0u8; 2];
                client.read_exact(&mut auth_resp).await.unwrap();
                assert_eq!(auth_resp, [0x05, 0x00]);

                // 2. Request
                client
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50])
                    .await
                    .unwrap();

                // 3. Receive success reply
                let mut reply_resp = [0u8; 10];
                client.read_exact(&mut reply_resp).await.unwrap();
                assert_eq!(reply_resp, encode_reply(RepCode::Success));
            });

            let target = handle_handshake(&mut server, None).await.unwrap();
            assert_eq!(
                target,
                TargetAddr::new(TargetHost::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), 80)
            );

            write_reply(&mut server, RepCode::Success).await.unwrap();
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_write_reply_for_io_error() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            let client_task = tokio::spawn(async move {
                let mut buf = [0u8; 10];
                client.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, encode_reply(RepCode::ConnectionRefused));
            });

            let err = std::io::Error::from(ErrorKind::ConnectionRefused);
            let rep = write_reply_for_io_error(&mut server, &err).await.unwrap();
            assert_eq!(rep, RepCode::ConnectionRefused);
            client_task.await.unwrap();
        });
    }

    #[test]
    fn test_parse_connect_invalid_version() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            tokio::spawn(async move {
                client
                    .write_all(&[0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
                    .await
                    .unwrap();
            });

            let err = parse_connect_request(&mut server).await.unwrap_err();
            assert!(matches!(err, Socks5Error::InvalidVersion(4)));
        });
    }

    #[test]
    fn test_premature_eof_in_auth() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            tokio::spawn(async move {
                // Client sends 1 byte then immediately closes write half
                client.write_all(&[0x05]).await.unwrap();
                drop(client);
            });

            let err = negotiate_auth(&mut server, None).await.unwrap_err();
            assert!(matches!(err, Socks5Error::Io(_)));
        });
    }

    #[test]
    fn test_premature_eof_in_request() {
        run_async(async {
            let (mut client, mut server) = duplex(64);

            tokio::spawn(async move {
                // Client sends 2 bytes of request then drops
                client.write_all(&[0x05, 0x01]).await.unwrap();
                drop(client);
            });

            let err = parse_connect_request(&mut server).await.unwrap_err();
            assert!(matches!(err, Socks5Error::Io(_)));
        });
    }

    #[test]
    fn test_fragmented_stream_delivery() {
        run_async(async {
            let (mut client, mut server) = duplex(128);

            let client_task = tokio::spawn(async move {
                // Send auth 1 byte at a time
                for &b in &[0x05, 0x01, 0x00] {
                    client.write_all(&[b]).await.unwrap();
                    tokio::task::yield_now().await;
                }

                let mut auth_resp = [0u8; 2];
                client.read_exact(&mut auth_resp).await.unwrap();
                assert_eq!(auth_resp, [0x05, 0x00]);

                // Send request 1 byte at a time
                let req = [
                    0x05, 0x01, 0x00, 0x03, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's',
                    b't', 0x04, 0xD2,
                ];
                for &b in &req {
                    client.write_all(&[b]).await.unwrap();
                    tokio::task::yield_now().await;
                }

                let mut reply_resp = [0u8; 10];
                client.read_exact(&mut reply_resp).await.unwrap();
                assert_eq!(reply_resp, encode_reply(RepCode::Success));
            });

            let target = handle_handshake(&mut server, None).await.unwrap();
            assert_eq!(
                target,
                TargetAddr::new(TargetHost::Domain("localhost".to_string()), 1234)
            );

            write_reply(&mut server, RepCode::Success).await.unwrap();
            client_task.await.unwrap();
        });
    }
}
