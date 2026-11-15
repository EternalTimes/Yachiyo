// SPDX-License-Identifier: AGPL-3.0-only

//! HTTP CONNECT protocol handler (RFC 7231 §4.3.6 / RFC 9110 §9.3.6).
//!
//! Provides:
//! - HTTP CONNECT request parsing with authority-form `host:port`
//! - IPv6 bracket syntax parsing `[::1]:port`
//! - HTTP/1.0 and HTTP/1.1 version validation
//! - Method validation: non-CONNECT methods return 405 Method Not Allowed
//! - Header size bounding capped at 8 KB (8192 bytes)
//! - Pipelined payload preservation for bytes following delimiter
//! - HTTP response generation: 200, 400, 405, 431, 502, 504
//! - Half-close bidirectional tunnel integration with idle timeout

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use yachiyo_core::address::TargetAddr;
use yachiyo_core::forward::copy_bidirectional_with_idle_timeout;
use yachiyo_core::outbound::dial_direct;

/// Maximum allowable header size before delimiter is reached (8 KB).
pub const MAX_HEADER_SIZE: usize = 8192;

/// Standard HTTP responses
pub const RESPONSE_200: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
pub const RESPONSE_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\r\n";
pub const RESPONSE_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\r\n";
pub const RESPONSE_405: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n";
pub const RESPONSE_431: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n";
pub const RESPONSE_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
pub const RESPONSE_504: &[u8] = b"HTTP/1.1 504 Gateway Timeout\r\n\r\n";

/// Supported HTTP versions for CONNECT requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

/// Parsed HTTP CONNECT request metadata and residual payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConnectRequest {
    /// Destination authority address (host and port).
    pub target: TargetAddr,
    /// HTTP version specified in request line.
    pub version: HttpVersion,
    /// Bytes received beyond the `\r\n\r\n` boundary (e.g. TLS ClientHello).
    pub pipelined_payload: Vec<u8>,
}

impl HttpConnectRequest {
    /// Return the pipelined payload slice as an `Option<&[u8]>`.
    #[inline]
    pub fn initial_data(&self) -> Option<&[u8]> {
        if self.pipelined_payload.is_empty() {
            None
        } else {
            Some(&self.pipelined_payload)
        }
    }
}

/// Errors encountered while reading or parsing an HTTP CONNECT request.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("zero-byte connection probe")]
    ZeroByteProbe,

    #[error("stream reached EOF prematurely before delimiter")]
    PrematureEof,

    #[error("header exceeded 8KB limit without delimiter")]
    HeaderTooLarge,

    #[error("non-CONNECT HTTP method: {0}")]
    MethodNotAllowed(String),

    #[error("invalid or malformed request line: {0}")]
    BadRequest(String),

    #[error("invalid authority: {0}")]
    InvalidAuthority(String),

    #[error("unsupported HTTP version: {0}")]
    UnsupportedVersion(String),
}

impl HttpParseError {
    /// Maps the error to the appropriate HTTP status response.
    /// Returns `None` for clean EOF probes where no response should be sent.
    pub fn response_bytes(&self) -> Option<&'static [u8]> {
        match self {
            Self::ZeroByteProbe | Self::PrematureEof => None,
            Self::HeaderTooLarge => Some(RESPONSE_431),
            Self::MethodNotAllowed(_) => Some(RESPONSE_405),
            Self::BadRequest(_) | Self::InvalidAuthority(_) | Self::UnsupportedVersion(_) => {
                Some(RESPONSE_400)
            }
        }
    }
}

/// Locate the end-of-headers delimiter in `buf`.
/// Returns `Some((delim_start, delim_len))` where delimiter begins at `delim_start`.
/// Prioritizes standard CRLF CRLF (`\r\n\r\n`, len 4), falling back to LF LF (`\n\n`, len 2).
pub fn find_header_delimiter(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos, 4));
    }
    if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
        return Some((pos, 2));
    }
    None
}

/// Validates whether a token represents standard ASCII HTTP method characters.
fn is_http_method_token(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_uppercase())
}

/// Parses an in-memory buffer containing an HTTP CONNECT request.
///
/// Returns `HttpConnectRequest` containing the destination `TargetAddr`, HTTP version,
/// and any unconsumed pipelined payload bytes following the header delimiter.
pub fn parse_http_connect_request(buf: &[u8]) -> Result<HttpConnectRequest, HttpParseError> {
    let (delim_start, delim_len) = match find_header_delimiter(buf) {
        Some(delim) => delim,
        None => {
            if buf.len() >= MAX_HEADER_SIZE {
                return Err(HttpParseError::HeaderTooLarge);
            }
            return Err(HttpParseError::PrematureEof);
        }
    };

    if delim_start > MAX_HEADER_SIZE {
        return Err(HttpParseError::HeaderTooLarge);
    }

    let header_bytes = &buf[..delim_start];
    let pipelined_payload = buf[delim_start + delim_len..].to_vec();

    // Extract the request line (the line up to the first LF or CRLF)
    let first_line_bytes = match header_bytes.iter().position(|&b| b == b'\n') {
        Some(pos) => {
            if pos > 0 && header_bytes[pos - 1] == b'\r' {
                &header_bytes[..pos - 1]
            } else {
                &header_bytes[..pos]
            }
        }
        None => header_bytes,
    };

    let line = std::str::from_utf8(first_line_bytes)
        .map_err(|_| HttpParseError::BadRequest("request line contains non-UTF-8 bytes".into()))?
        .trim();

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Err(HttpParseError::BadRequest("empty request line".into()));
    }

    let method = parts[0];

    // Method validation: MUST be CONNECT
    if method != "CONNECT" {
        if is_http_method_token(method) {
            return Err(HttpParseError::MethodNotAllowed(method.to_string()));
        }
        return Err(HttpParseError::BadRequest(format!(
            "invalid method token: '{method}'"
        )));
    }

    // Must have exactly 3 parts: CONNECT, authority, version
    if parts.len() != 3 {
        return Err(HttpParseError::BadRequest(format!(
            "malformed request line: '{line}'"
        )));
    }

    let authority = parts[1];
    let version_str = parts[2];

    // Version validation: HTTP/1.0 or HTTP/1.1
    let version = match version_str {
        "HTTP/1.1" => HttpVersion::Http11,
        "HTTP/1.0" => HttpVersion::Http10,
        other => return Err(HttpParseError::UnsupportedVersion(other.to_string())),
    };

    // Authority parsing: host:port, [::1]:port
    let target = authority
        .parse::<TargetAddr>()
        .map_err(|e| HttpParseError::InvalidAuthority(e.to_string()))?;

    // Disallow unroutable port 0
    if target.port == 0 {
        return Err(HttpParseError::InvalidAuthority(
            "port 0 is not permitted".to_string(),
        ));
    }

    Ok(HttpConnectRequest {
        target,
        version,
        pipelined_payload,
    })
}

/// Reads an HTTP CONNECT request from an async stream up to the 8 KB header limit.
///
/// Accepts an optional `initial_buffer` prefix for interoperability with protocol sniffers.
pub async fn read_http_connect_request<R: AsyncRead + Unpin>(
    stream: &mut R,
    initial_buffer: Option<&[u8]>,
) -> Result<HttpConnectRequest, HttpParseError> {
    let mut buf = Vec::with_capacity(1024);
    if let Some(init) = initial_buffer {
        if !init.is_empty() {
            buf.extend_from_slice(init);
        }
    }

    let mut chunk = [0u8; 1024];

    loop {
        // If delimiter is present, parse immediately
        if let Some((pos, _)) = find_header_delimiter(&buf) {
            if pos > MAX_HEADER_SIZE {
                return Err(HttpParseError::HeaderTooLarge);
            }
            return parse_http_connect_request(&buf);
        }

        // Check if header buffer has exceeded limit without delimiter
        if buf.len() >= MAX_HEADER_SIZE {
            return Err(HttpParseError::HeaderTooLarge);
        }

        // Bounded read: never allow buffer to grow past MAX_HEADER_SIZE while searching for delimiter
        let max_to_read = (MAX_HEADER_SIZE - buf.len()).min(chunk.len());
        let n = stream
            .read(&mut chunk[..max_to_read])
            .await
            .map_err(|_| HttpParseError::PrematureEof)?;

        if n == 0 {
            if buf.is_empty() {
                return Err(HttpParseError::ZeroByteProbe);
            }
            return Err(HttpParseError::PrematureEof);
        }

        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Handshake and parse helper for listener integration.
/// Automatically transmits HTTP error response (400, 405, 431) before returning error.
pub async fn handshake_and_parse<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<HttpConnectRequest, HttpParseError> {
    match read_http_connect_request(stream, None).await {
        Ok(req) => Ok(req),
        Err(e) => {
            if let Some(resp) = e.response_bytes() {
                let _ = stream.write_all(resp).await;
                let _ = stream.flush().await;
            }
            Err(e)
        }
    }
}

/// Transmits `HTTP/1.1 200 Connection Established\r\n\r\n` (39 bytes).
pub async fn send_success_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<(), std::io::Error> {
    stream.write_all(RESPONSE_200).await?;
    stream.flush().await?;
    Ok(())
}

/// Transmits `HTTP/1.1 403 Forbidden\r\n\r\n` when a connection is rejected by rules.
pub async fn send_rule_rejected_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<(), std::io::Error> {
    stream.write_all(RESPONSE_403).await?;
    stream.flush().await?;
    Ok(())
}

/// Transmits an error HTTP response mapped from `std::io::Error`.
pub async fn send_error_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    err: &std::io::Error,
) -> Result<(), std::io::Error> {
    let resp = if err.kind() == std::io::ErrorKind::TimedOut {
        RESPONSE_504
    } else {
        RESPONSE_502
    };
    stream.write_all(resp).await?;
    stream.flush().await?;
    Ok(())
}

/// Handles an incoming HTTP client connection:
/// 1. Reads and parses HTTP CONNECT request within `handshake_timeout`.
/// 2. Replies with 400, 405, 431 on errors.
/// 3. Dials target via DIRECT outbound within `connect_timeout`.
/// 4. Replies with 502/504 on dial failure.
/// 5. Replies with `HTTP/1.1 200 Connection Established\r\n\r\n` on success.
/// 6. Hands off connection and pipelined payload to bidirectional half-close copy loop.
pub async fn handle_http_connection(
    mut client: TcpStream,
    initial_buffer: Option<&[u8]>,
    handshake_timeout: Duration,
    connect_timeout: Duration,
    idle_timeout: Duration,
) -> Result<(), std::io::Error> {
    // 1. Handshake Phase
    let handshake_res = tokio::time::timeout(
        handshake_timeout,
        read_http_connect_request(&mut client, initial_buffer),
    )
    .await;

    let request = match handshake_res {
        Ok(Ok(req)) => req,
        Ok(Err(err)) => match err {
            HttpParseError::ZeroByteProbe => {
                tracing::debug!("client disconnected with clean zero-byte probe");
                return Ok(());
            }
            HttpParseError::PrematureEof => {
                tracing::debug!("client disconnected prematurely during handshake");
                return Ok(());
            }
            other => {
                tracing::warn!(error = %other, "invalid HTTP CONNECT request");
                if let Some(resp) = other.response_bytes() {
                    let _ = client.write_all(resp).await;
                    let _ = client.shutdown().await;
                }
                return Ok(());
            }
        },
        Err(_) => {
            tracing::warn!("HTTP CONNECT handshake timed out");
            let _ = client.write_all(RESPONSE_504).await;
            let _ = client.shutdown().await;
            return Ok(());
        }
    };

    // Strict zero-payload privacy constraint: log host:port only
    tracing::info!(target = %request.target, "http connect tunnel requested");

    // 2. Outbound DIRECT Dial Phase
    let remote = match dial_direct(&request.target, connect_timeout).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(target = %request.target, error = %e, "outbound dial failed");
            let resp = if e.kind() == std::io::ErrorKind::TimedOut {
                RESPONSE_504
            } else {
                RESPONSE_502
            };
            let _ = client.write_all(resp).await;
            let _ = client.shutdown().await;
            return Ok(());
        }
    };

    // 3. Success Response Phase
    client.write_all(RESPONSE_200).await?;
    client.flush().await?;

    // 4. Bidirectional Tunneling with Pipelined Payload Preservation
    let initial_outbound = request.initial_data();

    match copy_bidirectional_with_idle_timeout(client, remote, idle_timeout, initial_outbound).await
    {
        Ok(stats) => {
            tracing::info!(
                target = %request.target,
                client_to_remote = stats.client_to_remote,
                remote_to_client = stats.remote_to_client,
                "http tunnel completed"
            );
            Ok(())
        }
        Err(e) => {
            tracing::debug!(target = %request.target, error = %e, "http tunnel terminated");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use yachiyo_core::address::TargetHost;

    fn run_async<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn test_parse_valid_domain_http11() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let parsed = parse_http_connect_request(req).unwrap();
        assert_eq!(parsed.target.host, TargetHost::Domain("example.com".into()));
        assert_eq!(parsed.target.port, 443);
        assert_eq!(parsed.version, HttpVersion::Http11);
        assert!(parsed.pipelined_payload.is_empty());
    }

    #[test]
    fn test_parse_valid_http10() {
        let req = b"CONNECT 127.0.0.1:8080 HTTP/1.0\r\n\r\n";
        let parsed = parse_http_connect_request(req).unwrap();
        assert_eq!(
            parsed.target.host,
            TargetHost::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        assert_eq!(parsed.target.port, 8080);
        assert_eq!(parsed.version, HttpVersion::Http10);
    }

    #[test]
    fn test_parse_valid_ipv6_bracket() {
        let req = b"CONNECT [::1]:8443 HTTP/1.1\r\n\r\n";
        let parsed = parse_http_connect_request(req).unwrap();
        assert_eq!(
            parsed.target.host,
            TargetHost::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(parsed.target.port, 8443);
    }

    #[test]
    fn test_parse_valid_ipv6_complex_bracket() {
        let req = b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n";
        let parsed = parse_http_connect_request(req).unwrap();
        assert_eq!(parsed.target.port, 443);
        match parsed.target.host {
            TargetHost::Ip(IpAddr::V6(v6)) => {
                assert_eq!(v6, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
            }
            _ => panic!("expected IPv6"),
        }
    }

    #[test]
    fn test_reject_non_connect_method_get() {
        let req = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let err = parse_http_connect_request(req).unwrap_err();
        assert_eq!(err, HttpParseError::MethodNotAllowed("GET".into()));
        assert_eq!(err.response_bytes(), Some(RESPONSE_405));
    }

    #[test]
    fn test_reject_non_connect_method_post() {
        let req = b"POST /api HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let err = parse_http_connect_request(req).unwrap_err();
        assert_eq!(err, HttpParseError::MethodNotAllowed("POST".into()));
        assert_eq!(err.response_bytes(), Some(RESPONSE_405));
    }

    #[test]
    fn test_reject_missing_port() {
        let req = b"CONNECT example.com HTTP/1.1\r\n\r\n";
        let err = parse_http_connect_request(req).unwrap_err();
        assert!(matches!(err, HttpParseError::InvalidAuthority(_)));
        assert_eq!(err.response_bytes(), Some(RESPONSE_400));
    }

    #[test]
    fn test_reject_unbracketed_ipv6() {
        let req = b"CONNECT 2001:db8::1:443 HTTP/1.1\r\n\r\n";
        let err = parse_http_connect_request(req).unwrap_err();
        assert!(matches!(err, HttpParseError::InvalidAuthority(_)));
        assert_eq!(err.response_bytes(), Some(RESPONSE_400));
    }

    #[test]
    fn test_reject_port_zero() {
        let req = b"CONNECT example.com:0 HTTP/1.1\r\n\r\n";
        let err = parse_http_connect_request(req).unwrap_err();
        assert_eq!(
            err,
            HttpParseError::InvalidAuthority("port 0 is not permitted".into())
        );
        assert_eq!(err.response_bytes(), Some(RESPONSE_400));
    }

    #[test]
    fn test_reject_invalid_port_non_numeric() {
        let req = b"CONNECT example.com:xyz HTTP/1.1\r\n\r\n";
        let err = parse_http_connect_request(req).unwrap_err();
        assert!(matches!(err, HttpParseError::InvalidAuthority(_)));
        assert_eq!(err.response_bytes(), Some(RESPONSE_400));
    }

    #[test]
    fn test_reject_unsupported_http_version() {
        let req = b"CONNECT example.com:443 HTTP/2.0\r\n\r\n";
        let err = parse_http_connect_request(req).unwrap_err();
        assert_eq!(err, HttpParseError::UnsupportedVersion("HTTP/2.0".into()));
        assert_eq!(err.response_bytes(), Some(RESPONSE_400));
    }

    #[test]
    fn test_pipelined_payload_preservation() {
        let mut raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec();
        let payload = b"\x16\x03\x01\x00\xfa\x01\x00\x00\xf6\x03\x03";
        raw.extend_from_slice(payload);

        let parsed = parse_http_connect_request(&raw).unwrap();
        assert_eq!(parsed.target.host, TargetHost::Domain("example.com".into()));
        assert_eq!(parsed.pipelined_payload, payload);
        assert_eq!(parsed.initial_data(), Some(&payload[..]));
    }

    #[test]
    fn test_bare_lf_delimiter() {
        let req = b"CONNECT example.com:443 HTTP/1.1\n\n";
        let parsed = parse_http_connect_request(req).unwrap();
        assert_eq!(parsed.target.port, 443);
    }

    #[test]
    fn test_header_size_limit_rejection() {
        let mut large_req = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        large_req.extend(vec![b'X'; 8200]);
        let err = parse_http_connect_request(&large_req).unwrap_err();
        assert_eq!(err, HttpParseError::HeaderTooLarge);
        assert_eq!(err.response_bytes(), Some(RESPONSE_431));
    }

    #[test]
    fn test_async_read_chunked_streaming() {
        run_async(async {
            let (mut client, mut server) = tokio::io::duplex(1024);

            tokio::spawn(async move {
                client.write_all(b"CONNECT ").await.unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
                client
                    .write_all(b"example.com:443 HTTP/1.1\r\n")
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
                client
                    .write_all(b"Host: example.com:443\r\n\r\n")
                    .await
                    .unwrap();
                client.write_all(b"PIPELINED_DATA").await.unwrap();
            });

            let req = read_http_connect_request(&mut server, None).await.unwrap();
            assert_eq!(req.target.host, TargetHost::Domain("example.com".into()));
            assert_eq!(req.target.port, 443);
            assert_eq!(req.pipelined_payload, b"PIPELINED_DATA");
        });
    }

    #[test]
    fn test_async_read_zero_byte_probe() {
        run_async(async {
            let (client, mut server) = tokio::io::duplex(1024);
            drop(client); // Immediately close socket
            let err = read_http_connect_request(&mut server, None)
                .await
                .unwrap_err();
            assert_eq!(err, HttpParseError::ZeroByteProbe);
            assert_eq!(err.response_bytes(), None);
        });
    }

    #[test]
    fn test_handshake_and_parse_auto_reply_on_error() {
        run_async(async {
            let (mut client, mut server) = tokio::io::duplex(1024);

            let client_task = tokio::spawn(async move {
                client
                    .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    .await
                    .unwrap();
                let mut resp = [0u8; RESPONSE_405.len()];
                client.read_exact(&mut resp).await.unwrap();
                assert_eq!(&resp, RESPONSE_405);
            });

            let err = handshake_and_parse(&mut server).await.unwrap_err();
            assert_eq!(err, HttpParseError::MethodNotAllowed("GET".into()));
            client_task.await.unwrap();
        });
    }
}
