// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol client utilities for SOCKS5 and HTTP CONNECT testing.
//!
//! Provides both high-level happy-path helpers and low-level raw frame crafting
//! for boundary and error-path verification.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SOCKS5 constants per RFC 1928.
pub mod socks5_constants {
    pub const VERSION: u8 = 0x05;
    pub const METHOD_NO_AUTH: u8 = 0x00;
    pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

    pub const CMD_CONNECT: u8 = 0x01;
    pub const CMD_BIND: u8 = 0x02;
    pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;

    pub const REP_SUCCESS: u8 = 0x00;
    pub const REP_GENERAL_FAILURE: u8 = 0x01;
    pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
    pub const REP_HOST_UNREACHABLE: u8 = 0x04;
    pub const REP_CONNECTION_REFUSED: u8 = 0x05;
    pub const REP_TTL_EXPIRED: u8 = 0x06;
    pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// Target destination specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetDestination {
    Ipv4(std::net::Ipv4Addr, u16),
    Ipv6(std::net::Ipv6Addr, u16),
    Domain(String, u16),
}

impl TargetDestination {
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => TargetDestination::Ipv4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => TargetDestination::Ipv6(*v6.ip(), v6.port()),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetDestination::Ipv4(_, p) => *p,
            TargetDestination::Ipv6(_, p) => *p,
            TargetDestination::Domain(_, p) => *p,
        }
    }

    pub fn to_http_authority(&self) -> String {
        match self {
            TargetDestination::Ipv4(ip, port) => format!("{}:{}", ip, port),
            TargetDestination::Ipv6(ip, port) => format!("[{}]:{}", ip, port),
            TargetDestination::Domain(dom, port) => format!("{}:{}", dom, port),
        }
    }
}

/// SOCKS5 connection reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Reply {
    pub ver: u8,
    pub rep: u8,
    pub rsv: u8,
    pub atyp: u8,
    pub bnd_addr: Vec<u8>,
    pub bnd_port: u16,
}

/// High-level SOCKS5 client connector.
pub async fn socks5_connect(
    proxy_addr: SocketAddr,
    target: &TargetDestination,
    timeout: Duration,
) -> Result<TcpStream, String> {
    tokio::time::timeout(timeout, async move {
        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .map_err(|e| format!("Failed to connect to proxy {}: {}", proxy_addr, e))?;

        // 1. Send auth negotiation: [VER=5, NMETHODS=1, METHOD=0x00]
        stream
            .write_all(&[
                socks5_constants::VERSION,
                0x01,
                socks5_constants::METHOD_NO_AUTH,
            ])
            .await
            .map_err(|e| format!("Write auth handshake failed: {}", e))?;

        let mut auth_resp = [0u8; 2];
        stream
            .read_exact(&mut auth_resp)
            .await
            .map_err(|e| format!("Read auth response failed: {}", e))?;

        if auth_resp[0] != socks5_constants::VERSION {
            return Err(format!(
                "Invalid SOCKS version in auth reply: {}",
                auth_resp[0]
            ));
        }
        if auth_resp[1] != socks5_constants::METHOD_NO_AUTH {
            return Err(format!(
                "SOCKS auth rejected: method 0x{:02x}",
                auth_resp[1]
            ));
        }

        // 2. Build CONNECT request
        let mut req = Vec::new();
        req.push(socks5_constants::VERSION);
        req.push(socks5_constants::CMD_CONNECT);
        req.push(0x00); // RSV

        match target {
            TargetDestination::Ipv4(ip, port) => {
                req.push(socks5_constants::ATYP_IPV4);
                req.extend_from_slice(&ip.octets());
                req.extend_from_slice(&port.to_be_bytes());
            }
            TargetDestination::Ipv6(ip, port) => {
                req.push(socks5_constants::ATYP_IPV6);
                req.extend_from_slice(&ip.octets());
                req.extend_from_slice(&port.to_be_bytes());
            }
            TargetDestination::Domain(domain, port) => {
                req.push(socks5_constants::ATYP_DOMAIN);
                let dom_bytes = domain.as_bytes();
                if dom_bytes.len() > 255 {
                    return Err("Domain length exceeds 255 bytes".to_string());
                }
                req.push(dom_bytes.len() as u8);
                req.extend_from_slice(dom_bytes);
                req.extend_from_slice(&port.to_be_bytes());
            }
        }

        stream
            .write_all(&req)
            .await
            .map_err(|e| format!("Write CONNECT request failed: {}", e))?;

        // 3. Read reply header
        let mut header = [0u8; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| format!("Read CONNECT reply header failed: {}", e))?;

        if header[0] != socks5_constants::VERSION {
            return Err(format!("Invalid SOCKS version in reply: {}", header[0]));
        }
        if header[1] != socks5_constants::REP_SUCCESS {
            return Err(format!(
                "SOCKS CONNECT failed with REP code 0x{:02x}",
                header[1]
            ));
        }

        // Read bound address based on ATYP
        let atyp = header[3];
        match atyp {
            socks5_constants::ATYP_IPV4 => {
                let mut bnd = [0u8; 6]; // 4 bytes IP + 2 bytes port
                stream
                    .read_exact(&mut bnd)
                    .await
                    .map_err(|e| format!("Read bnd addr failed: {}", e))?;
            }
            socks5_constants::ATYP_IPV6 => {
                let mut bnd = [0u8; 18]; // 16 bytes IP + 2 bytes port
                stream
                    .read_exact(&mut bnd)
                    .await
                    .map_err(|e| format!("Read bnd addr failed: {}", e))?;
            }
            socks5_constants::ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(|e| format!("Read bnd domain len failed: {}", e))?;
                let mut bnd = vec![0u8; len_buf[0] as usize + 2];
                stream
                    .read_exact(&mut bnd)
                    .await
                    .map_err(|e| format!("Read bnd domain failed: {}", e))?;
            }
            other => return Err(format!("Unknown ATYP in reply: 0x{:02x}", other)),
        }

        Ok(stream)
    })
    .await
    .map_err(|_| "SOCKS5 connect timed out".to_string())?
}

/// Raw SOCKS5 handshake sender for boundary / adversarial tests.
pub async fn socks5_handshake_raw(
    stream: &mut TcpStream,
    methods: &[u8],
) -> Result<[u8; 2], std::io::Error> {
    let mut buf = Vec::with_capacity(2 + methods.len());
    buf.push(socks5_constants::VERSION);
    buf.push(methods.len() as u8);
    buf.extend_from_slice(methods);
    stream.write_all(&buf).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

/// Raw SOCKS5 request sender for boundary tests (e.g. testing invalid CMD, ATYP, etc.).
pub async fn socks5_send_raw_request(
    stream: &mut TcpStream,
    ver: u8,
    cmd: u8,
    rsv: u8,
    atyp: u8,
    addr_payload: &[u8],
    port: u16,
) -> Result<Socks5Reply, std::io::Error> {
    let mut req = vec![ver, cmd, rsv, atyp];
    req.extend_from_slice(addr_payload);
    req.extend_from_slice(&port.to_be_bytes());

    stream.write_all(&req).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    let rep_atyp = header[3];
    let (bnd_addr, bnd_port) = match rep_atyp {
        socks5_constants::ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port_b = [0u8; 2];
            stream.read_exact(&mut port_b).await?;
            (addr.to_vec(), u16::from_be_bytes(port_b))
        }
        socks5_constants::ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port_b = [0u8; 2];
            stream.read_exact(&mut port_b).await?;
            (addr.to_vec(), u16::from_be_bytes(port_b))
        }
        socks5_constants::ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut dom = vec![0u8; len[0] as usize];
            stream.read_exact(&mut dom).await?;
            let mut port_b = [0u8; 2];
            stream.read_exact(&mut port_b).await?;
            (dom, u16::from_be_bytes(port_b))
        }
        _ => (Vec::new(), 0),
    };

    Ok(Socks5Reply {
        ver: header[0],
        rep: header[1],
        rsv: header[2],
        atyp: rep_atyp,
        bnd_addr,
        bnd_port,
    })
}

/// High-level HTTP CONNECT client connector.
pub async fn http_connect(
    proxy_addr: SocketAddr,
    target: &TargetDestination,
    timeout: Duration,
) -> Result<TcpStream, String> {
    tokio::time::timeout(timeout, async move {
        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .map_err(|e| format!("Failed to connect to HTTP proxy {}: {}", proxy_addr, e))?;

        let authority = target.to_http_authority();
        let request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: yachiyo-test/1.0\r\n\r\n",
            authority, authority
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("Write HTTP CONNECT failed: {}", e))?;

        let (status_code, _headers, _unconsumed) = read_http_response(&mut stream).await?;

        if status_code != 200 {
            return Err(format!(
                "HTTP CONNECT rejected with status code: {}",
                status_code
            ));
        }

        Ok(stream)
    })
    .await
    .map_err(|_| "HTTP connect timed out".to_string())?
}

/// HTTP CONNECT with pipelined payload.
///
/// Sends `CONNECT authority HTTP/1.1\r\n...\r\n\r\n<pipelined_payload>` in one single write call.
/// Then reads the 200 response header, and returns the stream ready for subsequent transfer.
pub async fn http_connect_with_pipeline(
    proxy_addr: SocketAddr,
    target: &TargetDestination,
    pipelined_payload: &[u8],
    timeout: Duration,
) -> Result<TcpStream, String> {
    tokio::time::timeout(timeout, async move {
        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .map_err(|e| format!("Failed to connect to proxy {}: {}", proxy_addr, e))?;

        let authority = target.to_http_authority();
        let mut request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            authority, authority
        )
        .into_bytes();

        request.extend_from_slice(pipelined_payload);

        // Single write containing both headers and pipelined body
        stream
            .write_all(&request)
            .await
            .map_err(|e| format!("Write HTTP pipelined request failed: {}", e))?;

        let (status_code, _headers, unconsumed) = read_http_response(&mut stream).await?;

        if status_code != 200 {
            return Err(format!("HTTP CONNECT rejected with status {}", status_code));
        }

        // unconsumed should be empty because we pipelined outbound data towards the target,
        // not data coming back from proxy itself before 200 OK.
        if !unconsumed.is_empty() {
            return Err(format!(
                "Unexpected trailing bytes from proxy: {} bytes",
                unconsumed.len()
            ));
        }

        Ok(stream)
    })
    .await
    .map_err(|_| "HTTP pipelined connect timed out".to_string())?
}

/// Raw HTTP response reader returning (status_code, raw_headers_string, unconsumed_buffer).
pub async fn read_http_response(stream: &mut TcpStream) -> Result<(u16, String, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("Read HTTP response failed: {}", e))?;
        if n == 0 {
            return Err("Unexpected EOF while reading HTTP response headers".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);

        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let header_bytes = &buf[..pos + 4];
            let unconsumed = buf[pos + 4..].to_vec();
            let header_str = String::from_utf8_lossy(header_bytes).to_string();

            let status_code = parse_status_code(&header_str)?;
            return Ok((status_code, header_str, unconsumed));
        }

        if buf.len() > 16384 {
            return Err("HTTP response headers exceeded 16KB limit".to_string());
        }
    }
}

fn parse_status_code(headers: &str) -> Result<u16, String> {
    let first_line = headers
        .lines()
        .next()
        .ok_or_else(|| "Empty HTTP response".to_string())?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("Malformed HTTP status line: {}", first_line));
    }
    parts[1]
        .parse::<u16>()
        .map_err(|e| format!("Invalid HTTP status code {}: {}", parts[1], e))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Helper to write payload and verify exact byte-for-byte echo response.
pub async fn verify_bidirectional_echo(
    mut stream: TcpStream,
    payload: &[u8],
) -> Result<(), String> {
    stream
        .write_all(payload)
        .await
        .map_err(|e| format!("Failed to write payload: {}", e))?;

    let mut response = vec![0u8; payload.len()];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| format!("Failed to read echo response: {}", e))?;

    if response != payload {
        return Err(format!(
            "Echo mismatch: sent {} bytes, received {} bytes",
            payload.len(),
            response.len()
        ));
    }

    Ok(())
}
