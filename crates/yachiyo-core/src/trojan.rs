// SPDX-License-Identifier: AGPL-3.0-only

//! Trojan protocol TCP outbound support with pure Rust SHA-224 credential hashing,
//! standard binary framing, TLS transport, and credential redaction.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};

use crate::address::{TargetAddr, TargetHost};
use crate::forward::OutboundStream;
use crate::outbound::DirectDialer;

// ============================================================================
// 1. Pure Rust SHA-224 (FIPS PUB 180-4 standard)
// ============================================================================

const SHA224_H0: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = small_sigma0(w[i - 15]);
        let s1 = small_sigma1(w[i - 2]);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Computes the 28-byte raw SHA-224 digest of the given data per FIPS PUB 180-4.
pub fn sha224_digest(data: &[u8]) -> [u8; 28] {
    let mut state = SHA224_H0;
    let total_len = data.len();
    let bit_len = (total_len as u64).wrapping_mul(8);

    let mut chunks = data.chunks_exact(64);
    for chunk in &mut chunks {
        let block: &[u8; 64] = chunk.try_into().expect("chunks_exact yields 64 bytes");
        compress_block(&mut state, block);
    }

    let remainder = chunks.remainder();
    let rem_len = remainder.len();

    let mut tail = [0u8; 128];
    tail[..rem_len].copy_from_slice(remainder);
    tail[rem_len] = 0x80;

    let pad_blocks = if rem_len < 56 {
        tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
        1
    } else {
        tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
        2
    };

    for block in tail[..pad_blocks * 64].chunks_exact(64) {
        let b: &[u8; 64] = block.try_into().expect("chunks_exact yields 64 bytes");
        compress_block(&mut state, b);
    }

    let mut out = [0u8; 28];
    for i in 0..7 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Computes SHA-224 and returns the lowercase hexadecimal string as a 56-byte ASCII array.
pub fn sha224_hex_bytes(data: &[u8]) -> [u8; 56] {
    let digest = sha224_digest(data);
    let mut hex = [0u8; 56];
    for (i, &byte) in digest.iter().enumerate() {
        hex[i * 2] = HEX_CHARS[(byte >> 4) as usize];
        hex[i * 2 + 1] = HEX_CHARS[(byte & 0x0f) as usize];
    }
    hex
}

/// Computes SHA-224 and returns the lowercase hexadecimal string as a [`String`].
pub fn sha224_hex(data: &[u8]) -> String {
    let hex = sha224_hex_bytes(data);
    // Safety: hex contains only ASCII lowercase characters '0'..='9' and 'a'..='f'.
    std::str::from_utf8(&hex)
        .expect("hex characters are valid UTF-8")
        .to_string()
}

// ============================================================================
// 2. Trojan Request Header Framing
// ============================================================================

/// Encodes the standard Trojan binary request packet header according to the Trojan protocol:
///
/// `[56-byte ASCII SHA-224 hex] \r\n [0x01] [ATYP] [DST.ADDR] [DST.PORT] \r\n [Initial Data]`
///
/// - `ATYP 0x01`: IPv4 address (4 bytes)
/// - `ATYP 0x03`: Domain name (1-byte length prefix + domain ASCII bytes)
/// - `ATYP 0x04`: IPv6 address (16 bytes)
/// - `DST.PORT`: 2 bytes in big-endian network byte order
pub fn encode_trojan_header(
    sha224_hex: &[u8; 56],
    target: &TargetAddr,
    initial_payload: Option<&[u8]>,
) -> Result<Vec<u8>, std::io::Error> {
    let payload_len = initial_payload.map_or(0, |p| p.len());
    let mut buf = Vec::with_capacity(128 + payload_len);

    // 1. 56-byte hex hash + CRLF
    buf.extend_from_slice(sha224_hex);
    buf.extend_from_slice(b"\r\n");

    // 2. CMD = 0x01 (CONNECT)
    buf.push(0x01);

    // 3. ATYP + DST.ADDR
    match &target.host {
        TargetHost::Ip(std::net::IpAddr::V4(v4)) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.octets());
        }
        TargetHost::Ip(std::net::IpAddr::V6(v6)) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.octets());
        }
        TargetHost::Domain(domain) => {
            if domain.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Trojan domain length cannot exceed 255 bytes (got {})",
                        domain.len()
                    ),
                ));
            }
            buf.push(0x03);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        }
    }

    // 4. DST.PORT (2 bytes, big-endian)
    buf.extend_from_slice(&target.port.to_be_bytes());

    // 5. CRLF delimiter
    buf.extend_from_slice(b"\r\n");

    // 6. Optional initial payload
    if let Some(payload) = initial_payload {
        buf.extend_from_slice(payload);
    }

    Ok(buf)
}

// ============================================================================
// 3. TLS Transport Configuration & Custom Verifier
// ============================================================================

/// Insecure certificate verifier for `skip_cert_verify: true`.
#[derive(Debug)]
pub struct SkipServerVerification {
    provider: Arc<CryptoProvider>,
}

impl SkipServerVerification {
    /// Creates a new verifier with the given crypto provider.
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Maximum permitted size for a custom CA certificate bundle file (2 MiB).
pub const MAX_CA_CERT_FILE_BYTES: u64 = 2 * 1024 * 1024;

fn decode_base64_clean(input: &str) -> Result<Vec<u8>, std::io::Error> {
    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();

    if cleaned.is_empty() || cleaned.len() % 4 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid base64 length in PEM certificate",
        ));
    }

    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity((cleaned.len() / 4) * 3);
    let chunks = cleaned.chunks_exact(4);
    let total_chunks = chunks.len();

    for (idx, chunk) in chunks.enumerate() {
        let is_last = idx + 1 == total_chunks;
        let pad = if chunk[3] == b'=' {
            if !is_last {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected base64 padding before final quantum",
                ));
            }
            if chunk[2] == b'=' { 2 } else { 1 }
        } else {
            0
        };

        if chunk[0] == b'=' || chunk[1] == b'=' || (pad == 0 && chunk[2] == b'=') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed base64 padding in PEM certificate",
            ));
        }

        let b0 = val(chunk[0]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid base64 character in PEM certificate",
            )
        })?;
        let b1 = val(chunk[1]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid base64 character in PEM certificate",
            )
        })?;

        out.push((b0 << 2) | (b1 >> 4));

        if pad < 2 {
            let b2 = val(chunk[2]).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid base64 character in PEM certificate",
                )
            })?;
            out.push((b1 << 4) | (b2 >> 2));

            if pad == 0 {
                let b3 = val(chunk[3]).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid base64 character in PEM certificate",
                    )
                })?;
                out.push((b2 << 6) | b3);
            }
        }
    }

    Ok(out)
}

/// Parses one or more X.509 certificates from PEM (`CERTIFICATE` blocks) or raw ASN.1 DER bytes.
pub fn load_ca_certs_from_bytes(
    data: &[u8],
) -> Result<Vec<CertificateDer<'static>>, std::io::Error> {
    if data.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CA certificate data cannot be empty",
        ));
    }

    if let Ok(text) = std::str::from_utf8(data) {
        const BEGIN_MARKER: &str = "-----BEGIN CERTIFICATE-----";
        const END_MARKER: &str = "-----END CERTIFICATE-----";

        if text.contains(BEGIN_MARKER) {
            let mut certs = Vec::new();
            let mut rest = text;
            while let Some(start) = rest.find(BEGIN_MARKER) {
                let after_begin = &rest[start + BEGIN_MARKER.len()..];
                let end = after_begin.find(END_MARKER).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unclosed PEM CERTIFICATE block",
                    )
                })?;
                let body = &after_begin[..end];
                let der = decode_base64_clean(body)?;
                if der.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "empty DER payload in PEM CERTIFICATE block",
                    ));
                }
                certs.push(CertificateDer::from(der));
                rest = &after_begin[end + END_MARKER.len()..];
            }
            if certs.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "no valid PEM CERTIFICATE blocks found",
                ));
            }
            return Ok(certs);
        }
    }

    // Raw ASN.1 DER X.509 Certificate starts with SEQUENCE tag 0x30
    if data[0] == 0x30 && data.len() >= 4 {
        return Ok(vec![CertificateDer::from(data.to_vec())]);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "unrecognized CA certificate format (expected PEM CERTIFICATE or ASN.1 DER)",
    ))
}

/// Reads and parses X.509 CA certificates from a PEM or DER file on disk.
pub fn load_ca_certs_from_file(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, std::io::Error> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_CA_CERT_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "CA certificate file '{}' exceeds {} byte limit",
                path.display(),
                MAX_CA_CERT_FILE_BYTES
            ),
        ));
    }
    let raw = std::fs::read(path)?;
    load_ca_certs_from_bytes(&raw)
}

/// Constructs a cached `rustls::ClientConfig` using `ring` crypto provider and WebPKI roots.
pub fn build_tls_client_config(
    alpn: &[String],
    skip_cert_verify: bool,
) -> Result<Arc<rustls::ClientConfig>, std::io::Error> {
    build_tls_client_config_with_ca(alpn, skip_cert_verify, &[])
}

/// Constructs a cached `rustls::ClientConfig` using `ring` crypto provider, WebPKI roots,
/// and any additional custom X.509 CA certificates.
pub fn build_tls_client_config_with_ca(
    alpn: &[String],
    skip_cert_verify: bool,
    custom_ca_certs: &[CertificateDer<'static>],
) -> Result<Arc<rustls::ClientConfig>, std::io::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

    let mut root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in custom_ca_certs {
        root_store.add(cert.clone()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid CA certificate: {e}"),
            )
        })?;
    }

    let mut config = if skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new(provider)))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    if !alpn.is_empty() {
        config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }

    Ok(Arc::new(config))
}

// ============================================================================
// 4. Trojan Outbound Configuration & Dialer
// ============================================================================

/// Configuration for a Trojan outbound node.
#[derive(Clone)]
pub struct TrojanOutboundConfig {
    /// Upstream Trojan server target address (`host:port`).
    pub server: TargetAddr,
    /// Plaintext password (redacted in `Debug` output).
    pub password: String,
    /// Precomputed 56-byte lowercase hexadecimal SHA-224 hash of `password`.
    pub sha224_hex: [u8; 56],
    /// Optional TLS SNI override.
    pub sni: Option<String>,
    /// Configured ALPN protocols (e.g. `["h2", "http/1.1"]`).
    pub alpn: Vec<String>,
    /// Optional path to custom CA certificate bundle (PEM or DER).
    pub ca_cert: Option<PathBuf>,
    /// Whether to skip TLS certificate verification.
    pub skip_cert_verify: bool,
    /// Cached TLS client configuration.
    pub tls_config: Arc<rustls::ClientConfig>,
}

impl fmt::Debug for TrojanOutboundConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanOutboundConfig")
            .field("server", &self.server)
            .field("password", &"[REDACTED]")
            .field("sha224_hex", &"[REDACTED]")
            .field("sni", &self.sni)
            .field("alpn", &self.alpn)
            .field("ca_cert", &self.ca_cert)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .finish()
    }
}

impl PartialEq for TrojanOutboundConfig {
    fn eq(&self, other: &Self) -> bool {
        self.server == other.server
            && self.password == other.password
            && self.sha224_hex == other.sha224_hex
            && self.sni == other.sni
            && self.alpn == other.alpn
            && self.ca_cert == other.ca_cert
            && self.skip_cert_verify == other.skip_cert_verify
    }
}
impl Eq for TrojanOutboundConfig {}

/// Asynchronous outbound dialer establishing Trojan protocol tunnels over TLS.
pub struct TrojanDialer;

impl TrojanDialer {
    /// Dials the upstream Trojan server, completes the TLS handshake, transmits the
    /// initial Trojan request header (+ optional initial data), and returns the open stream.
    pub async fn dial(
        cfg: &TrojanOutboundConfig,
        target: &TargetAddr,
        connect_timeout: Duration,
        initial_data: Option<&[u8]>,
    ) -> Result<OutboundStream, std::io::Error> {
        let deadline = Instant::now() + connect_timeout;

        // 1. Resolve ServerName (custom SNI > domain fallback > IP fallback)
        let server_name = match &cfg.sni {
            Some(sni) => ServerName::try_from(sni.clone()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid SNI '{sni}': {e}"),
                )
            })?,
            None => match &cfg.server.host {
                TargetHost::Domain(domain) => {
                    ServerName::try_from(domain.clone()).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid server domain '{domain}': {e}"),
                        )
                    })?
                }
                TargetHost::Ip(ip) => ServerName::IpAddress((*ip).into()),
            },
        };

        // 2. TCP connect via DirectDialer with remaining budget
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect timeout exceeded before dialing {}", cfg.server),
            ));
        }
        let tcp_stream = DirectDialer::new(remaining).dial(&cfg.server).await?;

        // 3. TLS Handshake
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "connect timeout exceeded before TLS handshake to {}",
                    cfg.server
                ),
            ));
        }
        let connector = TlsConnector::from(Arc::clone(&cfg.tls_config));
        let mut tls_stream =
            tokio::time::timeout_at(deadline, connector.connect(server_name, tcp_stream))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "TLS handshake to {} timed out after {:?}",
                            cfg.server, connect_timeout
                        ),
                    )
                })?
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("TLS handshake to {} failed: {e}", cfg.server),
                    )
                })?;

        // 4. Encode Trojan header [56-hex SHA224]\r\n[0x01][ATYP][DST.ADDR][DST.PORT]\r\n[Initial Data]
        let header = encode_trojan_header(&cfg.sha224_hex, target, initial_data)?;

        // 5. Send Trojan header with remaining budget
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout exceeded before sending Trojan header",
            ));
        }
        tokio::time::timeout_at(deadline, tls_stream.write_all(&header))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "sending Trojan header timed out",
                )
            })??;

        tls_stream.flush().await?;

        Ok(OutboundStream::Tls(Box::new(tls_stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha224_fips_vectors() {
        // NIST / FIPS 180-4 standard test vectors
        assert_eq!(
            sha224_hex(b""),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            sha224_hex(b"abc"),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
        assert_eq!(
            sha224_hex(b"The quick brown fox jumps over the lazy dog"),
            "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"
        );
        assert_eq!(
            sha224_hex(b"The quick brown fox jumps over the lazy cog"),
            "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b"
        );
        assert_eq!(
            sha224_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
        );
        assert_eq!(
            sha224_hex(b"password"),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert_eq!(
            sha224_hex(b"trojan-password"),
            "d165d6725fa3eeb91851912bf3a943f31680c21af8fed026cddc8955"
        );
    }

    #[test]
    fn test_encode_trojan_header_ipv4() {
        let hex = sha224_hex_bytes(b"password");
        let target: TargetAddr = "192.0.2.1:80".parse().unwrap();
        let header = encode_trojan_header(&hex, &target, None).unwrap();

        // 56 (hex) + 2 (\r\n) + 1 (cmd) + 1 (atyp) + 4 (ipv4) + 2 (port) + 2 (\r\n) = 68
        assert_eq!(header.len(), 68);
        assert_eq!(&header[..56], &hex);
        assert_eq!(&header[56..58], b"\r\n");
        assert_eq!(header[58], 0x01); // CMD = 0x01
        assert_eq!(header[59], 0x01); // ATYP = 0x01 (IPv4)
        assert_eq!(&header[60..64], &[192, 0, 2, 1]);
        assert_eq!(&header[64..66], &80u16.to_be_bytes());
        assert_eq!(&header[66..68], b"\r\n");
    }

    #[test]
    fn test_encode_trojan_header_domain_and_payload() {
        let hex = sha224_hex_bytes(b"secret");
        let target: TargetAddr = "example.com:443".parse().unwrap();
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let header = encode_trojan_header(&hex, &target, Some(payload)).unwrap();

        // 56 + 2 + 1 + 1 (atyp 0x03) + 1 (len 11) + 11 ("example.com") + 2 (443) + 2 (\r\n) + 18 (payload) = 94
        assert_eq!(header.len(), 94);
        assert_eq!(&header[58..60], &[0x01, 0x03]); // CMD=1, ATYP=3
        assert_eq!(header[60], 11); // Domain length
        assert_eq!(&header[61..72], b"example.com");
        assert_eq!(&header[72..74], &443u16.to_be_bytes());
        assert_eq!(&header[74..76], b"\r\n");
        assert_eq!(&header[76..], payload);
    }

    #[test]
    fn test_encode_trojan_header_ipv6() {
        let hex = sha224_hex_bytes(b"key");
        let target: TargetAddr = "[2001:db8::1]:8080".parse().unwrap();
        let header = encode_trojan_header(&hex, &target, None).unwrap();

        // 56 + 2 + 1 + 1 (atyp 0x04) + 16 (ipv6) + 2 (port) + 2 (\r\n) = 80
        assert_eq!(header.len(), 80);
        assert_eq!(&header[58..60], &[0x01, 0x04]);
        let ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(&header[60..76], &ip.octets());
        assert_eq!(&header[76..78], &8080u16.to_be_bytes());
        assert_eq!(&header[78..80], b"\r\n");
    }

    #[test]
    fn test_encode_trojan_header_domain_overflow() {
        let hex = sha224_hex_bytes(b"key");
        let target = TargetAddr {
            host: TargetHost::Domain("a".repeat(256)),
            port: 443,
        };
        let err = encode_trojan_header(&hex, &target, None).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_credential_redaction_debug() {
        let tls_config = build_tls_client_config(&["h2".to_string()], true).unwrap();
        let cfg = TrojanOutboundConfig {
            server: "192.0.2.1:443".parse().unwrap(),
            password: "super_secret_password".to_string(),
            sha224_hex: sha224_hex_bytes(b"super_secret_password"),
            sni: Some("trojan.example.com".to_string()),
            alpn: vec!["h2".to_string()],
            ca_cert: None,
            skip_cert_verify: true,
            tls_config,
        };

        let debug_str = format!("{cfg:?}");
        assert!(!debug_str.contains("super_secret_password"));
        let hex_str = sha224_hex(b"super_secret_password");
        assert!(!debug_str.contains(&hex_str));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_ca_cert_loader_pem_der_and_invalid_inputs() {
        // Empty input rejected
        assert!(load_ca_certs_from_bytes(b"").is_err());
        // Unclosed PEM rejected
        assert!(load_ca_certs_from_bytes(b"-----BEGIN CERTIFICATE-----\nAAAA").is_err());
        // Malformed base64 rejected
        assert!(
            load_ca_certs_from_bytes(
                b"-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"
            )
            .is_err()
        );

        // Valid base64 inside PEM parses to exact DER bytes (0x30, 0x03, 0x02, 0x01, 0x00 -> MAMCAQA=)
        let pem = b"-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n";
        let certs = load_ca_certs_from_bytes(pem).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].as_ref(), &[0x30, 0x03, 0x02, 0x01, 0x00]);

        // Raw DER starts with 0x30, parses as 1 cert, but fails X.509 validation in RootCertStore
        let der = [0x30, 0x03, 0x02, 0x01, 0x00];
        let der_certs = load_ca_certs_from_bytes(&der).unwrap();
        assert_eq!(der_certs.len(), 1);
        let err = build_tls_client_config_with_ca(&[], false, &der_certs).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
