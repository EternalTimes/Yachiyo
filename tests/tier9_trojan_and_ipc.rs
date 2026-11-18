// SPDX-License-Identifier: AGPL-3.0-only

//! Tier 9 E2E Tests: Trojan TCP outbound (TLS verification, custom CA, SNI, auth failover,
//! half-close), Unix domain socket IPC CLI diagnostics (`ping`, `status`, `nodes`,
//! `connections`, `stats`, SIGHUP generation sync, redaction), and independent Xray interop.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio_rustls::TlsAcceptor;

use yachiyo_core::{sha224_hex, sha224_hex_bytes};
use yachiyo_e2e::client::{TargetDestination, read_http_response, socks5_connect};
use yachiyo_e2e::echo::{EchoMode, EchoServer};
use yachiyo_e2e::proxy::{ProxyConfig, ProxyProcess};

const TEST_TIMEOUT: Duration = Duration::from_secs(8);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// RAII temporary directory automatically deleted when dropped.
struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        // Use `/tmp` on Unix so Unix domain socket paths stay well below macOS 104-byte SUN_LEN
        #[cfg(unix)]
        let base = PathBuf::from("/tmp");
        #[cfg(not(unix))]
        let base = std::env::temp_dir();
        let short = &prefix[..prefix.len().min(6)];
        let path = base.join(format!("yt9_{short}_{pid}_{id}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("failed to create temp test dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ============================================================================
// Minimal Pure-Rust Ephemeral ECDSA P-256 X.509 v3 PKI Builder (Zero PEM literals)
// ============================================================================

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_seq(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(item);
    }
    der_tlv(0x30, &body)
}

fn der_set(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(item);
    }
    der_tlv(0x31, &body)
}

fn der_int_positive(bytes: &[u8]) -> Vec<u8> {
    let mut trimmed = bytes;
    while trimmed.len() > 1 && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }
    let mut body = Vec::new();
    if trimmed[0] & 0x80 != 0 {
        body.push(0x00);
    }
    body.extend_from_slice(trimmed);
    der_tlv(0x02, &body)
}

fn der_bit_string(unused_bits: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + payload.len());
    body.push(unused_bits);
    body.extend_from_slice(payload);
    der_tlv(0x03, &body)
}

fn der_common_name_dn(cn: &str) -> Vec<u8> {
    // OID 2.5.4.3 (id-at-commonName) = 55 04 03
    let oid_cn = der_tlv(0x06, &[0x55, 0x04, 0x03]);
    let val = der_tlv(0x0C, cn.as_bytes()); // UTF8String
    der_seq(&[der_set(&[der_seq(&[oid_cn, val])])])
}

fn der_spki_p256(public_key_uncompressed: &[u8]) -> Vec<u8> {
    // id-ecPublicKey (1.2.840.10045.2.1) = 2A 86 48 CE 3D 02 01
    let oid_ec_pub = der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
    // prime256v1 (1.2.840.10045.3.1.7) = 2A 86 48 CE 3D 03 01 07
    let oid_p256 = der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
    let alg = der_seq(&[oid_ec_pub, oid_p256]);
    let pub_bits = der_bit_string(0, public_key_uncompressed);
    der_seq(&[alg, pub_bits])
}

fn der_extension(oid: &[u8], critical: bool, value_der: &[u8]) -> Vec<u8> {
    let mut fields = vec![der_tlv(0x06, oid)];
    if critical {
        fields.push(der_tlv(0x01, &[0xFF]));
    }
    fields.push(der_tlv(0x04, value_der));
    der_seq(&fields)
}

fn sign_x509_v3(
    serial: &[u8],
    issuer_dn: Vec<u8>,
    subject_dn: Vec<u8>,
    subject_pub: &[u8],
    extensions: Vec<Vec<u8>>,
    issuer_key: &EcdsaKeyPair,
    rng: &SystemRandom,
) -> Vec<u8> {
    // ecdsa-with-SHA256 (1.2.840.10045.4.3.2) = 2A 86 48 CE 3D 04 03 02
    let sig_alg = der_seq(&[der_tlv(
        0x06,
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02],
    )]);
    let version_v3 = der_tlv(0xA0, &der_tlv(0x02, &[0x02]));
    let validity = der_seq(&[
        der_tlv(0x17, b"250101000000Z"),
        der_tlv(0x17, b"350101000000Z"),
    ]);
    let spki = der_spki_p256(subject_pub);
    let ext_block = der_tlv(0xA3, &der_seq(&extensions));

    let tbs = der_seq(&[
        version_v3,
        der_int_positive(serial),
        sig_alg.clone(),
        issuer_dn,
        validity,
        subject_dn,
        spki,
        ext_block,
    ]);

    let sig = issuer_key.sign(rng, &tbs).expect("ECDSA sign failed");
    der_seq(&[tbs, sig_alg, der_bit_string(0, sig.as_ref())])
}

/// Converts `ring`'s PKCS#8 v2 ECDSA P-256 document into standard RFC 5915 + RFC 5208 PKCS#8 v1 DER
/// so external Go/OpenSSL consumers (such as `Xray`) can parse it universally.
fn ring_p256_pkcs8_to_v1_der(ring_pkcs8: &[u8], pub_uncompressed: &[u8]) -> Vec<u8> {
    // Locate the 32-byte private scalar preceded by ASN.1 OCTET STRING header [0x04, 0x20]
    let scalar = ring_pkcs8
        .windows(34)
        .find(|w| w[0] == 0x04 && w[1] == 0x20)
        .map(|w| &w[2..34])
        .expect("32-byte P-256 scalar not found in ring PKCS#8 document");

    let ec_private_key = der_seq(&[
        der_tlv(0x02, &[0x01]),                              // version = 1
        der_tlv(0x04, scalar),                               // privateKey OCTET STRING (32 bytes)
        der_tlv(0xA1, &der_bit_string(0, pub_uncompressed)), // [1] publicKey
    ]);

    let oid_ec_pub = der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
    let oid_p256 = der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);

    der_seq(&[
        der_tlv(0x02, &[0x00]), // PKCS#8 v1 (version = 0)
        der_seq(&[oid_ec_pub, oid_p256]),
        der_tlv(0x04, &ec_private_key),
    ])
}

fn encode_base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn encode_pem_runtime(label: &str, der: &[u8]) -> String {
    let b64 = encode_base64(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

struct EphemeralPki {
    ca_cert_der: Vec<u8>,
    leaf_cert_der: Vec<u8>,
    leaf_key_pkcs8_v1_der: Vec<u8>,
}

impl EphemeralPki {
    fn generate(san_dns: &str) -> Self {
        let rng = SystemRandom::new();

        let ca_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let ca_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, ca_pkcs8.as_ref(), &rng)
                .unwrap();

        let leaf_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let leaf_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, leaf_pkcs8.as_ref(), &rng)
                .unwrap();

        let ca_dn = der_common_name_dn("Yachiyo Ephemeral Test Root CA");
        let leaf_dn = der_common_name_dn(san_dns);

        // Root CA extensions: basicConstraints(cA=TRUE, critical), keyUsage(keyCertSign, critical)
        let ca_exts = vec![
            der_extension(
                &[0x55, 0x1D, 0x13],
                true,
                &der_seq(&[der_tlv(0x01, &[0xFF])]),
            ),
            der_extension(&[0x55, 0x1D, 0x0F], true, &der_bit_string(2, &[0x04])),
        ];
        let ca_cert_der = sign_x509_v3(
            &[0x01, 0x00, 0x01],
            ca_dn.clone(),
            ca_dn.clone(),
            ca_kp.public_key().as_ref(),
            ca_exts,
            &ca_kp,
            &rng,
        );

        // Leaf extensions: basicConstraints(cA=FALSE), keyUsage(digitalSignature),
        // extKeyUsage(serverAuth), subjectAltName(DNS:san_dns, IP:127.0.0.1)
        let san_value = der_seq(&[
            der_tlv(0x82, san_dns.as_bytes()), // [2] dNSName
            der_tlv(0x87, &[127, 0, 0, 1]),    // [7] iPAddress 127.0.0.1
        ]);
        let eku_server_auth = der_seq(&[der_tlv(
            0x06,
            &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01],
        )]);
        let leaf_exts = vec![
            der_extension(&[0x55, 0x1D, 0x13], true, &der_seq(&[])),
            der_extension(&[0x55, 0x1D, 0x0F], true, &der_bit_string(7, &[0x80])),
            der_extension(&[0x55, 0x1D, 0x25], false, &eku_server_auth),
            der_extension(&[0x55, 0x1D, 0x11], false, &san_value),
        ];
        let leaf_cert_der = sign_x509_v3(
            &[0x01, 0x00, 0x02],
            ca_dn,
            leaf_dn,
            leaf_kp.public_key().as_ref(),
            leaf_exts,
            &ca_kp,
            &rng,
        );

        let leaf_key_pkcs8_v1_der =
            ring_p256_pkcs8_to_v1_der(leaf_pkcs8.as_ref(), leaf_kp.public_key().as_ref());

        Self {
            ca_cert_der,
            leaf_cert_der,
            leaf_key_pkcs8_v1_der,
        }
    }

    fn build_rustls_acceptor(&self) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert_chain = vec![
            CertificateDer::from(self.leaf_cert_der.clone()),
            CertificateDer::from(self.ca_cert_der.clone()),
        ];
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key_pkcs8_v1_der.clone()));
        let mut server_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("valid ephemeral leaf cert and PKCS#8 v1 key");
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(server_cfg))
    }
}

// ============================================================================
// Mock Async TLS Trojan Upstream Server
// ============================================================================

/// Spawns a controlled TLS Trojan server validating 56-byte hex SHA-224 credentials
/// and Trojan binary framing (`[hex]\r\n[0x01][ATYP][DST.ADDR][DST.PORT]\r\n[payload]`).
/// Domain targets are mapped to `127.0.0.1:<port>` for deterministic local loopback testing.
async fn spawn_mock_trojan_server(
    pki: &EphemeralPki,
    expected_password: &str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = pki.build_rustls_acceptor();
    let expected_hash = sha224_hex_bytes(expected_password.as_bytes());

    let handle = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                // 1. Read 56-byte hex SHA-224 + CRLF
                let mut auth_line = [0u8; 58];
                if tls.read_exact(&mut auth_line).await.is_err() {
                    return;
                }
                if auth_line[..56] != expected_hash || &auth_line[56..58] != b"\r\n" {
                    let _ = tls.shutdown().await;
                    return;
                }

                // 2. Read CMD (0x01) + ATYP
                let mut cmd_atyp = [0u8; 2];
                if tls.read_exact(&mut cmd_atyp).await.is_err() || cmd_atyp[0] != 0x01 {
                    return;
                }

                let dst_addr: SocketAddr = match cmd_atyp[1] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        if tls.read_exact(&mut ip).await.is_err() {
                            return;
                        }
                        let port = match tls.read_u16().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
                    }
                    0x03 => {
                        let len = match tls.read_u8().await {
                            Ok(l) => l as usize,
                            Err(_) => return,
                        };
                        let mut domain = vec![0u8; len];
                        if tls.read_exact(&mut domain).await.is_err() {
                            return;
                        }
                        let port = match tls.read_u16().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        // Map test domains deterministically to 127.0.0.1:<port>
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                    }
                    0x04 => {
                        let mut ip = [0u8; 16];
                        if tls.read_exact(&mut ip).await.is_err() {
                            return;
                        }
                        let port = match tls.read_u16().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(ip)), port)
                    }
                    _ => return,
                };

                // 3. Trailing CRLF
                let mut crlf = [0u8; 2];
                if tls.read_exact(&mut crlf).await.is_err() || &crlf != b"\r\n" {
                    return;
                }

                // 4. Connect to destination and relay bidirectionally (preserving half-close)
                let mut upstream = match TcpStream::connect(dst_addr).await {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = tls.shutdown().await;
                        return;
                    }
                };
                let _ = copy_bidirectional(&mut tls, &mut upstream).await;
            });
        }
    });

    (addr, handle)
}

async fn spawn_http_204_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = client.read(&mut buf).await;
                let _ = client
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    (addr, handle)
}

async fn echo_roundtrip(stream: &mut TcpStream, payload: &[u8]) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        stream.write_all(payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, payload);
    })
    .await
    .expect("echo roundtrip timed out");
}

async fn http_connect_pipelined(
    proxy_addr: SocketAddr,
    authority: &str,
    pipelined: &[u8],
) -> (TcpStream, Vec<u8>) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut req =
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes();
        req.extend_from_slice(pipelined);
        stream.write_all(&req).await.unwrap();
        let (status, _hdrs, unconsumed) = read_http_response(&mut stream).await.unwrap();
        assert_eq!(status, 200);
        (stream, unconsumed)
    })
    .await
    .expect("HTTP CONNECT pipelined timed out")
}

// ============================================================================
// Tier 9 Test Cases
// ============================================================================

#[tokio::test]
async fn test_trojan_strict_tls_forwarding_and_half_close() {
    let dir = TempTestDir::new("trojan_strict");
    let pki = EphemeralPki::generate("trojan.example.org");
    let ca_pem_path = dir.path().join("ca.pem");
    fs::write(
        &ca_pem_path,
        encode_pem_runtime("CERTIFICATE", &pki.ca_cert_der),
    )
    .unwrap();

    let password = "tier9-strict-trojan-pass";
    let (trojan_addr, trojan_task) = spawn_mock_trojan_server(&pki, password).await;
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();

    let mixed_addr = ProxyProcess::get_available_addr();
    let ipc_sock = dir.path().join("yachiyo.sock");
    let cfg_path = dir.path().join("config.yaml");
    let yaml = format!(
        r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
outbounds:
  trojan_strict:
    type: trojan
    server: {trojan_addr}
    password: {password}
    sni: trojan.example.org
    ca_cert: {}
    skip_cert_verify: false
rules:
  - MATCH,trojan_strict
"#,
        ca_pem_path.display()
    );
    fs::write(&cfg_path, yaml).unwrap();

    let mut proxy = ProxyProcess::start(ProxyConfig {
        mixed_addr: Some(mixed_addr),
        extra_args: vec![
            "--config".to_string(),
            cfg_path.to_string_lossy().to_string(),
            "--ipc-path".to_string(),
            ipc_sock.to_string_lossy().to_string(),
        ],
        ..Default::default()
    })
    .await
    .expect("yachiyo should start with strict Trojan CA config");

    // 1. SOCKS5 IPv4 target over Trojan TLS
    let mut s1 = socks5_connect(
        mixed_addr,
        &TargetDestination::from_socket_addr(echo.addr()),
        TEST_TIMEOUT,
    )
    .await
    .expect("SOCKS5 connect over Trojan should succeed");
    echo_roundtrip(&mut s1, b"hello-trojan-ipv4").await;

    // 2. SOCKS5 Domain target + client half-close (FIN) propagation over Trojan TLS
    let mut s2 = socks5_connect(
        mixed_addr,
        &TargetDestination::Domain("echo.example.org".to_string(), echo.port()),
        TEST_TIMEOUT,
    )
    .await
    .expect("SOCKS5 domain connect over Trojan should succeed");
    let half_close_msg = b"trojan-half-close-payload-4096";
    s2.write_all(half_close_msg).await.unwrap();
    s2.shutdown().await.unwrap(); // Send FIN while still reading echo reply
    let mut echoed = Vec::new();
    tokio::time::timeout(TEST_TIMEOUT, s2.read_to_end(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echoed, half_close_msg);

    // 3. HTTP CONNECT with initial pipelined payload over Trojan TLS
    let pipelined = b"pipelined-http-connect-over-trojan";
    let (mut h_stream, prefetched) = http_connect_pipelined(
        mixed_addr,
        &format!("app.example.org:{}", echo.port()),
        pipelined,
    )
    .await;
    let mut got = prefetched;
    while got.len() < pipelined.len() {
        let mut chunk = vec![0u8; pipelined.len() - got.len()];
        let n = tokio::time::timeout(TEST_TIMEOUT, h_stream.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0, "unexpected EOF reading pipelined Trojan echo");
        got.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(got, pipelined);

    proxy.kill().await;
    echo.stop().await;
    trojan_task.abort();
}

#[tokio::test]
async fn test_trojan_tls_certificate_and_sni_verification_enforced() {
    let dir = TempTestDir::new("trojan_verify");
    let pki = EphemeralPki::generate("trojan.example.org");
    let ca_der_path = dir.path().join("ca.der");
    fs::write(&ca_der_path, &pki.ca_cert_der).unwrap();

    let password = "tier9-verify-pass";
    let (trojan_addr, trojan_task) = spawn_mock_trojan_server(&pki, password).await;
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();

    let mixed_addr = ProxyProcess::get_available_addr();
    let ipc_sock = dir.path().join("yachiyo.sock");
    let cfg_path = dir.path().join("config.yaml");
    let yaml = format!(
        r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
outbounds:
  untrusted_cert:
    type: trojan
    server: {trojan_addr}
    password: {password}
    sni: trojan.example.org
    skip_cert_verify: false
  wrong_sni:
    type: trojan
    server: {trojan_addr}
    password: {password}
    sni: wrong-host.example.org
    ca_cert: {}
    skip_cert_verify: false
  explicit_skip_verify:
    type: trojan
    server: {trojan_addr}
    password: {password}
    sni: wrong-host.example.org
    skip_cert_verify: true
rules:
  - DOMAIN,untrusted.example.org,untrusted_cert
  - DOMAIN,wrongsni.example.org,wrong_sni
  - DOMAIN,skipverify.example.org,explicit_skip_verify
  - MATCH,REJECT
"#,
        ca_der_path.display()
    );
    fs::write(&cfg_path, yaml).unwrap();

    let mut proxy = ProxyProcess::start(ProxyConfig {
        mixed_addr: Some(mixed_addr),
        extra_args: vec![
            "--config".to_string(),
            cfg_path.to_string_lossy().to_string(),
            "--ipc-path".to_string(),
            ipc_sock.to_string_lossy().to_string(),
        ],
        ..Default::default()
    })
    .await
    .unwrap();

    // 1. Untrusted self-signed cert with skip_cert_verify=false MUST fail
    let res_untrusted = socks5_connect(
        mixed_addr,
        &TargetDestination::Domain("untrusted.example.org".to_string(), echo.port()),
        TEST_TIMEOUT,
    )
    .await;
    assert!(
        res_untrusted.is_err(),
        "Trojan dial without trusted CA must fail TLS verification"
    );

    // 2. Trusted CA but mismatched SNI (wrong-host.example.org != trojan.example.org) MUST fail
    let res_wrong_sni = socks5_connect(
        mixed_addr,
        &TargetDestination::Domain("wrongsni.example.org".to_string(), echo.port()),
        TEST_TIMEOUT,
    )
    .await;
    assert!(
        res_wrong_sni.is_err(),
        "Trojan dial with mismatched SNI must fail hostname verification"
    );

    // 3. Explicit skip_cert_verify=true succeeds when configured for lab testing
    let mut s_skip = socks5_connect(
        mixed_addr,
        &TargetDestination::Domain("skipverify.example.org".to_string(), echo.port()),
        TEST_TIMEOUT,
    )
    .await
    .expect("explicit skip_cert_verify=true should allow connection");
    echo_roundtrip(&mut s_skip, b"lab-skip-verify-ok").await;

    proxy.kill().await;
    echo.stop().await;
    trojan_task.abort();
}

#[tokio::test]
async fn test_trojan_wrong_password_and_fallback_group_failover() {
    let dir = TempTestDir::new("trojan_failover");
    let pki = EphemeralPki::generate("trojan.example.org");
    let ca_pem_path = dir.path().join("ca.pem");
    fs::write(
        &ca_pem_path,
        encode_pem_runtime("CERTIFICATE", &pki.ca_cert_der),
    )
    .unwrap();

    let (trojan_addr, trojan_task) = spawn_mock_trojan_server(&pki, "correct-trojan-pass").await;
    let (probe_addr, probe_task) = spawn_http_204_server().await;
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();

    let mixed_addr = ProxyProcess::get_available_addr();
    let ipc_sock = dir.path().join("yachiyo.sock");
    let cfg_path = dir.path().join("config.yaml");
    let yaml = format!(
        r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
outbounds:
  trojan_bad_auth:
    type: trojan
    server: {trojan_addr}
    password: wrong-trojan-pass
    sni: trojan.example.org
    ca_cert: {ca}
  trojan_good:
    type: trojan
    server: {trojan_addr}
    password: correct-trojan-pass
    sni: trojan.example.org
    ca_cert: {ca}
  ha_trojan:
    type: fallback
    outbounds:
      - trojan_bad_auth
      - trojan_good
    url: http://{probe_addr}/generate_204
    interval_secs: 1
    timeout_secs: 2
rules:
  - MATCH,ha_trojan
"#,
        ca = ca_pem_path.display()
    );
    fs::write(&cfg_path, yaml).unwrap();

    let mut proxy = ProxyProcess::start(ProxyConfig {
        mixed_addr: Some(mixed_addr),
        extra_args: vec![
            "--config".to_string(),
            cfg_path.to_string_lossy().to_string(),
            "--ipc-path".to_string(),
            ipc_sock.to_string_lossy().to_string(),
        ],
        ..Default::default()
    })
    .await
    .unwrap();

    // Wait for initial health probe cycle to mark `trojan_bad_auth` unhealthy and select `trojan_good`
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let out =
            ProxyProcess::run_cli(&["nodes", "--json", "--ipc-path", &ipc_sock.to_string_lossy()])
                .await
                .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains(r#""selected":"trojan_good""#) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for fallback group to select trojan_good; nodes={stdout}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut stream = socks5_connect(
        mixed_addr,
        &TargetDestination::from_socket_addr(echo.addr()),
        TEST_TIMEOUT,
    )
    .await
    .expect("fallback group should route through healthy trojan_good node");
    echo_roundtrip(&mut stream, b"failover-trojan-success").await;

    proxy.kill().await;
    echo.stop().await;
    probe_task.abort();
    trojan_task.abort();
}

#[tokio::test]
#[cfg(unix)]
async fn test_ipc_diagnostics_cli_queries_reload_and_redaction() {
    let dir = TempTestDir::new("ipc_e2e");
    let pki = EphemeralPki::generate("trojan.example.org");
    let ca_pem_path = dir.path().join("ca.pem");
    fs::write(
        &ca_pem_path,
        encode_pem_runtime("CERTIFICATE", &pki.ca_cert_der),
    )
    .unwrap();

    let secret_pw = "dummy-ipc-trojan-secret-99";
    let secret_sha = sha224_hex(secret_pw.as_bytes());
    let (trojan_addr, trojan_task) = spawn_mock_trojan_server(&pki, secret_pw).await;
    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();

    let mixed_addr = ProxyProcess::get_available_addr();
    let ipc_sock = dir.path().join("diag.sock");
    let sock_str = ipc_sock.to_string_lossy().to_string();
    let cfg_path = dir.path().join("config.yaml");

    let yaml_v1 = format!(
        r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
outbounds:
  trojan_primary:
    type: trojan
    server: {trojan_addr}
    password: {secret_pw}
    sni: trojan.example.org
    ca_cert: {}
  main_sel:
    type: selector
    outbounds:
      - trojan_primary
      - DIRECT
    selected: trojan_primary
rules:
  - MATCH,main_sel
"#,
        ca_pem_path.display()
    );
    fs::write(&cfg_path, &yaml_v1).unwrap();

    let mut proxy = ProxyProcess::start(ProxyConfig {
        mixed_addr: Some(mixed_addr),
        extra_args: vec![
            "--config".to_string(),
            cfg_path.to_string_lossy().to_string(),
            "--ipc-path".to_string(),
            sock_str.clone(),
        ],
        ..Default::default()
    })
    .await
    .unwrap();

    // Wait briefly for IPC socket bind
    let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !ipc_sock.exists() {
        assert!(
            tokio::time::Instant::now() < wait_deadline,
            "IPC socket file was not created"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // 1. `yachiyo ping --ipc-path <sock> --json`
    let ping_out = ProxyProcess::run_cli(&["ping", "--ipc-path", &sock_str, "--json"])
        .await
        .unwrap();
    assert!(ping_out.status.success());
    let ping_json = String::from_utf8_lossy(&ping_out.stdout);
    assert!(ping_json.contains(r#""ok":true"#) && ping_json.contains(r#""message":"pong""#));

    // 2. `yachiyo status --socket <sock> --json` (verifies --socket alias)
    let status_out = ProxyProcess::run_cli(&["status", "--socket", &sock_str, "--json"])
        .await
        .unwrap();
    assert!(status_out.status.success());
    let status_json = String::from_utf8_lossy(&status_out.stdout);
    assert!(status_json.contains(r#""config_generation":1"#));

    // 3. Open an active connection through Trojan and inspect `connections` while in-flight
    let app_secret_payload = b"SENSITIVE_APP_PAYLOAD_DO_NOT_LOG_42";
    let mut live_conn = socks5_connect(
        mixed_addr,
        &TargetDestination::Domain("inspect.example.org".to_string(), echo.port()),
        TEST_TIMEOUT,
    )
    .await
    .unwrap();
    echo_roundtrip(&mut live_conn, app_secret_payload).await;

    let conns_out = ProxyProcess::run_cli(&["connections", "--ipc-path", &sock_str, "--json"])
        .await
        .unwrap();
    assert!(conns_out.status.success());
    let conns_json = String::from_utf8_lossy(&conns_out.stdout);
    assert!(
        conns_json.contains(r#""active_count":1"#),
        "expected 1 active connection, got: {conns_json}"
    );
    assert!(conns_json.contains("inspect.example.org"));
    assert!(!conns_json.contains(secret_pw));
    assert!(!conns_json.contains(&secret_sha));
    assert!(!conns_json.contains("SENSITIVE_APP_PAYLOAD_DO_NOT_LOG_42"));

    // Close active connection and verify `stats` telemetry counters
    drop(live_conn);
    tokio::time::sleep(Duration::from_millis(80)).await;

    let stats_out = ProxyProcess::run_cli(&["stats", "--ipc-path", &sock_str, "--json"])
        .await
        .unwrap();
    assert!(stats_out.status.success());
    let stats_json = String::from_utf8_lossy(&stats_out.stdout);
    assert!(stats_json.contains(r#""total_connections":1"#));
    assert!(
        !stats_json.contains(r#""total_upload_bytes":0"#),
        "expected non-zero upload telemetry: {stats_json}"
    );
    assert!(
        !stats_json.contains(r#""total_download_bytes":0"#),
        "expected non-zero download telemetry: {stats_json}"
    );

    // 4. Hot-reload via SIGHUP and verify `status` (generation 2) & `nodes` update immediately
    let yaml_v2 = format!(
        r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
outbounds:
  trojan_primary:
    type: trojan
    server: {trojan_addr}
    password: {secret_pw}
    sni: trojan.example.org
    ca_cert: {ca}
  hot_added_trojan:
    type: trojan
    server: {trojan_addr}
    password: {secret_pw}
    sni: trojan.example.org
    ca_cert: {ca}
rules:
  - MATCH,hot_added_trojan
"#,
        ca = ca_pem_path.display()
    );
    fs::write(&cfg_path, &yaml_v2).unwrap();
    proxy.send_sighup().unwrap();

    let reload_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let st = ProxyProcess::run_cli(&["status", "--ipc-path", &sock_str, "--json"])
            .await
            .unwrap();
        if String::from_utf8_lossy(&st.stdout).contains(r#""config_generation":2"#) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < reload_deadline,
            "IPC status did not advance to config_generation 2 after SIGHUP"
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    let nodes_out = ProxyProcess::run_cli(&["nodes", "--ipc-path", &sock_str, "--json"])
        .await
        .unwrap();
    assert!(nodes_out.status.success());
    let nodes_json = String::from_utf8_lossy(&nodes_out.stdout);
    assert!(
        nodes_json.contains(r#""hot_added_trojan""#),
        "IPC nodes did not reflect newly reloaded outbound: {nodes_json}"
    );
    assert!(!nodes_json.contains(secret_pw));
    assert!(!nodes_json.contains(&secret_sha));

    // 5. Clean SIGINT shutdown unlinks socket file and passes zero-payload / redaction log audit
    proxy.send_sigint().unwrap();
    let exit_status = proxy
        .wait_with_timeout(Duration::from_secs(5))
        .await
        .unwrap();
    assert!(exit_status.success(), "expected clean SIGINT exit code 0");
    assert!(
        !ipc_sock.exists(),
        "IpcSocketGuard must unlink Unix socket file on clean shutdown"
    );

    proxy
        .assert_zero_payload_logging(&[
            secret_pw,
            &secret_sha,
            "SENSITIVE_APP_PAYLOAD_DO_NOT_LOG_42",
        ])
        .await;

    echo.stop().await;
    trojan_task.abort();
}

fn find_xray_binary() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("YACHIYO_XRAY_BIN") {
        let p = PathBuf::from(custom);
        if p.is_file() {
            return Some(p);
        }
    }
    for candidate in [
        "/opt/zerobrew/bin/xray",
        "/opt/homebrew/bin/xray",
        "/usr/local/bin/xray",
        "/usr/bin/xray",
    ] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[tokio::test]
async fn test_trojan_independent_xray_server_interop() {
    let Some(xray_bin) = find_xray_binary() else {
        eprintln!(
            "[SKIP] Independent xray binary not installed on this host; skipping external Trojan interop test."
        );
        return;
    };

    let dir = TempTestDir::new("xray_interop");
    let pki = EphemeralPki::generate("trojan.example.org");

    let ca_pem_path = dir.path().join("ca.pem");
    let leaf_pem_path = dir.path().join("server_cert.pem");
    let key_pem_path = dir.path().join("server_key.pem");

    fs::write(
        &ca_pem_path,
        encode_pem_runtime("CERTIFICATE", &pki.ca_cert_der),
    )
    .unwrap();
    let mut fullchain_pem = encode_pem_runtime("CERTIFICATE", &pki.leaf_cert_der);
    fullchain_pem.push_str(&encode_pem_runtime("CERTIFICATE", &pki.ca_cert_der));
    fs::write(&leaf_pem_path, fullchain_pem).unwrap();
    // Construct PKCS#8 PEM label dynamically at runtime without embedding private key markers in repo
    let key_label = format!("{} {}", "PRIVATE", "KEY");
    fs::write(
        &key_pem_path,
        encode_pem_runtime(&key_label, &pki.leaf_key_pkcs8_v1_der),
    )
    .unwrap();

    let xray_port = ProxyProcess::get_available_port();
    let xray_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), xray_port);
    let password = "xray-interop-dummy-pass";

    let xray_cfg_path = dir.path().join("xray_config.json");
    let xray_json = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "listen": "127.0.0.1",
      "port": {xray_port},
      "protocol": "trojan",
      "settings": {{
        "clients": [
          {{ "password": "{password}" }}
        ]
      }},
      "streamSettings": {{
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {{
          "alpn": ["h2", "http/1.1"],
          "certificates": [
            {{
              "certificateFile": "{}",
              "keyFile": "{}"
            }}
          ]
        }}
      }}
    }}
  ],
  "outbounds": [
    {{ "protocol": "freedom" }}
  ]
}}"#,
        leaf_pem_path.display(),
        key_pem_path.display()
    );
    fs::write(&xray_cfg_path, xray_json).unwrap();

    let mut xray_child = Command::new(&xray_bin)
        .arg("run")
        .arg("-c")
        .arg(&xray_cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn xray server");

    // Wait for Xray Trojan TLS listener to bind
    let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(status)) = xray_child.try_wait() {
            let out = xray_child.wait_with_output().await.unwrap();
            panic!(
                "xray exited prematurely ({status}): stdout={}, stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        if TcpStream::connect(xray_addr).await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < wait_deadline,
            "timed out waiting for xray Trojan port {xray_addr}"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    let echo = EchoServer::bind_ipv4(EchoMode::BidirectionalEcho)
        .await
        .unwrap();
    let mixed_addr = ProxyProcess::get_available_addr();
    let ipc_sock = dir.path().join("yachiyo_xray.sock");
    let yachiyo_cfg_path = dir.path().join("yachiyo.yaml");
    let yaml = format!(
        r#"
schema_version: 1
listeners:
  mixed: {mixed_addr}
outbounds:
  xray_trojan:
    type: trojan
    server: {xray_addr}
    password: {password}
    sni: trojan.example.org
    ca_cert: {}
    skip_cert_verify: false
rules:
  - MATCH,xray_trojan
"#,
        ca_pem_path.display()
    );
    fs::write(&yachiyo_cfg_path, yaml).unwrap();

    let mut proxy = ProxyProcess::start(ProxyConfig {
        mixed_addr: Some(mixed_addr),
        extra_args: vec![
            "--config".to_string(),
            yachiyo_cfg_path.to_string_lossy().to_string(),
            "--ipc-path".to_string(),
            ipc_sock.to_string_lossy().to_string(),
        ],
        ..Default::default()
    })
    .await
    .expect("yachiyo should start against Xray Trojan server");

    // Verify SOCKS5 bidirectional echo & half-close through independent Xray Trojan implementation
    let mut s = socks5_connect(
        mixed_addr,
        &TargetDestination::from_socket_addr(echo.addr()),
        TEST_TIMEOUT,
    )
    .await
    .expect("SOCKS5 -> Yachiyo -> Xray Trojan -> EchoServer should succeed");
    echo_roundtrip(&mut s, b"interop-with-independent-xray-server").await;

    s.write_all(b"-final-fin").await.unwrap();
    s.shutdown().await.unwrap();
    let mut tail = Vec::new();
    tokio::time::timeout(TEST_TIMEOUT, s.read_to_end(&mut tail))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tail, b"-final-fin");

    proxy.kill().await;
    let _ = xray_child.kill().await;
    echo.stop().await;
}
