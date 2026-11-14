// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol sniffer for mixed inbound endpoints, differentiating SOCKS5 (`0x05`) from HTTP CONNECT.

use std::time::Duration;
use tokio::net::TcpStream;

/// Identified inbound application protocol on a mixed port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// SOCKS5 protocol (RFC 1928, first byte 0x05)
    Socks5,
    /// HTTP protocol (RFC 9110, HTTP CONNECT or other text requests)
    HttpConnect,
    /// Clean disconnect before sending data (zero-byte health probe or port scan)
    CleanClose,
}

/// Backwards-compatible alias for [`Protocol`].
pub type InboundProtocol = Protocol;

impl Protocol {
    /// Returns `true` if protocol is SOCKS5.
    #[inline]
    pub fn is_socks5(&self) -> bool {
        matches!(self, Self::Socks5)
    }

    /// Returns `true` if protocol is HTTP CONNECT.
    #[inline]
    pub fn is_http(&self) -> bool {
        matches!(self, Self::HttpConnect)
    }

    /// Returns `true` if protocol is CleanClose.
    #[inline]
    pub fn is_clean_close(&self) -> bool {
        matches!(self, Self::CleanClose)
    }
}

/// Errors occurring during protocol sniffing.
#[derive(Debug, thiserror::Error)]
pub enum SniffError {
    /// The client failed to provide data within the configured handshake timeout.
    #[error("handshake timed out while sniffing protocol")]
    Timeout,
    /// An underlying socket I/O error occurred during peek.
    #[error("I/O error while sniffing protocol: {0}")]
    Io(#[from] std::io::Error),
}

/// Identifies the protocol from the first octet of an inbound connection.
///
/// Returns `Protocol::Socks5` if `first_byte == 0x05`, otherwise `Protocol::HttpConnect`.
#[inline]
pub fn identify_protocol(first_byte: u8) -> Protocol {
    if first_byte == 0x05 {
        Protocol::Socks5
    } else {
        Protocol::HttpConnect
    }
}

/// Peeks the first byte of `stream` within `handshake_timeout` without consuming it.
///
/// - Returns `Ok(Protocol::Socks5)` when the first byte is `0x05`.
/// - Returns `Ok(Protocol::HttpConnect)` when the first byte is not `0x05`.
/// - Returns `Ok(Protocol::CleanClose)` when the client disconnects immediately (0-byte EOF / health probe).
/// - Returns `Err(SniffError::Timeout)` if `handshake_timeout` expires before any byte arrives.
/// - Returns `Err(SniffError::Io)` on socket read failure.
///
/// # Byte Preservation
/// Because this uses `TcpStream::peek`, the inspected byte remains in the socket's
/// kernel receive buffer, allowing downstream protocol parsers to read the complete stream intact.
pub async fn sniff_protocol(
    stream: &TcpStream,
    handshake_timeout: Duration,
) -> Result<Protocol, SniffError> {
    let mut buf = [0u8; 1];
    let peek_fut = stream.peek(&mut buf);

    match tokio::time::timeout(handshake_timeout, peek_fut).await {
        Ok(Ok(0)) => {
            // Immediate EOF: peer disconnected without sending payload (health check / port scan)
            Ok(Protocol::CleanClose)
        }
        Ok(Ok(_)) => Ok(identify_protocol(buf[0])),
        Ok(Err(e)) => Err(SniffError::Io(e)),
        Err(_) => Err(SniffError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn run_async<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = accept_task.await.unwrap();
        (client, server)
    }

    #[test]
    fn test_identify_protocol_pure() {
        assert_eq!(identify_protocol(0x05), Protocol::Socks5);
        assert_eq!(identify_protocol(b'C'), Protocol::HttpConnect);
        assert_eq!(identify_protocol(b'G'), Protocol::HttpConnect);
        assert_eq!(identify_protocol(0x04), Protocol::HttpConnect);
        assert_eq!(identify_protocol(0x00), Protocol::HttpConnect);
        assert_eq!(identify_protocol(0xFF), Protocol::HttpConnect);
    }

    #[test]
    fn test_protocol_helper_methods() {
        assert!(Protocol::Socks5.is_socks5());
        assert!(!Protocol::Socks5.is_http());
        assert!(!Protocol::Socks5.is_clean_close());

        assert!(Protocol::HttpConnect.is_http());
        assert!(!Protocol::HttpConnect.is_socks5());
        assert!(!Protocol::HttpConnect.is_clean_close());

        assert!(Protocol::CleanClose.is_clean_close());
        assert!(!Protocol::CleanClose.is_socks5());
        assert!(!Protocol::CleanClose.is_http());
    }

    #[test]
    fn test_sniff_socks5_peek_preserves_first_byte() {
        run_async(async {
            let (mut client, server) = tcp_pair().await;

            let client_task = tokio::spawn(async move {
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                client
            });

            let proto = sniff_protocol(&server, Duration::from_secs(2))
                .await
                .expect("sniff succeeds");
            assert_eq!(proto, Protocol::Socks5);

            // Crucial verification: reading from server still yields the peeked 0x05 byte!
            let mut read_buf = [0u8; 3];
            let mut server = server;
            server.read_exact(&mut read_buf).await.unwrap();
            assert_eq!(&read_buf, &[0x05, 0x01, 0x00]);

            let _ = client_task.await.unwrap();
        });
    }

    #[test]
    fn test_sniff_http_peek_preserves_first_byte() {
        run_async(async {
            let (mut client, server) = tcp_pair().await;

            let request = b"CONNECT 127.0.0.1:8080 HTTP/1.1\r\n\r\n";
            let client_task = tokio::spawn(async move {
                client.write_all(request).await.unwrap();
                client
            });

            let proto = sniff_protocol(&server, Duration::from_secs(2))
                .await
                .expect("sniff succeeds");
            assert_eq!(proto, Protocol::HttpConnect);

            let mut read_buf = vec![0u8; request.len()];
            let mut server = server;
            server.read_exact(&mut read_buf).await.unwrap();
            assert_eq!(&read_buf, request);

            let _ = client_task.await.unwrap();
        });
    }

    #[test]
    fn test_sniff_zero_byte_eof_clean_probe() {
        run_async(async {
            let (client, server) = tcp_pair().await;

            // Client immediately shuts down without sending bytes
            drop(client);

            let result = sniff_protocol(&server, Duration::from_secs(2))
                .await
                .unwrap();
            assert_eq!(result, Protocol::CleanClose);
        });
    }

    #[test]
    fn test_sniff_timeout() {
        run_async(async {
            let (_client, server) = tcp_pair().await;

            // Client holds connection open but sends no bytes
            let result = sniff_protocol(&server, Duration::from_millis(50)).await;
            match result {
                Err(SniffError::Timeout) => {}
                other => panic!("expected SniffError::Timeout, got {other:?}"),
            }
        });
    }
}
