// SPDX-License-Identifier: AGPL-3.0-only

//! Bidirectional data forwarding kernel with dual-simplex half-close propagation,
//! HTTP CONNECT initial data preservation, 300s idle timeout, and zero-payload logging.

use std::fmt;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, warn};

/// Default bidirectional inactivity timeout (300 seconds).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Default directional transfer buffer size (8 KB).
pub const DEFAULT_BUFFER_SIZE: usize = 8192;

/// Bidirectional stream abstraction unifying raw TCP and TLS streams.
pub enum OutboundStream {
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl fmt::Debug for OutboundStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(s) => f.debug_tuple("Tcp").field(s).finish(),
            Self::Tls(_) => f.debug_tuple("Tls").finish(),
        }
    }
}

impl From<TcpStream> for OutboundStream {
    fn from(s: TcpStream) -> Self {
        Self::Tcp(s)
    }
}

impl From<tokio_rustls::client::TlsStream<TcpStream>> for OutboundStream {
    fn from(s: tokio_rustls::client::TlsStream<TcpStream>) -> Self {
        Self::Tls(Box::new(s))
    }
}

impl AsyncRead for OutboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Telemetry statistics returned upon forwarding completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransferStats {
    /// Total bytes transferred from client to remote (including pipelined initial data).
    pub client_to_remote: u64,
    /// Total bytes transferred from remote to client.
    pub remote_to_client: u64,
}

impl TransferStats {
    /// Returns the aggregate number of bytes transferred in both directions.
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.client_to_remote.saturating_add(self.remote_to_client)
    }
}

enum ReadEvent {
    Client(std::io::Result<usize>),
    Remote(std::io::Result<usize>),
}

/// Copies data bidirectionally between `client` and `remote` streams until both
/// directions are closed, an I/O error occurs, or the idle timeout expires.
///
/// # Semantics:
/// - **Initial Data**: If `initial_outbound_data` is provided, it is forwarded to `remote`
///   before reading subsequent client data, and counted in `client_to_remote`.
/// - **Half-Close**: When `client` reaches EOF, `remote`'s write half is shut down via
///   `shutdown()` while reading from `remote` continues; and vice-versa.
/// - **Idle Timeout**: The idle timer resets whenever bytes are transferred in either
///   direction. If no data flows for `idle_timeout`, the connection is aborted with
///   [`std::io::ErrorKind::TimedOut`].
/// - **Privacy**: Zero payload bytes are logged; tracing emits only byte metrics and state events.
pub async fn copy_bidirectional_with_idle_timeout(
    mut client: TcpStream,
    remote: impl Into<OutboundStream>,
    idle_timeout: Duration,
    initial_outbound_data: Option<&[u8]>,
) -> Result<TransferStats, std::io::Error> {
    let remote = remote.into();
    let (mut client_read, mut client_write) = client.split();
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let mut client_to_remote = 0u64;
    let mut remote_to_client = 0u64;

    let mut deadline = Instant::now() + idle_timeout;

    // 1. Forward pipelined initial data (e.g. TLS ClientHello from HTTP CONNECT)
    if let Some(initial) = initial_outbound_data {
        if !initial.is_empty() {
            debug!(
                bytes = initial.len(),
                "forwarding initial unconsumed data to remote"
            );
            match tokio::time::timeout_at(deadline, remote_write.write_all(initial)).await {
                Ok(res) => {
                    res?;
                    client_to_remote += initial.len() as u64;
                    deadline = Instant::now() + idle_timeout;
                }
                Err(_) => {
                    warn!("idle timeout while sending initial outbound data");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "idle timeout while forwarding initial outbound data",
                    ));
                }
            }
        }
    }

    let mut client_buf = [0u8; DEFAULT_BUFFER_SIZE];
    let mut remote_buf = [0u8; DEFAULT_BUFFER_SIZE];

    let mut client_closed = false;
    let mut remote_closed = false;
    let mut toggle = false;

    // 2. Dual-simplex multiplexed loop
    while !client_closed || !remote_closed {
        let read_fut = poll_fn(|cx| {
            if toggle {
                if !client_closed {
                    let mut read_buf = ReadBuf::new(&mut client_buf);
                    match Pin::new(&mut client_read).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            return Poll::Ready(ReadEvent::Client(Ok(read_buf.filled().len())));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(ReadEvent::Client(Err(e))),
                        Poll::Pending => {}
                    }
                }
                if !remote_closed {
                    let mut read_buf = ReadBuf::new(&mut remote_buf);
                    match Pin::new(&mut remote_read).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            return Poll::Ready(ReadEvent::Remote(Ok(read_buf.filled().len())));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(ReadEvent::Remote(Err(e))),
                        Poll::Pending => {}
                    }
                }
            } else {
                if !remote_closed {
                    let mut read_buf = ReadBuf::new(&mut remote_buf);
                    match Pin::new(&mut remote_read).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            return Poll::Ready(ReadEvent::Remote(Ok(read_buf.filled().len())));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(ReadEvent::Remote(Err(e))),
                        Poll::Pending => {}
                    }
                }
                if !client_closed {
                    let mut read_buf = ReadBuf::new(&mut client_buf);
                    match Pin::new(&mut client_read).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            return Poll::Ready(ReadEvent::Client(Ok(read_buf.filled().len())));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(ReadEvent::Client(Err(e))),
                        Poll::Pending => {}
                    }
                }
            }
            Poll::Pending
        });

        let event = match tokio::time::timeout_at(deadline, read_fut).await {
            Ok(ev) => ev,
            Err(_) => {
                warn!(
                    client_to_remote,
                    remote_to_client,
                    idle_timeout_secs = idle_timeout.as_secs(),
                    "forwarding aborted due to idle timeout"
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "idle timeout during bidirectional forwarding",
                ));
            }
        };

        toggle = !toggle;

        match event {
            ReadEvent::Client(res) => match res? {
                0 => {
                    client_closed = true;
                    debug!(
                        "client read EOF: propagating half-close FIN (shutdown Write) to remote"
                    );
                    remote_write.shutdown().await?;
                }
                n => {
                    remote_write.write_all(&client_buf[..n]).await?;
                    client_to_remote += n as u64;
                    deadline = Instant::now() + idle_timeout;
                }
            },
            ReadEvent::Remote(res) => match res? {
                0 => {
                    remote_closed = true;
                    debug!(
                        "remote read EOF: propagating half-close FIN (shutdown Write) to client"
                    );
                    client_write.shutdown().await?;
                }
                n => {
                    client_write.write_all(&remote_buf[..n]).await?;
                    remote_to_client += n as u64;
                    deadline = Instant::now() + idle_timeout;
                }
            },
        }
    }

    debug!(
        client_to_remote,
        remote_to_client, "bidirectional forwarding completed cleanly (both directions closed)"
    );

    Ok(TransferStats {
        client_to_remote,
        remote_to_client,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn run_async<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Helper creating a connected pair of local TCP streams over loopback.
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = accept_task.await.unwrap();
        (client, server)
    }

    /// Helper establishing proxy test harness with mock client and remote server.
    /// Returns: (client_side, proxy_client, proxy_remote, remote_side)
    async fn proxy_harness() -> (TcpStream, TcpStream, TcpStream, TcpStream) {
        let (client_side, proxy_client) = tcp_pair().await;
        let (proxy_remote, remote_side) = tcp_pair().await;
        (client_side, proxy_client, proxy_remote, remote_side)
    }

    #[test]
    fn test_forward_ping_pong_bidirectional() {
        run_async(async {
            let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

            let forward_task = tokio::spawn(async move {
                copy_bidirectional_with_idle_timeout(
                    proxy_client,
                    proxy_remote,
                    Duration::from_secs(10),
                    None,
                )
                .await
                .unwrap()
            });

            // Client sends 1000 bytes
            let client_msg = vec![0x42u8; 1000];
            client.write_all(&client_msg).await.unwrap();

            // Remote reads 1000 bytes
            let mut remote_recv = vec![0u8; 1000];
            remote.read_exact(&mut remote_recv).await.unwrap();
            assert_eq!(client_msg, remote_recv);

            // Remote sends 500 bytes back
            let remote_msg = vec![0x99u8; 500];
            remote.write_all(&remote_msg).await.unwrap();

            // Client reads 500 bytes
            let mut client_recv = vec![0u8; 500];
            client.read_exact(&mut client_recv).await.unwrap();
            assert_eq!(remote_msg, client_recv);

            // Both sides close
            client.shutdown().await.unwrap();
            remote.shutdown().await.unwrap();

            let stats = forward_task.await.unwrap();
            assert_eq!(stats.client_to_remote, 1000);
            assert_eq!(stats.remote_to_client, 500);
            assert_eq!(stats.total_bytes(), 1500);
        });
    }

    #[test]
    fn test_forward_client_half_close_fin_propagation() {
        run_async(async {
            let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

            let forward_task = tokio::spawn(async move {
                copy_bidirectional_with_idle_timeout(
                    proxy_client,
                    proxy_remote,
                    Duration::from_secs(10),
                    None,
                )
                .await
                .unwrap()
            });

            // 1. Client uploads request data, then half-closes write half (FIN)
            let request_payload = b"UPLOAD_DATA_BEFORE_FIN";
            client.write_all(request_payload).await.unwrap();
            client.shutdown().await.unwrap(); // Sends FIN; client read half is still open!

            // 2. Remote reads all data until EOF
            let mut received = Vec::new();
            let mut buf = [0u8; 64];
            loop {
                let n = remote.read(&mut buf).await.unwrap();
                if n == 0 {
                    break; // Remote cleanly received FIN from proxy!
                }
                received.extend_from_slice(&buf[..n]);
            }
            assert_eq!(&received, request_payload);

            // 3. Remote now replies with response data across the reverse half
            let response_payload = b"SERVER_RESPONSE_AFTER_CLIENT_FIN";
            remote.write_all(response_payload).await.unwrap();
            remote.shutdown().await.unwrap(); // Remote now sends FIN

            // 4. Client successfully reads response data until EOF
            let mut client_received = Vec::new();
            let mut client_buf = [0u8; 64];
            loop {
                let n = client.read(&mut client_buf).await.unwrap();
                if n == 0 {
                    break;
                }
                client_received.extend_from_slice(&client_buf[..n]);
            }
            assert_eq!(&client_received, response_payload);

            // 5. Forwarding task exits cleanly with exact stats
            let stats = forward_task.await.unwrap();
            assert_eq!(stats.client_to_remote, request_payload.len() as u64);
            assert_eq!(stats.remote_to_client, response_payload.len() as u64);
        });
    }

    #[test]
    fn test_forward_remote_half_close_fin_propagation() {
        run_async(async {
            let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

            let forward_task = tokio::spawn(async move {
                copy_bidirectional_with_idle_timeout(
                    proxy_client,
                    proxy_remote,
                    Duration::from_secs(10),
                    None,
                )
                .await
                .unwrap()
            });

            // 1. Remote sends banner and immediately half-closes write half (FIN)
            let banner = b"SERVER_BANNER_EOF";
            remote.write_all(banner).await.unwrap();
            remote.shutdown().await.unwrap();

            // 2. Client receives banner until EOF
            let mut client_buf = [0u8; 64];
            let mut client_received = Vec::new();
            loop {
                let n = client.read(&mut client_buf).await.unwrap();
                if n == 0 {
                    break;
                }
                client_received.extend_from_slice(&client_buf[..n]);
            }
            assert_eq!(&client_received, banner);

            // 3. Client transmits trailing acknowledgement to remote
            let ack = b"CLIENT_TRAILING_ACK";
            client.write_all(ack).await.unwrap();
            client.shutdown().await.unwrap();

            // 4. Remote receives acknowledgement until EOF
            let mut remote_buf = [0u8; 64];
            let mut remote_received = Vec::new();
            loop {
                let n = remote.read(&mut remote_buf).await.unwrap();
                if n == 0 {
                    break;
                }
                remote_received.extend_from_slice(&remote_buf[..n]);
            }
            assert_eq!(&remote_received, ack);

            let stats = forward_task.await.unwrap();
            assert_eq!(stats.client_to_remote, ack.len() as u64);
            assert_eq!(stats.remote_to_client, banner.len() as u64);
        });
    }

    #[test]
    fn test_forward_initial_outbound_data_preservation() {
        run_async(async {
            let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

            let pipelined_tls_hello = b"\x16\x03\x01\x00\x10MOCK_TLS_CLIENT_HELLO";

            let forward_task = tokio::spawn(async move {
                copy_bidirectional_with_idle_timeout(
                    proxy_client,
                    proxy_remote,
                    Duration::from_secs(10),
                    Some(pipelined_tls_hello),
                )
                .await
                .unwrap()
            });

            // 1. Remote's first read must receive the preserved pipelined data
            let mut first_recv = vec![0u8; pipelined_tls_hello.len()];
            remote.read_exact(&mut first_recv).await.unwrap();
            assert_eq!(&first_recv, pipelined_tls_hello);

            // 2. Client then sends further data
            client.write_all(b"SECONDARY_DATA").await.unwrap();
            let mut second_recv = vec![0u8; 14];
            remote.read_exact(&mut second_recv).await.unwrap();
            assert_eq!(&second_recv, b"SECONDARY_DATA");

            client.shutdown().await.unwrap();
            remote.shutdown().await.unwrap();

            let stats = forward_task.await.unwrap();
            assert_eq!(
                stats.client_to_remote,
                (pipelined_tls_hello.len() + 14) as u64
            );
        });
    }

    #[test]
    fn test_forward_idle_timeout_expiration() {
        run_async(async {
            let (_client, proxy_client, proxy_remote, _remote) = proxy_harness().await;

            let result = copy_bidirectional_with_idle_timeout(
                proxy_client,
                proxy_remote,
                Duration::from_millis(50),
                None,
            )
            .await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        });
    }

    #[test]
    fn test_forward_idle_timeout_reset_on_activity() {
        run_async(async {
            let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

            let forward_task = tokio::spawn(async move {
                copy_bidirectional_with_idle_timeout(
                    proxy_client,
                    proxy_remote,
                    Duration::from_millis(80),
                    None,
                )
                .await
            });

            // Wait 40ms (< 80ms)
            tokio::time::sleep(Duration::from_millis(40)).await;

            // Client transfers data at t=40ms, resetting idle timer
            client.write_all(b"PING").await.unwrap();
            let mut buf = [0u8; 4];
            remote.read_exact(&mut buf).await.unwrap();

            // Wait 50ms (t=90ms total, but only 50ms since last activity)
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Remote transfers data at t=90ms, resetting idle timer
            remote.write_all(b"PONG").await.unwrap();
            let mut buf2 = [0u8; 4];
            client.read_exact(&mut buf2).await.unwrap();

            // Verify task is still alive
            assert!(!forward_task.is_finished());

            // Wait 100ms (> 80ms inactivity) -> NOW it times out!
            tokio::time::sleep(Duration::from_millis(100)).await;

            let result = forward_task.await.unwrap();
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        });
    }

    #[test]
    fn test_forward_zero_byte_connection() {
        run_async(async {
            let (mut client, proxy_client, proxy_remote, mut remote) = proxy_harness().await;

            let forward_task = tokio::spawn(async move {
                copy_bidirectional_with_idle_timeout(
                    proxy_client,
                    proxy_remote,
                    Duration::from_secs(10),
                    None,
                )
                .await
                .unwrap()
            });

            // Immediate close without payload
            client.shutdown().await.unwrap();
            remote.shutdown().await.unwrap();

            let stats = forward_task.await.unwrap();
            assert_eq!(stats.client_to_remote, 0);
            assert_eq!(stats.remote_to_client, 0);
            assert_eq!(stats.total_bytes(), 0);
        });
    }
}
