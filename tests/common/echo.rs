// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-protocol local echo server harness for Project Yachiyo E2E testing.
//!
//! Supports IPv4, IPv6, half-close detection, configurable delays,
//! blackhole simulation, and metrics collection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Operating mode for the echo server instance.
#[derive(Debug, Clone)]
pub enum EchoMode {
    /// Standard bidirectional echo: reads until EOF, writing received bytes back.
    BidirectionalEcho,
    /// Half-close detection (Client FIN first):
    /// Reads client data until EOF (client shut down write half),
    /// then sends back `b"HALF_CLOSE_ACK:"` followed by received data, then shuts down.
    HalfCloseClientFin,
    /// Half-close detection (Server FIN first):
    /// Receives initial greeting, writes response, then shuts down write half (`shutdown(Write)`),
    /// and keeps reading client stream until client EOF.
    HalfCloseServerFin,
    /// Delayed response: sleeps for the specified duration before replying.
    DelayedEcho(Duration),
    /// Blackhole server: accepts connection, but neither reads nor writes (sleeps until closed).
    Blackhole,
    /// Immediately closes connection on accept.
    DropImmediately,
    /// Discard all incoming bytes (sink), useful for high-throughput or 1024 concurrency tests.
    Discard,
    /// Responds with a fixed HTTP response payload (useful for HTTP CONNECT target testing).
    HttpServer { body: String },
}

/// Statistics collected by the echo server.
#[derive(Debug, Default)]
pub struct EchoStats {
    pub connections_accepted: AtomicUsize,
    pub bytes_received: AtomicUsize,
    pub bytes_sent: AtomicUsize,
    pub half_close_detected: AtomicBool,
}

/// Running handle to a multi-protocol echo server.
pub struct EchoServer {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: Option<JoinHandle<()>>,
    stats: Arc<EchoStats>,
}

impl EchoServer {
    /// Bind and start an IPv4 echo server on loopback (`127.0.0.1:0`).
    pub async fn bind_ipv4(mode: EchoMode) -> Result<Self, std::io::Error> {
        Self::start("127.0.0.1:0", mode).await
    }

    /// Bind and start an IPv6 echo server on loopback (`[::1]:0`).
    pub async fn bind_ipv6(mode: EchoMode) -> Result<Self, std::io::Error> {
        Self::start("[::1]:0", mode).await
    }

    /// Bind and start an echo server on the specified address.
    pub async fn start(bind_addr: &str, mode: EchoMode) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(bind_addr).await?;
        let addr = listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let stats = Arc::new(EchoStats::default());
        let stats_clone = Arc::clone(&stats);

        let server_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, _peer)) => {
                                stats_clone.connections_accepted.fetch_add(1, Ordering::SeqCst);
                                let stream_stats = Arc::clone(&stats_clone);
                                let stream_mode = mode.clone();
                                tokio::spawn(async move {
                                    handle_connection(stream, stream_mode, stream_stats).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Ok(Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
            server_task: Some(server_task),
            stats,
        })
    }

    /// Local bound address of the server.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Bound port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Access collected statistics.
    pub fn stats(&self) -> &EchoStats {
        &self.stats
    }

    /// Stop the server gracefully.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.server_task.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn handle_connection(mut stream: TcpStream, mode: EchoMode, stats: Arc<EchoStats>) {
    match mode {
        EchoMode::BidirectionalEcho => {
            let (mut reader, mut writer) = stream.split();
            let mut buf = vec![0u8; 8192];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        stats.bytes_received.fetch_add(n, Ordering::SeqCst);
                        if writer.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        stats.bytes_sent.fetch_add(n, Ordering::SeqCst);
                    }
                    Err(_) => break,
                }
            }
        }
        EchoMode::HalfCloseClientFin => {
            // Read until client sends EOF (FIN)
            let mut received = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => {
                        // EOF detected from client
                        stats.half_close_detected.store(true, Ordering::SeqCst);
                        break;
                    }
                    Ok(n) => {
                        stats.bytes_received.fetch_add(n, Ordering::SeqCst);
                        received.extend_from_slice(&buf[..n]);
                    }
                    Err(_) => return,
                }
            }

            // Now send response back to client
            let mut response = b"HALF_CLOSE_ACK:".to_vec();
            response.extend_from_slice(&received);
            if stream.write_all(&response).await.is_ok() {
                stats.bytes_sent.fetch_add(response.len(), Ordering::SeqCst);
            }
            let _ = stream.shutdown().await;
        }
        EchoMode::HalfCloseServerFin => {
            // Read initial message from client
            let mut buf = [0u8; 512];
            let _n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    stats.bytes_received.fetch_add(n, Ordering::SeqCst);
                    n
                }
                _ => return,
            };

            // Write response
            let response = b"SERVER_FIN_ACK";
            if stream.write_all(response).await.is_ok() {
                stats.bytes_sent.fetch_add(response.len(), Ordering::SeqCst);
            }

            // Half-close server write side
            if stream.shutdown().await.is_err() {
                return;
            }
            stats.half_close_detected.store(true, Ordering::SeqCst);

            // Continue reading from client until client closes
            let mut drain_buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut drain_buf).await {
                    Ok(0) => break,
                    Ok(read_n) => {
                        stats.bytes_received.fetch_add(read_n, Ordering::SeqCst);
                    }
                    Err(_) => break,
                }
            }
        }
        EchoMode::DelayedEcho(delay) => {
            tokio::time::sleep(delay).await;
            let (mut reader, mut writer) = stream.split();
            let mut buf = vec![0u8; 4096];
            while let Ok(n) = reader.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                stats.bytes_received.fetch_add(n, Ordering::SeqCst);
                if writer.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                stats.bytes_sent.fetch_add(n, Ordering::SeqCst);
            }
        }
        EchoMode::Blackhole => {
            // Read nothing, write nothing, wait indefinitely until peer drops
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf).await;
        }
        EchoMode::DropImmediately => {
            // Drop connection immediately
            drop(stream);
        }
        EchoMode::Discard => {
            let mut buf = vec![0u8; 8192];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                stats.bytes_received.fetch_add(n, Ordering::SeqCst);
            }
        }
        EchoMode::HttpServer { body } => {
            // Read HTTP request until \r\n\r\n
            let mut req_buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(n) = stream.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                stats.bytes_received.fetch_add(n, Ordering::SeqCst);
                req_buf.extend_from_slice(&chunk[..n]);
                if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            if stream.write_all(response.as_bytes()).await.is_ok() {
                stats.bytes_sent.fetch_add(response.len(), Ordering::SeqCst);
            }
            let _ = stream.shutdown().await;
        }
    }
}

/// Connection blackhole fixture that binds a loopback listener with backlog=1
/// and saturates its accept queue with dummy connections.
///
/// Because incoming SYN packets are silently discarded by the kernel when the
/// accept queue is full, subsequent TCP connect attempts will hang until the
/// client-side connection timeout expires.
///
/// Because this binds strictly to loopback (`127.0.0.1`), it is completely immune
/// to transparent VPN, fake-IP, or TUN interception on local developer machines,
/// and behaves identically on macOS and Linux CI runners.
#[cfg(unix)]
#[derive(Debug)]
pub struct ConnectBlackhole {
    _listener: std::net::TcpListener,
    _fillers: Vec<std::net::TcpStream>,
    pub addr: std::net::SocketAddr,
}

#[cfg(unix)]
impl ConnectBlackhole {
    pub fn new() -> Result<Self, std::io::Error> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = libc::htonl(libc::INADDR_LOOPBACK);
        addr.sin_port = 0;

        unsafe {
            if libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            ) != 0
            {
                libc::close(fd);
                return Err(std::io::Error::last_os_error());
            }

            if libc::listen(fd, 1) != 0 {
                libc::close(fd);
                return Err(std::io::Error::last_os_error());
            }
        }

        use std::os::unix::io::FromRawFd;
        let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        let bound_addr = listener.local_addr()?;

        // Saturate the accept queue by connecting filler sockets.
        // On macOS/BSD backlog=1 allows 1 connection in accept queue;
        // On Linux it allows up to 2.
        let mut fillers = Vec::new();
        for _ in 0..3 {
            if let Ok(stream) = std::net::TcpStream::connect_timeout(
                &bound_addr,
                std::time::Duration::from_millis(50),
            ) {
                fillers.push(stream);
            }
        }

        Ok(Self {
            _listener: listener,
            _fillers: fillers,
            addr: bound_addr,
        })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}
