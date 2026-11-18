// SPDX-License-Identifier: AGPL-3.0-only

//! Outbound direct TCP dialer supporting system DNS resolution, connect timeout, and multi-IP fallback.

use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::address::{TargetAddr, TargetHost};

/// Outbound direct TCP dialer supporting system DNS resolution and sequential multi-IP fallback.
#[derive(Debug, Clone)]
pub struct DirectDialer {
    connect_timeout: Duration,
    per_ip_timeout: Option<Duration>,
}

impl Default for DirectDialer {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CONNECT_TIMEOUT)
    }
}

impl DirectDialer {
    /// Default connection timeout: 10 seconds.
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Create a new `DirectDialer` with the specified total connection timeout budget.
    pub fn new(connect_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            per_ip_timeout: None,
        }
    }

    /// Set an optional timeout cap for each individual IP candidate attempt.
    pub fn with_per_ip_timeout(mut self, timeout: Duration) -> Self {
        self.per_ip_timeout = Some(timeout);
        self
    }

    /// Get configured total connect timeout.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Dial destination address directly.
    ///
    /// For domain targets, resolves candidates via system DNS (`tokio::net::lookup_host`)
    /// and sequentially attempts connection across candidate IPs within the timeout budget.
    pub async fn dial(&self, target: &TargetAddr) -> Result<TcpStream, Error> {
        let deadline = Instant::now() + self.connect_timeout;

        match tokio::time::timeout_at(deadline, self.dial_internal(target, deadline)).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(
                    target = %target,
                    timeout = ?self.connect_timeout,
                    "outbound dial timeout budget exceeded"
                );
                Err(Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "connection to {target} timed out after {:?}",
                        self.connect_timeout
                    ),
                ))
            }
        }
    }

    async fn dial_internal(
        &self,
        target: &TargetAddr,
        deadline: Instant,
    ) -> Result<TcpStream, Error> {
        match &target.host {
            TargetHost::Ip(ip) => {
                let addr = SocketAddr::new(*ip, target.port);
                self.dial_single(addr, deadline, target).await
            }
            TargetHost::Domain(domain) => {
                let host_port = format!("{}:{}", domain, target.port);
                tracing::debug!(target = %target, "resolving domain via system DNS");

                let candidates: Vec<SocketAddr> = match tokio::net::lookup_host(&host_port).await {
                    Ok(iter) => iter.collect(),
                    Err(e) => {
                        tracing::warn!(target = %target, error = %e, "system DNS lookup failed");
                        return Err(Error::new(
                            ErrorKind::NotFound,
                            format!("DNS resolution failed for {target}: {e}"),
                        ));
                    }
                };

                if candidates.is_empty() {
                    tracing::warn!(target = %target, "system DNS returned 0 addresses");
                    return Err(Error::new(
                        ErrorKind::NotFound,
                        format!("no IP addresses resolved for {target}"),
                    ));
                }

                tracing::debug!(
                    target = %target,
                    candidate_count = candidates.len(),
                    "system DNS resolved candidates"
                );

                let mut last_error = None;
                for (idx, &addr) in candidates.iter().enumerate() {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(Error::new(
                            ErrorKind::TimedOut,
                            format!("connection budget expired before trying candidate {addr}"),
                        ));
                    }

                    tracing::debug!(
                        target = %target,
                        candidate = %addr,
                        attempt = idx + 1,
                        total = candidates.len(),
                        "dialing candidate IP"
                    );

                    match self.dial_single(addr, deadline, target).await {
                        Ok(stream) => {
                            tracing::info!(
                                target = %target,
                                connected = %addr,
                                "outbound direct connection established"
                            );
                            return Ok(stream);
                        }
                        Err(e) => {
                            tracing::warn!(
                                target = %target,
                                candidate = %addr,
                                error = %e,
                                kind = ?e.kind(),
                                "candidate connection failed, falling back to next"
                            );
                            last_error = Some(e);
                        }
                    }
                }

                Err(last_error.unwrap_or_else(|| {
                    Error::new(
                        ErrorKind::HostUnreachable,
                        format!("all resolved addresses for {target} failed to connect"),
                    )
                }))
            }
        }
    }

    async fn dial_single(
        &self,
        addr: SocketAddr,
        deadline: Instant,
        target: &TargetAddr,
    ) -> Result<TcpStream, Error> {
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::new(
                ErrorKind::TimedOut,
                format!("connection budget expired before connecting to {addr}"),
            ));
        }

        let remaining = deadline - now;
        let attempt_timeout = match self.per_ip_timeout {
            Some(per_ip) => remaining.min(per_ip),
            None => remaining,
        };

        match tokio::time::timeout(attempt_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                Ok(stream)
            }
            Ok(Err(io_err)) => Err(normalize_connect_error(io_err, target, addr)),
            Err(_) => Err(Error::new(
                ErrorKind::TimedOut,
                format!("connection to {addr} timed out after {attempt_timeout:?}"),
            )),
        }
    }
}

/// Dial target address directly with specified timeout.
pub async fn dial_direct(target: &TargetAddr, timeout: Duration) -> Result<TcpStream, Error> {
    DirectDialer::new(timeout).dial(target).await
}

/// Normalize OS connect error into specific `ErrorKind`.
fn normalize_connect_error(err: Error, target: &TargetAddr, addr: SocketAddr) -> Error {
    let kind = err.kind();
    match kind {
        ErrorKind::ConnectionRefused
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::TimedOut
        | ErrorKind::AddrNotAvailable => err,
        _ => {
            // Check raw OS error on Unix platforms as fallback
            #[cfg(unix)]
            if let Some(raw) = err.raw_os_error() {
                if raw == 61 /* ECONNREFUSED on macOS */ || raw == 111
                /* Linux */
                {
                    return Error::new(
                        ErrorKind::ConnectionRefused,
                        format!("connection refused to {target} ({addr})"),
                    );
                }
                if raw == 65 /* EHOSTUNREACH on macOS */ || raw == 113
                /* Linux */
                {
                    return Error::new(
                        ErrorKind::HostUnreachable,
                        format!("host unreachable: {target} ({addr})"),
                    );
                }
                if raw == 51 /* ENETUNREACH on macOS */ || raw == 101
                /* Linux */
                {
                    return Error::new(
                        ErrorKind::NetworkUnreachable,
                        format!("network unreachable: {target} ({addr})"),
                    );
                }
                if raw == 60 /* ETIMEDOUT on macOS */ || raw == 110
                /* Linux */
                {
                    return Error::new(
                        ErrorKind::TimedOut,
                        format!("connection timed out to {target} ({addr})"),
                    );
                }
            }
            err
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
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

    #[test]
    fn test_direct_dial_ip_success() {
        run_async(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local_addr = listener.local_addr().unwrap();

            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
                stream.write_all(b"pong").await.unwrap();
            });

            let target = TargetAddr::from(local_addr);
            let dialer = DirectDialer::new(Duration::from_secs(2));
            let mut client = dialer.dial(&target).await.expect("dial should succeed");

            client.write_all(b"ping").await.unwrap();
            let mut res = [0u8; 4];
            client.read_exact(&mut res).await.unwrap();
            assert_eq!(&res, b"pong");
        });
    }

    #[test]
    fn test_direct_dial_domain_localhost_success() {
        run_async(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();

            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.write_all(b"ok").await.unwrap();
            });

            let target = TargetAddr::from_domain("localhost", port).unwrap();
            let dialer = DirectDialer::new(Duration::from_secs(5));
            let mut client = dialer
                .dial(&target)
                .await
                .expect("dial localhost should succeed");

            let mut buf = [0u8; 2];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ok");
        });
    }

    #[test]
    fn test_direct_dial_connection_refused() {
        run_async(async {
            // Bind and drop to get a guaranteed unused closed port on loopback
            let port = {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                listener.local_addr().unwrap().port()
            };

            let target = TargetAddr::from_ip(Ipv4Addr::LOCALHOST, port);
            let dialer = DirectDialer::new(Duration::from_secs(2));
            let result = dialer.dial(&target).await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
        });
    }

    #[test]
    fn test_direct_dial_timeout() {
        run_async(async {
            // Zero/sub-microsecond timeout guarantees deadline expiration
            let target = TargetAddr::from_ip(Ipv4Addr::LOCALHOST, 18484);
            let dialer = DirectDialer::new(Duration::from_nanos(1));
            let result = dialer.dial(&target).await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        });
    }

    #[test]
    fn test_dial_direct_function_contract() {
        run_async(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local_addr = listener.local_addr().unwrap();

            tokio::spawn(async move {
                let _ = listener.accept().await;
            });

            let target = TargetAddr::from(local_addr);
            let stream = dial_direct(&target, Duration::from_secs(2)).await;
            assert!(stream.is_ok());
        });
    }

    #[test]
    fn test_dialer_builder_and_defaults() {
        let default_dialer = DirectDialer::default();
        assert_eq!(default_dialer.connect_timeout(), Duration::from_secs(10));

        let custom =
            DirectDialer::new(Duration::from_secs(5)).with_per_ip_timeout(Duration::from_secs(2));
        assert_eq!(custom.connect_timeout(), Duration::from_secs(5));
    }
}
