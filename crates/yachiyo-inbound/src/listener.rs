// SPDX-License-Identifier: AGPL-3.0-only

//! Inbound multi-listener orchestrator, concurrency limiter (1024), and connection lifecycle manager.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use yachiyo_core::{
    ConnMetadata, ConnectionGuard, ConnectionTracker, InboundKind, Network, OutboundRegistry,
    OutboundTarget, Policy, RuleSet, Socks5Dialer, TargetAddr,
    copy_bidirectional_with_idle_timeout, dial_direct,
};

use crate::http::{self, HttpParseError};
use crate::sniffer::{self, Protocol, SniffError};
use crate::socks5::{self, Socks5Error};

/// Internal error during inbound handshake phase.
#[derive(Debug, thiserror::Error)]
enum HandshakeError {
    #[error("sniff error: {0}")]
    Sniff(#[from] SniffError),
    #[error("socks5 error: {0}")]
    Socks5(#[from] Socks5Error),
    #[error("http error: {0}")]
    Http(#[from] HttpParseError),
}

/// Inbound server configuration.
#[derive(Debug, Clone)]
pub struct InboundConfig {
    /// Mixed endpoint address (demuxes SOCKS5 vs HTTP CONNECT by first byte).
    pub mixed_addr: Option<SocketAddr>,
    /// Dedicated SOCKS5 endpoint address.
    pub socks_addr: Option<SocketAddr>,
    /// Dedicated HTTP CONNECT endpoint address.
    pub http_addr: Option<SocketAddr>,
    /// Inbound handshake timeout budget (10 seconds default).
    pub handshake_timeout: Duration,
    /// Outbound direct connect timeout budget (10 seconds default).
    pub connect_timeout: Duration,
    /// Bidirectional forwarding idle timeout (300 seconds default).
    pub idle_timeout: Duration,
    /// Ordered rule set for connection policy evaluation.
    pub rules: Arc<RuleSet>,
    /// Named outbound registry (e.g. SOCKS5 upstream nodes).
    pub outbounds: Arc<OutboundRegistry>,
    /// Configuration generation active for this listener.
    pub config_generation: u64,
}

impl Default for InboundConfig {
    fn default() -> Self {
        Self {
            mixed_addr: Some(SocketAddr::from(([127, 0, 0, 1], 18484))),
            socks_addr: None,
            http_addr: None,
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            rules: Arc::new(RuleSet::default_direct()),
            outbounds: Arc::new(OutboundRegistry::new()),
            config_generation: 0,
        }
    }
}

/// Distinguishes the protocol handling mode of an accepted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    /// Mixed mode demultiplexing by first byte.
    Mixed,
    /// Dedicated SOCKS5 mode.
    Socks5,
    /// Dedicated HTTP CONNECT mode.
    Http,
}

/// Helper future that polls two futures simultaneously without requiring macros or external crates.
struct EitherFuture<F1, F2> {
    f1: F1,
    f2: F2,
}

impl<F1, F2, T1, T2> Future for EitherFuture<F1, F2>
where
    F1: Future<Output = T1> + Unpin,
    F2: Future<Output = T2> + Unpin,
{
    type Output = Result<T1, T2>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Poll::Ready(val) = Pin::new(&mut self.f1).poll(cx) {
            return Poll::Ready(Ok(val));
        }
        if let Poll::Ready(val) = Pin::new(&mut self.f2).poll(cx) {
            return Poll::Ready(Err(val));
        }
        Poll::Pending
    }
}

/// Inbound listener engine holding bound sockets.
#[derive(Debug)]
pub struct InboundListener {
    listeners: Vec<(ListenerKind, TcpListener)>,
    config: InboundConfig,
    tracker: ConnectionTracker,
}

impl InboundListener {
    /// Binds all configured socket addresses.
    ///
    /// Fails immediately if any address cannot be bound, or if no addresses were configured.
    pub async fn bind(
        config: InboundConfig,
        tracker: ConnectionTracker,
    ) -> Result<Self, std::io::Error> {
        let mut listeners = Vec::new();

        if let Some(addr) = config.mixed_addr {
            let listener = TcpListener::bind(addr).await?;
            info!(kind = ?ListenerKind::Mixed, addr = %listener.local_addr()?, "bound inbound listener");
            listeners.push((ListenerKind::Mixed, listener));
        }

        if let Some(addr) = config.socks_addr {
            let listener = TcpListener::bind(addr).await?;
            info!(kind = ?ListenerKind::Socks5, addr = %listener.local_addr()?, "bound inbound listener");
            listeners.push((ListenerKind::Socks5, listener));
        }

        if let Some(addr) = config.http_addr {
            let listener = TcpListener::bind(addr).await?;
            info!(kind = ?ListenerKind::Http, addr = %listener.local_addr()?, "bound inbound listener");
            listeners.push((ListenerKind::Http, listener));
        }

        if listeners.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no inbound listener addresses configured",
            ));
        }

        Ok(Self {
            listeners,
            config,
            tracker,
        })
    }

    /// Returns the local addresses of all active listeners.
    pub fn local_addrs(&self) -> Vec<(ListenerKind, SocketAddr)> {
        self.listeners
            .iter()
            .filter_map(|(kind, l)| l.local_addr().ok().map(|addr| (*kind, addr)))
            .collect()
    }

    /// Runs all listener accept loops until `shutdown_rx` receives `true`.
    pub async fn run(self, shutdown_rx: watch::Receiver<bool>) -> Result<(), std::io::Error> {
        let mut join_set = JoinSet::new();

        for (kind, listener) in self.listeners {
            let rx = shutdown_rx.clone();
            let config = self.config.clone();
            let tracker = self.tracker.clone();

            join_set.spawn(async move {
                accept_loop(kind, listener, config, tracker, rx).await;
            });
        }

        // Wait for all accept loops to terminate (triggered by shutdown_rx)
        while let Some(res) = join_set.join_next().await {
            if let Err(e) = res {
                error!(error = %e, "listener task panicked or was cancelled");
            }
        }

        info!("all inbound listener accept loops terminated");
        Ok(())
    }
}

/// Accept loop for a single listener socket.
async fn accept_loop(
    kind: ListenerKind,
    listener: TcpListener,
    config: InboundConfig,
    tracker: ConnectionTracker,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        // Fast-path: check if shutdown was already triggered
        if *shutdown_rx.borrow() {
            debug!(kind = ?kind, "shutdown signal detected, exiting accept loop");
            break;
        }

        let select_res = {
            let accept_fut = std::pin::pin!(listener.accept());
            let changed_fut = std::pin::pin!(shutdown_rx.changed());
            let select_fut = EitherFuture {
                f1: accept_fut,
                f2: changed_fut,
            };
            select_fut.await
        };

        match select_res {
            Ok(Ok((stream, peer_addr))) => {
                // Concurrency Limit Check: non-blocking attempt to acquire slot
                let guard = match tracker.try_acquire() {
                    Some(g) => g,
                    None => {
                        warn!(
                            kind = ?kind,
                            peer = %peer_addr,
                            limit = tracker.limit(),
                            active = tracker.active_count(),
                            "connection limit exceeded, immediately rejecting incoming connection"
                        );
                        // Dropping stream immediately closes the socket without stalling loop
                        drop(stream);
                        continue;
                    }
                };

                let conn_config = config.clone();
                tokio::spawn(async move {
                    handle_inbound_connection(kind, stream, peer_addr, conn_config, guard).await;
                });
            }
            Ok(Err(e)) => {
                warn!(kind = ?kind, error = %e, "failed to accept TCP connection");
            }
            Err(_) => {
                // shutdown_rx.changed() fired
                if *shutdown_rx.borrow() {
                    debug!(kind = ?kind, "shutdown signal received, closing listener");
                    break;
                }
            }
        }
    }
}

/// Helper function to execute the protocol handshake and target parsing.
async fn perform_handshake(
    kind: ListenerKind,
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    config: &InboundConfig,
) -> Result<Option<(Protocol, TargetAddr, Option<Vec<u8>>)>, HandshakeError> {
    let protocol = match kind {
        ListenerKind::Socks5 => Protocol::Socks5,
        ListenerKind::Http => Protocol::HttpConnect,
        ListenerKind::Mixed => {
            match sniffer::sniff_protocol(stream, config.handshake_timeout).await? {
                Protocol::CleanClose => {
                    debug!(peer = %peer_addr, "clean EOF / health probe on mixed port");
                    return Ok(None);
                }
                proto => proto,
            }
        }
    };

    match protocol {
        Protocol::Socks5 => {
            let target = socks5::handshake_and_parse(stream).await?;
            Ok(Some((protocol, target, None)))
        }
        Protocol::HttpConnect => {
            let req = http::handshake_and_parse(stream).await?;
            let initial = if req.pipelined_payload.is_empty() {
                None
            } else {
                Some(req.pipelined_payload)
            };
            Ok(Some((protocol, req.target, initial)))
        }
        Protocol::CleanClose => Ok(None),
    }
}

/// Orchestrates the 4-phase lifecycle of an accepted connection.
async fn handle_inbound_connection(
    kind: ListenerKind,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    config: InboundConfig,
    _guard: ConnectionGuard,
) {
    // Phase 1: Inbound Handshake & Target Extraction (bounded by handshake_timeout)
    let handshake_fut = perform_handshake(kind, &mut stream, peer_addr, &config);

    let (protocol, target, initial_data) = match tokio::time::timeout(
        config.handshake_timeout,
        handshake_fut,
    )
    .await
    {
        Ok(Ok(Some(triplet))) => triplet,
        Ok(Ok(None)) => return, // Clean health probe EOF without error
        Ok(Err(e)) => {
            debug!(peer = %peer_addr, error = %e, "handshake parsing failed or connection aborted");
            return;
        }
        Err(_) => {
            warn!(peer = %peer_addr, timeout_secs = config.handshake_timeout.as_secs(), "handshake timed out");
            return;
        }
    };

    // Phase 2: Build Connection Metadata & Evaluate Rules
    let inbound_kind = match kind {
        ListenerKind::Mixed => InboundKind::Mixed,
        ListenerKind::Socks5 => InboundKind::Socks5,
        ListenerKind::Http => InboundKind::Http,
    };
    let meta = ConnMetadata::new(
        inbound_kind,
        Network::Tcp,
        target.clone(),
        peer_addr,
        config.config_generation,
    );

    let rule_match = config.rules.evaluate(&meta.target).await;
    info!(
        conn_id = meta.conn_id,
        target = %meta.target,
        protocol = ?protocol,
        peer = %meta.peer_addr,
        policy = %rule_match.policy,
        rule = %rule_match.matched_rule,
        "rule evaluated"
    );

    let dial_res = match &rule_match.policy {
        Policy::Reject => {
            match protocol {
                Protocol::Socks5 => {
                    let _ = socks5::send_rule_rejected_reply(&mut stream).await;
                }
                Protocol::HttpConnect => {
                    let _ = http::send_rule_rejected_reply(&mut stream).await;
                }
                Protocol::CleanClose => {}
            }
            return;
        }
        Policy::Direct => dial_direct(&meta.target, config.connect_timeout).await,
        Policy::Outbound(name) => match config.outbounds.get(name) {
            Some(OutboundTarget::Direct) => dial_direct(&meta.target, config.connect_timeout).await,
            Some(OutboundTarget::Reject) => {
                match protocol {
                    Protocol::Socks5 => {
                        let _ = socks5::send_rule_rejected_reply(&mut stream).await;
                    }
                    Protocol::HttpConnect => {
                        let _ = http::send_rule_rejected_reply(&mut stream).await;
                    }
                    Protocol::CleanClose => {}
                }
                return;
            }
            Some(OutboundTarget::Socks5(cfg)) => {
                Socks5Dialer::dial(cfg, &meta.target, config.connect_timeout).await
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("undefined outbound policy '{name}'"),
            )),
        },
    };

    let outbound = match dial_res {
        Ok(outbound) => outbound,
        Err(e) => {
            warn!(target = %target, error = %e, "outbound dial failed");
            // Transmit protocol-appropriate error reply before closing
            match protocol {
                Protocol::Socks5 => {
                    let _ = socks5::send_error_reply(&mut stream, &e).await;
                }
                Protocol::HttpConnect => {
                    let _ = http::send_error_reply(&mut stream, &e).await;
                }
                Protocol::CleanClose => {}
            }
            return;
        }
    };

    // Phase 3: Protocol Success Reply
    let reply_res = match protocol {
        Protocol::Socks5 => socks5::send_success_reply(&mut stream).await,
        Protocol::HttpConnect => http::send_success_reply(&mut stream).await,
        Protocol::CleanClose => Ok(()),
    };

    if let Err(e) = reply_res {
        warn!(target = %target, error = %e, "failed to send protocol success response to client");
        return;
    }

    // Phase 4: Full-Duplex Forwarding with TCP Half-Close and 300s Idle Timeout
    match copy_bidirectional_with_idle_timeout(
        stream,
        outbound,
        config.idle_timeout,
        initial_data.as_deref(),
    )
    .await
    {
        Ok(stats) => {
            info!(
                target = %target,
                client_to_remote = stats.client_to_remote,
                remote_to_client = stats.remote_to_client,
                "tunnel closed cleanly"
            );
        }
        Err(e) => {
            debug!(target = %target, error = %e, "tunnel closed with error or idle timeout");
        }
    }
}

/// Convenience runner function matching the orchestrator interface contract.
pub async fn run_server(
    config: InboundConfig,
    tracker: ConnectionTracker,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    let listener = InboundListener::bind(config, tracker).await?;
    listener.run(shutdown_rx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    fn run_async<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn test_inbound_config_defaults() {
        let config = InboundConfig::default();
        assert_eq!(
            config.mixed_addr,
            Some(SocketAddr::from(([127, 0, 0, 1], 18484)))
        );
        assert_eq!(config.socks_addr, None);
        assert_eq!(config.http_addr, None);
        assert_eq!(config.handshake_timeout, Duration::from_secs(10));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.idle_timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_inbound_listener_empty_config_fails() {
        run_async(async {
            let config = InboundConfig {
                mixed_addr: None,
                socks_addr: None,
                http_addr: None,
                ..Default::default()
            };
            let tracker = ConnectionTracker::new(10);
            let res = InboundListener::bind(config, tracker).await;
            assert!(res.is_err());
            assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn test_inbound_listener_bind_dynamic_ports() {
        run_async(async {
            let config = InboundConfig {
                mixed_addr: Some("127.0.0.1:0".parse().unwrap()),
                socks_addr: Some("127.0.0.1:0".parse().unwrap()),
                http_addr: Some("127.0.0.1:0".parse().unwrap()),
                ..Default::default()
            };
            let tracker = ConnectionTracker::new(10);
            let listener = InboundListener::bind(config, tracker).await.unwrap();
            let addrs = listener.local_addrs();
            assert_eq!(addrs.len(), 3);
            for (_, addr) in addrs {
                assert_ne!(addr.port(), 0);
            }
        });
    }

    #[test]
    fn test_concurrency_limit_immediate_rejection() {
        run_async(async {
            let tracker = ConnectionTracker::new(1); // Limit of 1
            let config = InboundConfig {
                mixed_addr: Some("127.0.0.1:0".parse().unwrap()),
                socks_addr: None,
                http_addr: None,
                ..Default::default()
            };

            let listener = InboundListener::bind(config, tracker.clone())
                .await
                .unwrap();
            let mixed_addr = listener.local_addrs()[0].1;

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let server_handle = tokio::spawn(async move {
                listener.run(shutdown_rx).await.unwrap();
            });

            // Connect client 1: acquire the sole guard
            let _c1 = TcpStream::connect(mixed_addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(tracker.active_count(), 1);

            // Connect client 2: limit exceeded -> rejected and dropped immediately
            let mut c2 = TcpStream::connect(mixed_addr).await.unwrap();
            let mut buf = [0u8; 1];
            // Since server drops c2 immediately, reading should return EOF (0 bytes) or error
            let read_res = c2.read(&mut buf).await;
            assert!(matches!(read_res, Ok(0) | Err(_)));

            // Server active count remains 1
            assert_eq!(tracker.active_count(), 1);

            shutdown_tx.send(true).unwrap();
            server_handle.await.unwrap();
        });
    }

    #[test]
    fn test_graceful_shutdown_stops_accept_loop() {
        run_async(async {
            let config = InboundConfig {
                mixed_addr: Some("127.0.0.1:0".parse().unwrap()),
                socks_addr: None,
                http_addr: None,
                ..Default::default()
            };
            let tracker = ConnectionTracker::new(10);
            let listener = InboundListener::bind(config, tracker).await.unwrap();

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let handle = tokio::spawn(async move {
                listener.run(shutdown_rx).await.unwrap();
            });

            // Trigger shutdown
            tokio::time::sleep(Duration::from_millis(20)).await;
            shutdown_tx.send(true).unwrap();

            // Accept loop should terminate promptly
            let res = tokio::time::timeout(Duration::from_secs(1), handle).await;
            assert!(res.is_ok());
        });
    }
}
