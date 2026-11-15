// SPDX-License-Identifier: AGPL-3.0-only

//! Connection metadata and session context contracts.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::address::TargetAddr;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Inbound listener kind that accepted a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    Mixed,
    Socks5,
    Http,
}

/// Transport network type for a connection or datagram session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
}

/// Immutable per-connection metadata established after inbound handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnMetadata {
    /// Monotonic connection identifier for structured logging and tracing.
    pub conn_id: u64,
    /// Inbound listener kind.
    pub inbound: InboundKind,
    /// Transport network type.
    pub network: Network,
    /// Target destination (preserving original domain if provided).
    pub target: TargetAddr,
    /// Remote peer socket address.
    pub peer_addr: SocketAddr,
    /// Configuration generation active when this connection was accepted.
    pub config_generation: u64,
}

impl ConnMetadata {
    /// Creates a new `ConnMetadata` with a freshly allocated monotonic `conn_id`.
    pub fn new(
        inbound: InboundKind,
        network: Network,
        target: TargetAddr,
        peer_addr: SocketAddr,
        config_generation: u64,
    ) -> Self {
        Self {
            conn_id: NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed),
            inbound,
            network,
            target,
            peer_addr,
            config_generation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::TargetHost;

    #[test]
    fn test_conn_id_is_monotonic() {
        let target = TargetAddr::new(TargetHost::Domain("example.com".to_string()), 443);
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let a = ConnMetadata::new(InboundKind::Mixed, Network::Tcp, target.clone(), peer, 1);
        let b = ConnMetadata::new(InboundKind::Socks5, Network::Tcp, target, peer, 1);
        assert!(b.conn_id > a.conn_id);
        assert_eq!(a.config_generation, 1);
    }
}
