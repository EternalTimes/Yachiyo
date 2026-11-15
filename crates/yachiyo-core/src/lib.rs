// SPDX-License-Identifier: AGPL-3.0-only

//! # yachiyo-core
//!
//! Core types, dialers, connection tracking, and forwarding kernel for Project Yachiyo.

pub mod address;
pub mod config;
pub mod connection;
pub mod context;
pub mod forward;
pub mod outbound;
pub mod rule;
pub mod socks5_outbound;

pub use address::{AddressParseError, TargetAddr, TargetHost};
pub use config::{CURRENT_SCHEMA_VERSION, Config, ConfigError, is_loopback_socket_addr};
pub use connection::{ConnectionGuard, ConnectionTracker, DEFAULT_MAX_CONNECTIONS};
pub use context::{ConnMetadata, InboundKind, Network};
pub use forward::{
    DEFAULT_BUFFER_SIZE, DEFAULT_IDLE_TIMEOUT, TransferStats, copy_bidirectional_with_idle_timeout,
};
pub use outbound::{DirectDialer, dial_direct};
pub use rule::{IpCidr, Policy, Rule, RuleError, RuleMatch, RuleSet};
pub use socks5_outbound::{
    OutboundRegistry, OutboundTarget, Socks5Auth, Socks5Dialer, Socks5OutboundConfig,
};
