// SPDX-License-Identifier: AGPL-3.0-only

//! # yachiyo-core
//!
//! Core types, dialers, connection tracking, and forwarding kernel for Project Yachiyo.

pub mod address;
pub mod config;
pub mod connection;
pub mod context;
pub mod diagnostics;
pub mod forward;
pub mod group;
pub mod outbound;
pub mod rule;
pub mod socks5_outbound;
pub mod trojan;

pub use address::{AddressParseError, TargetAddr, TargetHost};
pub use config::{CURRENT_SCHEMA_VERSION, Config, ConfigError, is_loopback_socket_addr};
pub use connection::{ConnectionGuard, ConnectionTracker, DEFAULT_MAX_CONNECTIONS};
pub use context::{ConnMetadata, InboundKind, Network};
pub use diagnostics::{
    ActiveConnGuard, ActiveConnSnapshot, DiagnosticsTracker, RuntimeStatusSnapshot,
    TrafficStatsSnapshot, escape_json, redact_credentials,
};
pub use forward::{
    DEFAULT_BUFFER_SIZE, DEFAULT_IDLE_TIMEOUT, OutboundStream, TransferStats,
    copy_bidirectional_with_idle_timeout,
};
pub use group::{
    DEFAULT_HEALTH_CHECK_INTERVAL, DEFAULT_HEALTH_CHECK_TIMEOUT, DEFAULT_HEALTH_CHECK_URL,
    DEFAULT_URL_TEST_TOLERANCE, FallbackGroup, NodeHealth, NodeHealthReport, OutboundRegistry,
    OutboundResolveError, OutboundTarget, ProbeError, ResolvedOutbound, SelectorGroup,
    UrlTestGroup, parse_http_probe_url, probe_candidate, probe_leaf,
};
pub use outbound::{DirectDialer, dial_direct};
pub use rule::{IpCidr, Policy, Rule, RuleError, RuleMatch, RuleSet};
pub use socks5_outbound::{Socks5Auth, Socks5Dialer, Socks5OutboundConfig};
pub use trojan::{
    SkipServerVerification, TrojanDialer, TrojanOutboundConfig, build_tls_client_config,
    build_tls_client_config_with_ca, encode_trojan_header, load_ca_certs_from_bytes,
    load_ca_certs_from_file, sha224_digest, sha224_hex, sha224_hex_bytes,
};
