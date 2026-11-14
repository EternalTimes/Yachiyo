// SPDX-License-Identifier: AGPL-3.0-only

//! # yachiyo-core
//!
//! Core types, dialers, connection tracking, and forwarding kernel for Project Yachiyo.

pub mod address;
pub mod connection;
pub mod forward;
pub mod outbound;

pub use address::{AddressParseError, TargetAddr, TargetHost};
pub use connection::{ConnectionGuard, ConnectionTracker, DEFAULT_MAX_CONNECTIONS};
pub use forward::{
    DEFAULT_BUFFER_SIZE, DEFAULT_IDLE_TIMEOUT, TransferStats, copy_bidirectional_with_idle_timeout,
};
pub use outbound::{DirectDialer, dial_direct};
