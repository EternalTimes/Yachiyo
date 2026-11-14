// SPDX-License-Identifier: AGPL-3.0-only

//! Common test harness library for Project Yachiyo E2E tests.

pub mod client;
pub mod echo;
pub mod proxy;

pub use client::{
    Socks5Reply, TargetDestination, http_connect, http_connect_with_pipeline, read_http_response,
    socks5_connect, socks5_constants, socks5_handshake_raw, socks5_send_raw_request,
    verify_bidirectional_echo,
};
#[cfg(unix)]
pub use echo::ConnectBlackhole;
pub use echo::{EchoMode, EchoServer, EchoStats};
pub use proxy::{ProxyConfig, ProxyProcess};
