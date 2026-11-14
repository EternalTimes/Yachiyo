// SPDX-License-Identifier: AGPL-3.0-only

//! # yachiyo-inbound
//!
//! Inbound connection handling, protocol sniffing, SOCKS5 and HTTP CONNECT proxies.

pub mod http;
pub mod listener;
pub mod sniffer;
pub mod socks5;

pub use http::{
    HttpConnectRequest, HttpParseError, HttpVersion, MAX_HEADER_SIZE, handle_http_connection,
    parse_http_connect_request, read_http_connect_request,
};
pub use listener::{InboundConfig, InboundListener, ListenerKind, run_server};
pub use sniffer::{InboundProtocol, Protocol, SniffError, identify_protocol, sniff_protocol};
pub use socks5::{
    RepCode, Socks5Error, encode_reply, handle_handshake, negotiate_auth, parse_connect_request,
    write_reply, write_reply_for_io_error,
};
