// SPDX-License-Identifier: AGPL-3.0-only

//! Yachiyo CLI library interface exposing argument parsing, signal coordination, and logging setup.

pub mod args;
pub mod logging;
pub mod reload;
pub mod signal;

pub use args::{
    ArgsError, CliArgs, DEFAULT_MIXED_ADDR, DEFAULT_MIXED_SOCKET_ADDR, ResolvedListeners,
    is_loopback_addr,
};
pub use logging::{LoggingError, build_env_filter, init_logging};
pub use reload::{ReloadBaseline, ReloadError, reload_from_file};
pub use signal::{
    DEFAULT_DRAIN_TIMEOUT, ShutdownOutcome, drain_connections, wait_for_signal,
    wait_for_signal_and_drain,
};
