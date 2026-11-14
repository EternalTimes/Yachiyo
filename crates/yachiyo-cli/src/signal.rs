// SPDX-License-Identifier: AGPL-3.0-only

//! Signal handling and graceful drain lifecycle coordinator for Project Yachiyo CLI.
//!
//! Handles POSIX termination signals (SIGINT, SIGTERM) on Unix and Ctrl-C on non-Unix platforms,
//! notifies listener accept loops to terminate immediately, awaits draining of active connections
//! up to a 5-second deadline, and returns a process exit code indicating clean vs forced exit.

use std::process::ExitCode;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn};
use yachiyo_core::ConnectionTracker;

/// Default timeout budget for draining active connections upon termination signal.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of the graceful shutdown and drain sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// All active connections drained cleanly to 0 within timeout budget.
    Clean,
    /// Timeout expired while active connections remained; remaining connections forcefully aborted.
    ForcedTimeout {
        /// Number of connections that were active when timeout expired.
        remaining: usize,
    },
}

impl ShutdownOutcome {
    /// Maps the shutdown outcome to a standard process `ExitCode`.
    ///
    /// - `ExitCode::SUCCESS` (0) for clean drain.
    /// - `ExitCode::FAILURE` (1) for forced timeout.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Clean => ExitCode::SUCCESS,
            Self::ForcedTimeout { .. } => ExitCode::FAILURE,
        }
    }

    /// Returns `true` if all connections drained cleanly.
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }

    /// Returns the number of connections remaining at timeout (0 if clean).
    pub fn remaining_count(&self) -> usize {
        match self {
            Self::Clean => 0,
            Self::ForcedTimeout { remaining } => *remaining,
        }
    }
}

/// Awaits an OS termination signal.
///
/// On Unix (macOS, Linux), listens concurrently for `SIGINT` (Ctrl-C) and `SIGTERM`.
/// On non-Unix platforms, falls back to `tokio::signal::ctrl_c()`.
///
/// Returns the name of the caught signal upon success.
#[cfg(unix)]
pub async fn wait_for_signal() -> std::io::Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            res?;
            Ok("SIGINT")
        }
        _ = sigterm.recv() => {
            Ok("SIGTERM")
        }
    }
}

/// Awaits an OS termination signal on non-Unix platforms.
#[cfg(not(unix))]
pub async fn wait_for_signal() -> std::io::Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("Ctrl-C")
}

/// Coordinates the connection drain sequence after a termination signal has been received.
///
/// Steps:
/// 1. Logs: `"Received termination signal, stopping listener and draining connections..."`.
/// 2. Sends `true` through `shutdown_tx` to stop all inbound listener accept loops immediately.
/// 3. Awaits active connection drain via `tracker.wait_drained(drain_timeout)`.
/// 4. Logs clean exit or forced timeout message and returns `ShutdownOutcome`.
pub async fn drain_connections(
    shutdown_tx: &watch::Sender<bool>,
    tracker: &ConnectionTracker,
    drain_timeout: Duration,
) -> ShutdownOutcome {
    info!("Received termination signal, stopping listener and draining connections...");

    // 1. Notify inbound listeners to cease accepting new connections immediately
    let _ = shutdown_tx.send(true);

    // 2. Await drain of in-flight connections up to the specified timeout
    match tracker.wait_drained(drain_timeout).await {
        Ok(()) => {
            info!("All connections drained cleanly. Exiting.");
            ShutdownOutcome::Clean
        }
        Err(remaining) => {
            warn!(
                "Drain timeout reached, {} active connection(s) forcefully aborted.",
                remaining
            );
            ShutdownOutcome::ForcedTimeout { remaining }
        }
    }
}

/// High-level lifecycle coordinator combining signal reception and connection drain.
///
/// Waits for an OS termination signal, executes the drain sequence, and returns
/// the resulting process `ExitCode`.
pub async fn wait_for_signal_and_drain(
    shutdown_tx: &watch::Sender<bool>,
    tracker: &ConnectionTracker,
    drain_timeout: Duration,
) -> ExitCode {
    if let Err(e) = wait_for_signal().await {
        error!(error = %e, "failed to register or listen for termination signal; aborting accept loops");
        let _ = shutdown_tx.send(true);
        return ExitCode::FAILURE;
    }

    drain_connections(shutdown_tx, tracker, drain_timeout)
        .await
        .exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::watch;
    use yachiyo_core::ConnectionTracker;

    fn run_async<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn test_shutdown_outcome_exit_codes() {
        let clean = ShutdownOutcome::Clean;
        assert!(clean.is_clean());
        assert_eq!(clean.remaining_count(), 0);
        assert_eq!(clean.exit_code(), ExitCode::SUCCESS);

        let forced = ShutdownOutcome::ForcedTimeout { remaining: 3 };
        assert!(!forced.is_clean());
        assert_eq!(forced.remaining_count(), 3);
        assert_eq!(forced.exit_code(), ExitCode::FAILURE);
    }

    #[test]
    fn test_drain_already_empty_returns_clean() {
        run_async(async {
            let (tx, rx) = watch::channel(false);
            let tracker = ConnectionTracker::new(10);

            let outcome = drain_connections(&tx, &tracker, Duration::from_millis(100)).await;

            assert_eq!(outcome, ShutdownOutcome::Clean);
            assert_eq!(outcome.exit_code(), ExitCode::SUCCESS);
            assert!(
                *rx.borrow(),
                "shutdown signal must be broadcast to listeners"
            );
        });
    }

    #[test]
    fn test_drain_active_connections_clean_within_deadline() {
        run_async(async {
            let (tx, rx) = watch::channel(false);
            let tracker = ConnectionTracker::new(10);

            let g1 = tracker.try_acquire().expect("guard 1");
            let g2 = tracker.try_acquire().expect("guard 2");
            assert_eq!(tracker.active_count(), 2);

            let tracker_clone = tracker.clone();
            let drain_handle = tokio::spawn(async move {
                drain_connections(&tx, &tracker_clone, Duration::from_secs(1)).await
            });

            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(g1);
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(g2);

            let outcome = drain_handle.await.expect("join handle");
            assert_eq!(outcome, ShutdownOutcome::Clean);
            assert_eq!(outcome.exit_code(), ExitCode::SUCCESS);
            assert_eq!(tracker.active_count(), 0);
            assert!(*rx.borrow());
        });
    }

    #[test]
    fn test_drain_timeout_forced_exit() {
        run_async(async {
            let (tx, rx) = watch::channel(false);
            let tracker = ConnectionTracker::new(10);

            let _g1 = tracker.try_acquire().expect("guard 1");
            assert_eq!(tracker.active_count(), 1);

            let outcome = drain_connections(&tx, &tracker, Duration::from_millis(50)).await;

            assert_eq!(outcome, ShutdownOutcome::ForcedTimeout { remaining: 1 });
            assert_eq!(outcome.exit_code(), ExitCode::FAILURE);
            assert_eq!(tracker.active_count(), 1);
            assert!(*rx.borrow());
        });
    }

    #[test]
    #[cfg(unix)]
    fn test_signal_listener_initialization() {
        run_async(async {
            use tokio::signal::unix::{SignalKind, signal};
            let sigterm = signal(SignalKind::terminate());
            assert!(
                sigterm.is_ok(),
                "SIGTERM listener registration must succeed"
            );
            let sigint = signal(SignalKind::interrupt());
            assert!(sigint.is_ok(), "SIGINT listener registration must succeed");
        });
    }
}
