// SPDX-License-Identifier: AGPL-3.0-only

//! Connection tracker for limiting concurrent connections and orchestrating graceful shutdown drain.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::watch;

/// Default maximum concurrent connections allowed by the server.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Connection tracker for limiting concurrent connections and orchestrating graceful shutdown drain.
#[derive(Debug, Clone)]
pub struct ConnectionTracker {
    inner: Arc<TrackerInner>,
}

#[derive(Debug)]
struct TrackerInner {
    limit: usize,
    active: AtomicUsize,
    drain_tx: watch::Sender<usize>,
}

/// RAII guard representing an active connection slot.
/// Decrements the active connection count on drop.
///
/// Note: Intentionally does NOT implement `Clone` to guarantee exact 1-to-1 tracking.
#[derive(Debug)]
pub struct ConnectionGuard {
    tracker: Arc<TrackerInner>,
}

impl ConnectionTracker {
    /// Creates a new `ConnectionTracker` with the specified concurrency limit.
    pub fn new(limit: usize) -> Self {
        let (drain_tx, _) = watch::channel(0);
        Self {
            inner: Arc::new(TrackerInner {
                limit,
                active: AtomicUsize::new(0),
                drain_tx,
            }),
        }
    }

    /// Returns the configured concurrency limit.
    pub fn limit(&self) -> usize {
        self.inner.limit
    }

    /// Returns the current number of active connections.
    pub fn active_count(&self) -> usize {
        self.inner.active.load(Ordering::Acquire)
    }

    /// Attempts to acquire a connection slot.
    /// Returns `Some(ConnectionGuard)` if below the limit, or `None` if the limit is reached.
    /// This operation is lock-free and non-blocking.
    pub fn try_acquire(&self) -> Option<ConnectionGuard> {
        let mut curr = self.inner.active.load(Ordering::Acquire);
        loop {
            if curr >= self.inner.limit {
                return None;
            }
            match self.inner.active.compare_exchange_weak(
                curr,
                curr + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ConnectionGuard {
                        tracker: Arc::clone(&self.inner),
                    });
                }
                Err(actual) => curr = actual,
            }
        }
    }

    /// Waits up to `timeout` for all active connections to drain to zero.
    /// Returns `Ok(())` if drained, or `Err(remaining_count)` if timed out.
    pub async fn wait_drained(&self, timeout: Duration) -> Result<(), usize> {
        if self.active_count() == 0 {
            return Ok(());
        }

        let mut rx = self.inner.drain_tx.subscribe();
        if self.active_count() == 0 {
            return Ok(());
        }

        let drain_fut = async {
            loop {
                if rx.changed().await.is_err() {
                    break;
                }
                if self.active_count() == 0 {
                    break;
                }
            }
        };

        match tokio::time::timeout(timeout, drain_fut).await {
            Ok(()) => {
                let remaining = self.active_count();
                if remaining == 0 {
                    Ok(())
                } else {
                    Err(remaining)
                }
            }
            Err(_) => Err(self.active_count()),
        }
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONNECTIONS)
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let prev = self.tracker.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "active connections counter underflow");
        if prev == 1 {
            let _ = self.tracker.drain_tx.send(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn run_async<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn test_tracker_basic_lifecycle() {
        let tracker = ConnectionTracker::new(10);
        assert_eq!(tracker.limit(), 10);
        assert_eq!(tracker.active_count(), 0);

        let g1 = tracker.try_acquire();
        assert!(g1.is_some());
        assert_eq!(tracker.active_count(), 1);

        let g2 = tracker.try_acquire();
        assert!(g2.is_some());
        assert_eq!(tracker.active_count(), 2);

        drop(g1);
        assert_eq!(tracker.active_count(), 1);

        drop(g2);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_concurrency_overflow_rejection() {
        let tracker = ConnectionTracker::new(2);
        let g1 = tracker.try_acquire().expect("guard 1");
        let g2 = tracker.try_acquire().expect("guard 2");
        assert_eq!(tracker.active_count(), 2);

        // Third connection must be rejected immediately without blocking
        let g3 = tracker.try_acquire();
        assert!(g3.is_none());
        assert_eq!(tracker.active_count(), 2);

        // Freeing a slot allows subsequent acquisition
        drop(g1);
        assert_eq!(tracker.active_count(), 1);

        let g4 = tracker.try_acquire().expect("guard 4");
        assert_eq!(tracker.active_count(), 2);

        // Rejection again
        assert!(tracker.try_acquire().is_none());

        drop(g2);
        drop(g4);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_zero_limit() {
        let tracker = ConnectionTracker::new(0);
        assert_eq!(tracker.limit(), 0);
        assert_eq!(tracker.active_count(), 0);
        assert!(tracker.try_acquire().is_none());
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_default_limit_1024() {
        let tracker = ConnectionTracker::default();
        assert_eq!(tracker.limit(), 1024);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_drain_already_empty() {
        run_async(async {
            let tracker = ConnectionTracker::new(5);
            let res = tracker.wait_drained(Duration::from_millis(50)).await;
            assert_eq!(res, Ok(()));
        });
    }

    #[test]
    fn test_drain_notification_success() {
        run_async(async {
            let tracker = ConnectionTracker::new(5);
            let g1 = tracker.try_acquire().unwrap();
            let g2 = tracker.try_acquire().unwrap();
            assert_eq!(tracker.active_count(), 2);

            let tracker_clone = tracker.clone();
            let drain_handle =
                tokio::spawn(
                    async move { tracker_clone.wait_drained(Duration::from_secs(1)).await },
                );

            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(g1);
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(g2);

            let result = drain_handle.await.expect("join handle");
            assert_eq!(result, Ok(()));
            assert_eq!(tracker.active_count(), 0);
        });
    }

    #[test]
    fn test_drain_timeout() {
        run_async(async {
            let tracker = ConnectionTracker::new(5);
            let _g1 = tracker.try_acquire().unwrap();
            assert_eq!(tracker.active_count(), 1);

            // Drain with short timeout while guard is still held
            let res = tracker.wait_drained(Duration::from_millis(50)).await;
            assert_eq!(res, Err(1));
            assert_eq!(tracker.active_count(), 1);
        });
    }

    #[test]
    fn test_multithreaded_concurrency_stress() {
        run_async(async {
            let tracker = ConnectionTracker::new(10);
            let mut handles = Vec::new();

            for _ in 0..50 {
                let t = tracker.clone();
                handles.push(tokio::spawn(async move {
                    for _ in 0..100 {
                        if let Some(guard) = t.try_acquire() {
                            assert!(t.active_count() <= 10);
                            tokio::task::yield_now().await;
                            drop(guard);
                        }
                    }
                }));
            }

            for h in handles {
                h.await.unwrap();
            }

            assert_eq!(tracker.active_count(), 0);
            assert_eq!(
                tracker.wait_drained(Duration::from_millis(50)).await,
                Ok(())
            );
        });
    }
}
