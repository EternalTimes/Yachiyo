// SPDX-License-Identifier: AGPL-3.0-only

//! Atomic configuration snapshot reload on SIGHUP.
//!
//! Validates the new configuration file completely before committing a new [`RuntimeSnapshot`].
//! Any parse/semantic error or change to restart-required fields (`listeners`, `limits.max_connections`)
//! leaves the active snapshot untouched.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info, warn};
use yachiyo_core::{Config, ConfigError, DiagnosticsTracker, OutboundRegistry};
use yachiyo_inbound::RuntimeSnapshot;

use crate::args::RuntimeConfig;

/// Startup-immutable fields that cannot be atomically switched on live listeners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadBaseline {
    pub mixed_addr: Option<SocketAddr>,
    pub socks_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
    pub max_connections: usize,
    pub log_level: String,
}

impl From<&RuntimeConfig> for ReloadBaseline {
    fn from(rt: &RuntimeConfig) -> Self {
        Self {
            mixed_addr: rt.inbound.mixed_addr,
            socks_addr: rt.inbound.socks_addr,
            http_addr: rt.inbound.http_addr,
            max_connections: rt.max_connections,
            log_level: rt.log_level.clone(),
        }
    }
}

/// Errors returned when attempting to reload a configuration snapshot.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("configuration validation failed: {0}")]
    Config(#[from] ConfigError),

    #[error("field '{field}' cannot be hot-reloaded and requires a process restart")]
    RestartRequired { field: &'static str },

    #[error("snapshot channel closed")]
    ChannelClosed,
}

/// Loads, validates, and atomically publishes a new [`RuntimeSnapshot`] from `path`.
///
/// On any validation failure or restart-required field change, the active snapshot
/// in `snapshot_tx` is preserved unchanged.
pub fn reload_from_file(
    path: &Path,
    baseline: &ReloadBaseline,
    snapshot_tx: &watch::Sender<Arc<RuntimeSnapshot>>,
) -> Result<u64, ReloadError> {
    let cfg = Config::from_file(path)?;

    if cfg.listeners.mixed != baseline.mixed_addr
        || cfg.listeners.socks != baseline.socks_addr
        || cfg.listeners.http != baseline.http_addr
    {
        return Err(ReloadError::RestartRequired { field: "listeners" });
    }

    if cfg.limits.max_connections != baseline.max_connections {
        return Err(ReloadError::RestartRequired {
            field: "limits.max_connections",
        });
    }

    if cfg.logging.level != baseline.log_level {
        warn!(
            active = %baseline.log_level,
            requested = %cfg.logging.level,
            "logging.level change requires restart; keeping active log filter"
        );
    }

    let next_generation = snapshot_tx.borrow().config_generation + 1;
    let next_snapshot = Arc::new(RuntimeSnapshot {
        handshake_timeout: cfg.timeouts.handshake,
        connect_timeout: cfg.timeouts.connect,
        idle_timeout: cfg.timeouts.idle,
        rules: Arc::new(cfg.rules),
        outbounds: Arc::new(cfg.outbounds),
        config_generation: next_generation,
    });

    snapshot_tx
        .send(next_snapshot)
        .map_err(|_| ReloadError::ChannelClosed)?;

    Ok(next_generation)
}

/// RAII handle owning background health-check tasks for a single configuration generation.
///
/// Dropping or replacing this guard signals all health-check loops of the previous
/// generation to stop immediately, preventing task accumulation across repeated SIGHUP reloads.
#[derive(Debug)]
pub struct HealthCheckGuard {
    stop_tx: Option<watch::Sender<bool>>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl HealthCheckGuard {
    /// Signals all generation health-check tasks to stop and awaits their completion.
    #[allow(dead_code)]
    pub async fn stop_and_join(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        for handle in self.handles.drain(..) {
            let _ = handle.await;
        }
    }
}

impl Drop for HealthCheckGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
    }
}

/// Spawns health-check tasks for `outbounds` scoped to both `shutdown_rx` and the returned [`HealthCheckGuard`].
pub fn spawn_generation_health_checks(
    outbounds: &Arc<OutboundRegistry>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> HealthCheckGuard {
    let (hc_tx, hc_rx) = watch::channel(*shutdown_rx.borrow());
    let handles = outbounds.spawn_health_checks(hc_rx);
    if handles.is_empty() {
        return HealthCheckGuard {
            stop_tx: None,
            handles,
        };
    }

    let (gen_stop_tx, mut gen_stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        if *shutdown_rx.borrow() {
            let _ = hc_tx.send(true);
            return;
        }
        loop {
            tokio::select! {
                res = gen_stop_rx.changed() => {
                    if res.is_err() || *gen_stop_rx.borrow() {
                        let _ = hc_tx.send(true);
                        break;
                    }
                }
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        let _ = hc_tx.send(true);
                        break;
                    }
                }
            }
        }
    });

    HealthCheckGuard {
        stop_tx: Some(gen_stop_tx),
        handles,
    }
}

/// Spawns a background SIGHUP listener that reloads `config_path` until `shutdown_rx` becomes `true`.
#[cfg(unix)]
pub fn spawn_sighup_reloader(
    config_path: std::path::PathBuf,
    baseline: ReloadBaseline,
    snapshot_tx: watch::Sender<Arc<RuntimeSnapshot>>,
    diagnostics: Arc<DiagnosticsTracker>,
    mut active_hc_guard: HealthCheckGuard,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    use tokio::signal::unix::{SignalKind, signal};

    tokio::spawn(async move {
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(err) => {
                error!(error = %err, "failed to register SIGHUP handler for config reload");
                return;
            }
        };

        loop {
            tokio::select! {
                _ = sighup.recv() => {
                    match reload_from_file(&config_path, &baseline, &snapshot_tx) {
                        Ok(generation) => {
                            diagnostics.set_config_generation(generation);
                            let current_outbounds = Arc::clone(&snapshot_tx.borrow().outbounds);
                            drop(active_hc_guard);
                            active_hc_guard = spawn_generation_health_checks(
                                &current_outbounds,
                                shutdown_rx.clone(),
                            );
                            info!(
                                generation = generation,
                                path = %config_path.display(),
                                "configuration snapshot reloaded"
                            );
                        }
                        Err(err) => {
                            error!(
                                error = %err,
                                path = %config_path.display(),
                                "configuration reload failed; preserving active snapshot"
                            );
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use yachiyo_core::{Policy, RuleSet, TargetAddr};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TempYamlFile {
        path: PathBuf,
    }

    impl TempYamlFile {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempYamlFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn write_temp_yaml(content: &str) -> TempYamlFile {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "yachiyo-reload-test-{}-{id}.yaml",
            std::process::id()
        ));
        std::fs::write(&path, content.as_bytes()).unwrap();
        TempYamlFile { path }
    }

    fn initial_snapshot_and_baseline() -> (
        ReloadBaseline,
        watch::Sender<Arc<RuntimeSnapshot>>,
        watch::Receiver<Arc<RuntimeSnapshot>>,
    ) {
        let baseline = ReloadBaseline {
            mixed_addr: Some("127.0.0.1:18484".parse().unwrap()),
            socks_addr: None,
            http_addr: None,
            max_connections: 1024,
            log_level: "info".to_string(),
        };
        let initial = Arc::new(RuntimeSnapshot {
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            rules: Arc::new(RuleSet::default_direct()),
            outbounds: Arc::new(Default::default()),
            config_generation: 1,
        });
        let (tx, rx) = watch::channel(initial);
        (baseline, tx, rx)
    }

    #[tokio::test]
    async fn test_reload_valid_updates_snapshot_and_preserves_old_arc() {
        let (baseline, tx, _rx) = initial_snapshot_and_baseline();
        let captured_old = tx.borrow().clone();

        let file = write_temp_yaml(
            r#"
schema_version: 1
listeners:
  mixed: 127.0.0.1:18484
timeouts:
  handshake_secs: 5
  connect_secs: 7
  idle_secs: 120
rules:
  - DOMAIN,blocked.example.com,REJECT
  - MATCH,DIRECT
"#,
        );

        let generation = reload_from_file(file.path(), &baseline, &tx).unwrap();
        assert_eq!(generation, 2);

        let current = tx.borrow().clone();
        assert_eq!(current.config_generation, 2);
        assert_eq!(current.handshake_timeout, Duration::from_secs(5));
        assert_eq!(current.connect_timeout, Duration::from_secs(7));
        assert_eq!(current.idle_timeout, Duration::from_secs(120));

        let blocked_target: TargetAddr = "blocked.example.com:443".parse().unwrap();
        assert_eq!(
            current.rules.evaluate(&blocked_target).await.policy,
            Policy::Reject
        );
        // Old captured snapshot still sees generation 1 and DIRECT
        assert_eq!(captured_old.config_generation, 1);
        assert_eq!(
            captured_old.rules.evaluate(&blocked_target).await.policy,
            Policy::Direct
        );
    }

    #[tokio::test]
    async fn test_reload_invalid_config_preserves_active_snapshot() {
        let (baseline, tx, _rx) = initial_snapshot_and_baseline();
        let file = write_temp_yaml(
            r#"
schema_version: 1
rules:
  - DOMAIN,app.example.com,missing_outbound
  - MATCH,DIRECT
"#,
        );

        let err = reload_from_file(file.path(), &baseline, &tx).unwrap_err();
        assert!(matches!(
            err,
            ReloadError::Config(ConfigError::UnknownOutboundReference { .. })
        ));
        assert_eq!(tx.borrow().config_generation, 1);
    }

    #[tokio::test]
    async fn test_reload_restart_required_field_preserves_active_snapshot() {
        let (baseline, tx, _rx) = initial_snapshot_and_baseline();
        let file = write_temp_yaml(
            r#"
schema_version: 1
listeners:
  mixed: 127.0.0.1:18485
rules:
  - MATCH,DIRECT
"#,
        );

        let err = reload_from_file(file.path(), &baseline, &tx).unwrap_err();
        assert!(matches!(
            err,
            ReloadError::RestartRequired { field: "listeners" }
        ));
        assert_eq!(tx.borrow().config_generation, 1);
    }

    #[tokio::test]
    async fn test_health_check_guard_cancels_previous_generation_tasks() {
        let cfg = Config::from_yaml_str(
            r#"
schema_version: 1
outbounds:
  auto_group:
    type: url-test
    outbounds:
      - DIRECT
    url: http://127.0.0.1:1/generate_204
    interval_secs: 60
    timeout_secs: 1
rules:
  - MATCH,auto_group
"#,
        )
        .unwrap();

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let outbounds_arc = Arc::new(cfg.outbounds);
        let guard = spawn_generation_health_checks(&outbounds_arc, shutdown_rx);
        assert_eq!(guard.handles.len(), 1);

        // Stopping/dropping the generation guard must terminate its health-check loop cleanly
        // even while process-wide shutdown_rx remains false.
        tokio::time::timeout(Duration::from_secs(2), guard.stop_and_join())
            .await
            .expect("previous generation health-check task should stop promptly on reload");
    }
}
