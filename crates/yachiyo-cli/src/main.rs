// SPDX-License-Identifier: AGPL-3.0-only

//! Yachiyo CLI entrypoint, argument parsing, security pre-flight checks, and runtime lifecycle coordination.

use clap::Parser;
use std::process::ExitCode;
use std::sync::Arc;
use tracing::{error, info};
use yachiyo_core::connection::ConnectionTracker;
use yachiyo_inbound::InboundListener;

use yachiyo_cli::args::{ArgsError, CliArgs, RuntimeConfigError};
use yachiyo_cli::logging;
use yachiyo_cli::reload::{self, ReloadBaseline};
use yachiyo_cli::signal;
use yachiyo_core::ConfigError;

mod ipc;

#[tokio::main]
async fn main() -> ExitCode {
    run().await
}

/// Inner runner function allowing clean error handling and test execution.
pub async fn run() -> ExitCode {
    // 1. Parse command-line arguments via clap
    let args = CliArgs::parse();

    // 2. If a status/diagnostics query command was specified, execute as IPC client and exit
    if let Some(query_cmd) = args.query_command() {
        let ipc_path = args
            .ipc_path
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from(ipc::DEFAULT_IPC_PATH));
        return ipc::run_cli_query(&ipc_path, query_cmd, args.json).await;
    }

    // 3. Resolve configuration from --config <PATH> or CLI flags
    let runtime = match args.resolve_runtime() {
        Ok(rt) => rt,
        Err(err) => {
            let is_security = matches!(
                err,
                RuntimeConfigError::Args(ArgsError::NonLoopbackAddressForbidden { .. })
                    | RuntimeConfigError::Config(ConfigError::NonLoopbackWithoutAllowLan { .. })
            );
            if is_security {
                eprintln!("Security error: {err}");
            } else {
                eprintln!("Configuration error: {err}");
            }
            return ExitCode::FAILURE;
        }
    };

    // 3. If --check was requested, validate logging directive and exit without binding sockets
    if args.check {
        if let Err(err) = logging::build_env_filter(Some(&runtime.log_level)) {
            eprintln!("Configuration error (logging.level): {err}");
            return ExitCode::FAILURE;
        }
        println!("Configuration check passed.");
        return ExitCode::SUCCESS;
    }

    // 4. Initialize tracing subscriber with resolved log level or RUST_LOG
    if let Err(err) = logging::init_logging(Some(&runtime.log_level)) {
        eprintln!("Error initializing logging: {err}");
        return ExitCode::FAILURE;
    }

    // 5. Initialize connection concurrency tracker and reload baseline
    let tracker = ConnectionTracker::new(runtime.max_connections);
    let reload_baseline = ReloadBaseline::from(&runtime);
    let outbounds = Arc::clone(&runtime.inbound.outbounds);

    // 6. Bind inbound listener sockets (mixed, socks, and/or http)
    let listener = match InboundListener::bind(runtime.inbound, tracker.clone()).await {
        Ok(l) => l,
        Err(err) => {
            error!(error = %err, "failed to bind inbound listener sockets");
            eprintln!("Error binding inbound listeners: {err}");
            return ExitCode::FAILURE;
        }
    };

    let snapshot_tx = listener.snapshot_tx();

    for (kind, addr) in listener.local_addrs() {
        info!(kind = ?kind, addr = %addr, "listener active and ready for connections");
    }

    // 7. Initialize shutdown notification watch channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // 8. Bind IPC server for runtime status and diagnostics inspection
    let (ipc_path, is_custom) = match args.ipc_path {
        Some(ref p) => (p.clone(), true),
        None => (std::path::PathBuf::from(ipc::DEFAULT_IPC_PATH), false),
    };

    let ipc_server = match ipc::IpcServer::bind_with_fallback(
        &ipc_path,
        is_custom,
        listener.diagnostics(),
        Arc::clone(&outbounds),
    )
    .await
    {
        Ok(s) => s,
        Err(err) => {
            error!(path = %ipc_path.display(), error = %err, "failed to bind IPC socket");
            eprintln!("Error binding IPC socket {}: {err}", ipc_path.display());
            return ExitCode::FAILURE;
        }
    };
    info!(path = %ipc_server.path().display(), "IPC diagnostics server active");
    let ipc_rx = shutdown_rx.clone();
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_server.run(ipc_rx).await {
            tracing::warn!(error = %e, "IPC server stopped with error");
        }
    });

    // 9. Spawn background health checks for outbound groups
    outbounds.spawn_health_checks(shutdown_rx.clone());

    // 9. Spawn SIGHUP config reloader (when --config is provided) and inbound accept loops
    #[cfg(unix)]
    if let Some(config_path) = args.config.clone() {
        reload::spawn_sighup_reloader(
            config_path,
            reload_baseline,
            snapshot_tx,
            shutdown_rx.clone(),
        );
    }
    let server_handle = tokio::spawn(async move { listener.run(shutdown_rx).await });

    // 9. Coordinate server execution, termination signals, and graceful connection draining
    let drain_timeout = runtime.drain_timeout;
    let exit_code = tokio::select! {
        server_res = server_handle => {
            match server_res {
                Ok(Ok(())) => {
                    info!("server terminated cleanly");
                    ExitCode::SUCCESS
                }
                Ok(Err(e)) => {
                    error!(error = %e, "server failed with error");
                    ExitCode::FAILURE
                }
                Err(e) => {
                    error!(error = %e, "server task panicked");
                    ExitCode::FAILURE
                }
            }
        }
        sig_res = signal::wait_for_signal() => {
            if let Err(e) = sig_res {
                error!(error = %e, "failed to register or listen for termination signal; aborting accept loops");
                let _ = shutdown_tx.send(true);
                return ExitCode::FAILURE;
            }

            let outcome = signal::drain_connections(
                &shutdown_tx,
                &tracker,
                drain_timeout,
            ).await;

            outcome.exit_code()
        }
    };

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), ipc_handle).await;
    exit_code
}
