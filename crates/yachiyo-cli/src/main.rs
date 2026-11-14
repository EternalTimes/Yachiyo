// SPDX-License-Identifier: AGPL-3.0-only

//! Yachiyo CLI entrypoint, argument parsing, security pre-flight checks, and runtime lifecycle coordination.

use clap::Parser;
use std::process::ExitCode;
use tracing::{error, info};
use yachiyo_core::connection::ConnectionTracker;
use yachiyo_inbound::InboundListener;

use yachiyo_cli::args::CliArgs;
use yachiyo_cli::logging;
use yachiyo_cli::signal;

#[tokio::main]
async fn main() -> ExitCode {
    run().await
}

/// Inner runner function allowing clean error handling and test execution.
pub async fn run() -> ExitCode {
    // 1. Parse command-line arguments via clap
    let args = CliArgs::parse();

    // 2. Initialize tracing subscriber with log level from CLI or RUST_LOG
    if let Err(err) = logging::init_logging(Some(&args.log_level)) {
        eprintln!("Error initializing logging: {err}");
        return ExitCode::FAILURE;
    }

    // 3. Pre-flight security check: reject non-loopback bindings if --allow-lan is not provided
    if let Err(err) = args.validate_security() {
        error!(error = %err, "pre-flight security validation failed");
        eprintln!("Security error: {err}");
        return ExitCode::FAILURE;
    }

    // 4. Resolve listener addresses and build InboundConfig
    let config = match args.to_inbound_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            error!(error = %err, "failed to configure inbound listeners");
            eprintln!("Configuration error: {err}");
            return ExitCode::FAILURE;
        }
    };

    // 5. Initialize connection concurrency tracker (configured limit, default 1024)
    let tracker = ConnectionTracker::new(args.max_connections);

    // 6. Bind inbound listener sockets (mixed, socks, and/or http)
    let listener = match InboundListener::bind(config, tracker.clone()).await {
        Ok(l) => l,
        Err(err) => {
            error!(error = %err, "failed to bind inbound listener sockets");
            eprintln!("Error binding inbound listeners: {err}");
            return ExitCode::FAILURE;
        }
    };

    for (kind, addr) in listener.local_addrs() {
        info!(kind = ?kind, addr = %addr, "listener active and ready for connections");
    }

    // 7. Initialize shutdown notification watch channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // 8. Spawn inbound listener accept loops in background task
    let server_handle = tokio::spawn(async move { listener.run(shutdown_rx).await });

    // 9. Coordinate server execution, termination signals, and 5-second graceful connection draining
    tokio::select! {
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
                signal::DEFAULT_DRAIN_TIMEOUT,
            ).await;

            outcome.exit_code()
        }
    }
}
