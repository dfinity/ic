use clap::Parser;
use ic_http_endpoints_async_utils::shutdown_signal;
use ic_logger::{info, new_replica_logger_from_config, warn};
use ic_registry_replicator::{args::RegistryReplicatorArgs, RegistryReplicator};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    let args = RegistryReplicatorArgs::parse();
    let (config, _dir) = args.get_ic_config();

    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    let (registry_replicator, _tmp) = RegistryReplicator::new_with_metrics_runtime(
        logger.clone(),
        None,
        &config,
        args.get_metrics_addr(),
    );

    let (nns_urls, nns_pub_key) =
        registry_replicator.parse_registry_access_info_from_config(&config);

    let cancellation_token = CancellationToken::new();
    info!(logger, "Initializing registry replicator.");
    let future = registry_replicator
        .start_polling(nns_urls, nns_pub_key, cancellation_token.clone())
        .await
        .expect("Failed to start registry replicator");

    info!(logger, "Start polling registry.");
    let mut handle = tokio::task::spawn(future);

    tokio::select! {
        _ = shutdown_signal(logger.clone()) => {},
        _ = &mut handle => {},
    }

    info!(logger, "Shutting down the registry replicator");
    cancellation_token.cancel();

    match handle.await {
        Err(err) if err.is_panic() => {
            warn!(logger, "Registry replicator task panicked: {err}");
        }
        _ => {
            info!(logger, "Registry replicator shut down gracefully");
        }
    }
}
