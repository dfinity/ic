use clap::Parser;
use ic_logger::{info, new_replica_logger_from_config};
use ic_registry_replicator::{args::RegistryReplicatorArgs, RegistryReplicator};

#[tokio::main]
async fn main() {
    let args = RegistryReplicatorArgs::parse();
    let (config, _dir) = args.get_ic_config();

    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    let registry_replicator = RegistryReplicator::new_from_config(logger.clone(), None, &config);

    let (nns_urls, nns_pub_key) =
        registry_replicator.parse_registry_access_info_from_config(&config);

    info!(logger, "Start polling registry.");
    registry_replicator
        .start_polling(nns_urls, nns_pub_key)
        .await
        .expect("Failed to start registry replicator")
        .await
        .expect("Failed to join registry replicator thread handle");
}
