/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.socket
use clap::Parser;
use hyper::Client;
use ic_async_utils::abort_on_panic;
use ic_base_types::NodeId;
use ic_config::registry_client::DataProviderConfig;
use ic_crypto::CryptoComponent;
use ic_logger::{error, info, new_replica_logger_from_config, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_onchain_observability_adapter::{
    get_peer_ids, Config, Flags, MetricsParseError, SampledMetricsCollector,
};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::LocalStoreImpl;
use serde_json::to_string_pretty;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Instant,
};
use tokio::{
    runtime::Handle,
    time::{interval, MissedTickBehavior},
};

#[tokio::main]
pub async fn main() {
    // We abort the whole program with a core dump if a single thread panics.
    // This way we can capture all the context if a critical error
    // happens.
    abort_on_panic();

    let flags = Flags::parse();
    let config = flags.get_config().expect("Error getting config");
    if config.canister_client_url.is_empty() {
        // This means the process is disabled
        return;
    }

    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    info!(
        logger,
        "Starting the onchain observability adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );
    let handle = Handle::current();
    // TODO (NET-1332): Switch to adapter-specific metrics registry
    let metrics_registry = MetricsRegistry::global();
    let crypto_component =
        create_crypto_component(&logger, &metrics_registry, &config, handle).await;
    let _node_id = crypto_component.get_node_id();
    let http_client = Client::new();
    let http_client_clone = http_client.clone();

    // This will be replaced with fetching node ids from registry
    let peer_ids = get_peer_ids(http_client_clone)
        .await
        .expect("Error getting peer_ids");

    let mut sampling_interval = interval(config.sampling_interval_sec);
    sampling_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut sampler = SampledMetricsCollector::new_with_client(http_client);
    let mut start_time = Instant::now();

    loop {
        sampling_interval.tick().await;
        if let Err(e) = sampler.sample().await {
            error!(logger, "sampling failed {:?}", e);
        }
        if start_time.elapsed() >= config.report_length_sec {
            let end_time = Instant::now();
            let up_time_peer_labels = sampler.aggregate();
            // TODO NET-1328 - remove panic and handle failed conversion gracefully
            let uptime: HashMap<NodeId, f32> = up_time_peer_labels
                .iter()
                .map(|(node_label, percent)| {
                    (
                        convert_peer_label_to_node_id(node_label, &peer_ids).unwrap(),
                        *percent,
                    )
                })
                .collect();

            info!(
                logger,
                "Completed Report: interval{:?}-{:?} uptime% {:?}", start_time, end_time, uptime
            );

            sampler.clear();
            start_time = Instant::now();

            //TODO send report
        }
    }
}

// Generate crypto component which is needed for signing messages
async fn create_crypto_component(
    logger: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    config: &Config,
    rt_handle: Handle,
) -> Arc<CryptoComponent> {
    let DataProviderConfig::LocalStore(local_store_from_config) = config
        .registry_config
        .data_provider
        .as_ref()
        .expect("No registry provider found");

    let data_provider = Arc::new(LocalStoreImpl::new(local_store_from_config));
    let registry_client = Arc::new(RegistryClientImpl::new(
        data_provider,
        Some(metrics_registry),
    ));

    // TODO (NET-1336) proper error handling in case registry is not populated
    registry_client
        .fetch_and_start_polling()
        .expect("fetch_and_start_polling failed");

    let metrics_registry_clone = metrics_registry.clone();
    let config_clone = config.clone();
    let logger_clone = logger.clone();
    tokio::task::spawn_blocking(move || {
        Arc::new(CryptoComponent::new(
            &config_clone.crypto_config,
            Some(rt_handle),
            registry_client,
            logger_clone,
            Some(&metrics_registry_clone),
        ))
    })
    .await
    .expect("Failed to create crypto component")
}

// Peer label is in form of "{NODE IP}_{NODE ID PREFIX}" so we can take the prefix
// and compare to peer ids to infer the full id
fn convert_peer_label_to_node_id(
    peer_label: &str,
    node_id_list: &HashSet<NodeId>,
) -> Result<NodeId, MetricsParseError> {
    let peer_label_split = peer_label.split('_').collect::<Vec<&str>>();
    if peer_label_split.len() != 2 {
        return Err(MetricsParseError::PeerLabelToIdConversionFailure(
            "Peer label was not succesfully split into 2 pieces".to_string(),
        ));
    }
    let peer_id_prefix = peer_label_split[1];

    let valid_node_ids: Vec<_> = node_id_list
        .iter()
        .filter(|&id| id.to_string().contains(peer_id_prefix))
        .collect();

    // Assumption: There is a 1:1 mapping between id prefix and full id
    if valid_node_ids.len() != 1 {
        return Err(MetricsParseError::PeerLabelToIdConversionFailure(
            "Did not find 1:1 mapping between node id prefix and node id list".to_string(),
        ));
    }
    Ok(*valid_node_ids[0])
}
