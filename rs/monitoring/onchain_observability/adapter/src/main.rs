/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.socket
use clap::Parser;
use hyper::Client;
use ic_async_utils::abort_on_panic;
use ic_base_types::NodeId;
use ic_logger::{error, info, new_replica_logger_from_config};
use ic_onchain_observability_adapter::{
    get_peer_ids, Cli, MetricsParseError, SampledMetricsCollector,
};
use serde_json::to_string_pretty;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::time::{interval, MissedTickBehavior};

const POLLING_INTERVAL_SEC: Duration = Duration::from_secs(60);
const REPORT_LENGTH_SEC: Duration = Duration::from_secs(180); // 3 min: TODO (prod should be 1hr)

const CANISTER_URL: &str = "";

#[tokio::main]
pub async fn main() {
    if CANISTER_URL.is_empty() {
        // This means the process is disabled
        return;
    }

    // We abort the whole program with a core dump if a single thread panics.
    // This way we can capture all the context if a critical error
    // happens.
    abort_on_panic();

    let cli = Cli::parse();

    let config = match cli.get_config() {
        Ok(config) => config,
        Err(err) => {
            panic!("An error occurred while getting the config: {}", err);
        }
    };

    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    info!(
        logger,
        "Starting the onchain observability adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );

    let client = Client::new();

    // This will be replaced with fetching node ids from registry
    let peer_ids = match get_peer_ids(client.clone()).await {
        Ok(peer_ids) => peer_ids,
        Err(e) => panic!("error getting peer_ids ids {:?}", e),
    };

    let mut sampling_interval = interval(POLLING_INTERVAL_SEC);
    sampling_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut sampler = SampledMetricsCollector::new_with_client(client);
    let mut start_time = Instant::now();

    loop {
        sampling_interval.tick().await;
        if let Err(e) = sampler.sample().await {
            error!(logger, "sampling failed {:?}", e);
        }
        if start_time.elapsed() >= REPORT_LENGTH_SEC {
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
