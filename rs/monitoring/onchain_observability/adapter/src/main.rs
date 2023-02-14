/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.socket
use clap::Parser;
use hyper::Client;
use ic_async_utils::abort_on_panic;
use ic_base_types::NodeId;
use ic_canister_client::{Agent, Sender};
use ic_config::registry_client::DataProviderConfig;
use ic_crypto::CryptoComponent;
use ic_interfaces::crypto::{BasicSigner, ErrorReproducibility, KeyManager};
use ic_logger::{error, info, new_replica_logger_from_config, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_onchain_observability_adapter::{
    get_peer_ids, Config, Flags, MetricsParseError, SampledMetricsCollector,
};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::LocalStoreImpl;
use ic_types::{
    crypto::CryptoError,
    messages::MessageId,
    onchain_observability::{PeerReport, Report, SignedReport},
};
use serde_json::to_string_pretty;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::SystemTime,
};
use tokio::{
    runtime::Handle,
    time::{interval, MissedTickBehavior},
};
use url::Url;

const MAX_CRYPTO_SIGNATURE_ATTEMPTS: u64 = 5;

#[tokio::main]
pub async fn main() {
    // We abort the whole program with a core dump if a single thread panics.
    // This way we can capture all the context if a critical error
    // happens.
    abort_on_panic();

    let flags = Flags::parse();
    let config = flags.get_config().expect("Error getting config");
    if config.canister_id.is_empty() {
        // This means the process is disabled
        return;
    }
    let canister_client_url =
        Url::parse(&config.canister_client_url).expect("Failed to create url");

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
    let node_id = crypto_component.get_node_id();
    let _canister_client =
        create_canister_client(crypto_component.clone(), canister_client_url, node_id).await;

    let http_client = Client::new();
    let http_client_clone = http_client.clone();

    // This will be replaced with fetching node ids from registry
    let peer_ids = get_peer_ids(http_client_clone)
        .await
        .expect("Error getting peer_ids");

    let mut sampling_interval = interval(config.sampling_interval_sec);
    sampling_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut sampler = SampledMetricsCollector::new_with_client(http_client);
    let mut start_time = SystemTime::now();
    loop {
        sampling_interval.tick().await;
        if let Err(e) = sampler.sample().await {
            error!(logger, "sampling failed {:?}", e);
        }
        if start_time
            .elapsed()
            .expect("Negative system time must not happen")
            >= config.report_length_sec
        {
            let end_time = SystemTime::now();
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

            let report = prepare_report(node_id, start_time, end_time, uptime);

            for signature_attempts in 0..MAX_CRYPTO_SIGNATURE_ATTEMPTS {
                match sign_report(crypto_component.clone(), report.clone(), node_id).await {
                    Ok(_signed_report) => {
                        /* send report */
                        break;
                    }
                    Err(e) => {
                        if e.is_reproducible()
                            || signature_attempts == MAX_CRYPTO_SIGNATURE_ATTEMPTS - 1
                        {
                            // "Reproducible" represents a fundamental issue with the crypto setup
                            // TODO (NET-1338) convert to metric counter
                            error!(logger, "Failed to sign report, skipping {:?}", e);
                            break;
                        }
                        // Otherwise, if we receive sporadic error, re-try a limited number of times.
                        warn!(logger, "Received sporadic crypto signature failure {:?}", e);
                    }
                }
            }
            sampler.clear();
            start_time = SystemTime::now();
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

async fn create_canister_client(crypto: Arc<CryptoComponent>, url: Url, node_id: NodeId) -> Agent {
    let latest_version = crypto.registry_client().get_latest_version();

    let crypto_clone = crypto.clone();

    let node_pub_key = tokio::task::spawn_blocking(move || {
        crypto
            .current_node_public_keys()
            .map(|cnpks| cnpks.node_signing_public_key)
            .expect("Failed to retrieve current node public keys")
            .expect("Missing node signing public key")
    })
    .await
    .unwrap();

    let sign_cmd = move |msg: &MessageId| {
        tokio::task::block_in_place(|| {
            crypto_clone
                .sign_basic(msg, node_id, latest_version)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
                .map(|value| value.get().0)
        })
    };

    let sender = Sender::Node {
        pub_key: node_pub_key.key_value,
        sign: Arc::new(sign_cmd),
    };
    Agent::new(url, sender)
}

// Prepare a report in the format expected by the observability canister.
// The report will be sent along with a signature allowing canister to
// verify its authentictiy.
fn prepare_report(
    reporting_node_id: NodeId,
    start_time: SystemTime,
    end_time: SystemTime,
    uptime_percent: HashMap<NodeId, f32>,
) -> Report {
    // First, prepare the peer data
    let peer_reports = uptime_percent
        .iter()
        .map(|(peer_id, uptime)| PeerReport {
            peer_id_binary: peer_id.get().to_vec(),
            peer_uptime_percent: *uptime,
        })
        .collect();

    // Next, append the reporting-node-specific fields
    Report {
        start_time,
        end_time,
        reporting_node_id_binary: reporting_node_id.get().to_vec(),
        replica_last_start: SystemTime::now(), // TODO (NET-1331) add real value
        peer_report: peer_reports,
    }
}

async fn sign_report(
    crypto: Arc<CryptoComponent>,
    report: Report,
    reporting_node_id: NodeId,
) -> Result<SignedReport, CryptoError> {
    let report_clone = report.clone();
    match tokio::task::spawn_blocking(move || {
        crypto
            .sign_basic(
                &report_clone,
                reporting_node_id,
                crypto.registry_client().get_latest_version(),
            )
            .map(|value| value.get().0)
    })
    .await
    .unwrap()
    {
        Ok(signature) => Ok(SignedReport { report, signature }),
        Err(e) => Err(e),
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
