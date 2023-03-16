/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.socket
use candid::{Decode, Encode};
use clap::Parser;
use ic_async_utils::abort_on_panic;
use ic_base_types::{CanisterId, NodeId};
use ic_canister_client::{Agent, Sender};
use ic_config::registry_client::DataProviderConfig;
use ic_crypto::CryptoComponent;
use ic_interfaces::crypto::{BasicSigner, ErrorReproducibility, KeyManager};
use ic_logger::{error, info, new_replica_logger_from_config, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_onchain_observability_adapter::{
    collect_metrics_for_peers, Config, Flags, MetricsCollectError, SampledMetricsCollector,
};
use ic_onchain_observability_service::onchain_observability_service_client::OnchainObservabilityServiceClient;
use ic_registry_client::client::{RegistryClient, RegistryClientImpl};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_local_store::LocalStoreImpl;
use ic_types::{
    crypto::CryptoError,
    messages::MessageId,
    onchain_observability::{PeerReport, Report, SignedReport},
};
use rand::Rng;
use serde_json::to_string_pretty;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::SystemTime,
};
use tokio::{
    net::UnixStream,
    runtime::Handle,
    time::{interval, sleep, Duration, MissedTickBehavior},
};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use url::Url;

const MAX_CRYPTO_SIGNATURE_ATTEMPTS: u64 = 5;

const PREPARE_SOME_METHOD: &str = "prepare_some";
const GET_CERTIFICATE_METHOD: &str = "get_certificate";
const COMMIT_METHOD: &str = "commit";

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
    let canister_id =
        CanisterId::from_str(&config.canister_id).expect("Failed to parse canister id");

    // TODO (NET-1332): Switch to adapter-specific metrics registry
    let metrics_registry = MetricsRegistry::global();

    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    info!(
        logger,
        "Starting the onchain observability adapter with config: {}, url: {:?} id{:?}",
        to_string_pretty(&config).unwrap(),
        canister_client_url,
        canister_id,
    );
    let handle = Handle::current();

    let (registry_client, crypto_component) = create_registry_client_and_crypto_component(
        logger.clone(),
        metrics_registry.clone(),
        config.clone(),
        handle,
    )
    .await;

    let node_id = crypto_component.get_node_id();

    let canister_client =
        create_canister_client(crypto_component.clone(), canister_client_url, node_id).await;

    let grpc_client =
        setup_onchain_observability_adapter_client(PathBuf::from(config.uds_socket_path));

    let peer_ids = get_peer_ids(node_id, &registry_client);

    // TODO(NET-1368) - Collect metrics every 60 minutes, compute delta, and skip log entry if metric collection failed
    let collected_metrics = collect_metrics_for_peers(grpc_client.clone(), &peer_ids)
        .await
        .expect("Failed to retrieve metrics");
    let replica_last_start = collected_metrics.replica_last_start_time;

    let mut sampling_interval = interval(config.sampling_interval_sec);
    sampling_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut sampler = SampledMetricsCollector::new_with_client(grpc_client);
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

            let report = prepare_report(node_id, start_time, end_time, uptime, replica_last_start);

            for signature_attempts in 0..MAX_CRYPTO_SIGNATURE_ATTEMPTS {
                match sign_report(crypto_component.clone(), report.clone(), node_id).await {
                    Ok(signed_report) => {
                        if let Err(e) = send_report_to_canister(
                            &canister_client,
                            canister_id,
                            signed_report,
                            &logger,
                        )
                        .await
                        {
                            error!(logger, "Failed to send report: {:?}", e);
                        }
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

// Currently the adapter only consider the peer ids from the latest registry versions.
// This may cause some occasional discrepancies between metrics between registry and peers.
// NET-1352 to track
fn get_peer_ids(
    current_node_id: NodeId,
    registry_client: &Arc<RegistryClientImpl>,
) -> HashSet<NodeId> {
    let latest_version = registry_client.get_latest_version();

    let (subnet_id, _) = registry_client
        .get_listed_subnet_for_node_id(current_node_id, latest_version)
        .expect("Failed to get subnet data for node id")
        .expect("Failed to retrieve subnet id for node id");

    registry_client
        .get_node_ids_on_subnet(subnet_id, latest_version)
        .expect("Failed to get subnet data for subnet id")
        .expect("Failed to retrieve node ids from subnet")
        .iter()
        .copied()
        .filter(|&x| x != current_node_id)
        .collect()
}

// Generate crypto component which is needed for signing messages
async fn create_registry_client_and_crypto_component(
    logger: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    config: Config,
    rt_handle: Handle,
) -> (Arc<RegistryClientImpl>, Arc<CryptoComponent>) {
    let DataProviderConfig::LocalStore(local_store_from_config) = config
        .registry_config
        .data_provider
        .as_ref()
        .expect("No registry provider found");

    let data_provider = Arc::new(LocalStoreImpl::new(local_store_from_config));
    let registry_client = Arc::new(RegistryClientImpl::new(
        data_provider,
        Some(&metrics_registry),
    ));
    // Cloning registry client since we need to move it into the task below
    let registry_client_clone = registry_client.clone();

    // TODO (NET-1336) proper error handling in case registry is not populated
    registry_client
        .fetch_and_start_polling()
        .expect("fetch_and_start_polling failed");

    let crypto_component = tokio::task::spawn_blocking(move || {
        Arc::new(CryptoComponent::new(
            &config.crypto_config,
            Some(rt_handle),
            registry_client_clone,
            logger,
            Some(&metrics_registry),
        ))
    })
    .await
    .expect("Failed to create crypto component");

    (registry_client, crypto_component)
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
        // Implementation of 'sign_basic' uses Tokio's 'block_on' when issuing a RPC
        // to the crypto service. 'block_on' panics when called from async context
        // that's why we need to wrap 'sign_basic' in 'block_in_place'.
        #[allow(clippy::disallowed_methods)]
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
    replica_last_start_time: SystemTime,
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
        replica_last_start_time,
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

/// Publish the report to the canister using the Canister Client API.  This involves a 3-step process
/// 1. prepare_some(vec![encoded report]) to prepare the data and create a certificate
/// 2. Get_certificate() to get the certificate for the data
/// 3. commit(certificate) to publish the results to the canister
/// Note that these calls must account for race conditions from simultaneous publishes across replicas
async fn send_report_to_canister(
    canister_client: &Agent,
    canister_id: CanisterId,
    report: SignedReport,
    logger: &ReplicaLogger,
) -> Result<(), String> {
    // Introducing some jitter to break synchronization across replicas and reduce probability that multiple replicas
    // initiate a request at the same time, which can cause canister client calls to fail. TODO(NET-1343) - integrate into retry logic
    let mut rng = rand::thread_rng();
    let random_sleep_duration = 2 * rng.gen_range(0..5);
    sleep(Duration::from_secs(random_sleep_duration)).await;

    // Step 1 - the canister API requires us to call prepare_some(Vec<Vec<u8>>) to prepare the data. Note that this requires 2 levels of encoding.
    // First we encode the report itself to vec<u8>.  However, the API expects vec<vec<u8> so we must then wrap it in another vector.
    // Finally, the canister client expects a candid-encoded representation of the method arguments, so we must re-encode this back into another Vec<u8>.
    let encoded_report =
        Encode!(&report).or_else(|_| Err("Error serializing report to candid".to_string()))?;
    let candid_prepare_some_arg = Encode!(&vec![encoded_report])
        .or_else(|_| Err("Error encoding prepare_some() args".to_string()))?;

    canister_client
        .execute_update(
            &canister_id,
            &canister_id,
            PREPARE_SOME_METHOD,
            candid_prepare_some_arg,
            generate_nonce(),
        )
        .await
        .map_err(|e| format!("Canister client prepare_some() query failed: {e}"))?
        .ok_or_else(|| {
            "Canister client unexpectedly received empty response from prepare_some()".to_string()
        })?;

    // Step 2 - We must call get_certificate() to obtain the certificate corresponding to the prepared data.
    // This is used later to confirm we are not attempting to publish stale data.
    let encoded_empty_arg = Encode!(&Vec::<u8>::new())
        .or_else(|_| Err("Error encoding get_certificate() args".to_string()))?;

    let encoded_certificate = canister_client
        .execute_query(&canister_id, GET_CERTIFICATE_METHOD, encoded_empty_arg)
        .await
        .map_err(|e| format!("Canister client get_certificate() query failed: {e}"))?
        .ok_or_else(|| {
            "Canister client unexpectedly received empty response from get_certificate()"
                .to_string()
        })?;

    let decoded_certificate_opt = Decode!(&encoded_certificate, Option<Vec<u8>>)
        .or_else(|_| Err("Error deserializing certificate into optional type".to_string()))?;

    // Step 3 - We must commit the data using the certificate
    // If certificate is not found, that means there was no pending data and we can assume
    // that this data was already published by another replica.
    let certificate = match decoded_certificate_opt {
        Some(cert) => cert,
        None => {
            warn!(
                logger,
                "Certificate not found. Data may have already been published"
            );
            return Ok(());
        }
    };

    let candid_commit_arg =
        Encode!(&certificate).or_else(|_| Err("Error encoding commit() args".to_string()))?;

    match canister_client
        .execute_update(
            &canister_id,
            &canister_id,
            COMMIT_METHOD,
            candid_commit_arg,
            generate_nonce(),
        )
        .await
    {
        // If error, we can assume this is due to stale certificate and that
        // another replica staged new data and will eventually commit the data

        // TODO: Convert canister client to strongly typed error so that we can also
        // check for timeouts
        Ok(Some(encoded_block_number)) => {
            let decoded_result = Decode!(&encoded_block_number, Option<u64>)
                .or_else(|_| Err("Error decoding block".to_string()))?;
            if let Some(block) = decoded_result {
                info!(
                    logger,
                    "Successfully published data at block height: {:?}", block
                );
            } else {
                warn!(logger, "Commit was skipped due to no pending data");
            }
        }
        Ok(None) => return Err("Commit() did not return a valid response".to_string()),
        Err(e) => {
            warn!(
                logger,
                "Did not commit data (may have already been committed): {:?}", e
            );
        }
    }
    Ok(())
}

fn generate_nonce() -> Vec<u8> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes()
        .to_vec()
}

// Peer label is in form of "{NODE IP}_{NODE ID PREFIX}" so we can take the prefix
// and compare to peer ids to infer the full id
fn convert_peer_label_to_node_id(
    peer_label: &str,
    node_id_list: &HashSet<NodeId>,
) -> Result<NodeId, MetricsCollectError> {
    let peer_label_split = peer_label.split('_').collect::<Vec<&str>>();
    if peer_label_split.len() != 2 {
        return Err(MetricsCollectError::MetricParseFailure(
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
        return Err(MetricsCollectError::MetricParseFailure(
            "Did not find 1:1 mapping between node id prefix and node id list".to_string(),
        ));
    }
    Ok(*valid_node_ids[0])
}

pub fn setup_onchain_observability_adapter_client(
    uds_path: PathBuf,
) -> OnchainObservabilityServiceClient<Channel> {
    let endpoint = Endpoint::try_from("http://[::]:50051").expect("Failed to connect to endpoint");
    let channel = endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
        // Connect to a Uds socket
        UnixStream::connect(uds_path.clone())
    }));

    OnchainObservabilityServiceClient::new(channel)
}
