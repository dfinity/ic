/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.socket
use candid::{Decode, Encode};
use clap::Parser;
use ic_adapter_metrics_server::start_metrics_grpc;
use ic_async_utils::{abort_on_panic, incoming_from_nth_systemd_socket};
use ic_base_types::{CanisterId, NodeId};
use ic_canister_client::{Agent, Sender};
use ic_crypto::CryptoComponent;
use ic_interfaces::crypto::{BasicSigner, ErrorReproducibility, KeyManager};
use ic_logger::{error, info, new_replica_logger_from_config, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_onchain_observability_adapter::{
    collect_metrics_for_peers, derive_peer_counters_for_current_report_interval,
    CanisterPublishError, Config, Flags, MetricsCollectError, OnchainObservabilityAdapterMetrics,
    PeerCounterMetrics, SampledMetricsCollector,
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
use sha2::Digest;
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
const FIND_METHOD: &str = "find";

const FIND_REPORT_SLEEP_DURATION: Duration = Duration::from_secs(10);

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

    let metrics_registry = MetricsRegistry::global();
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);
    let onchain_observability_adapter_metrics =
        OnchainObservabilityAdapterMetrics::new(&metrics_registry);

    // SAFETY:
    // The systemd service is configured to set its first socket as the metrics socket, so we expect the FD to exist.
    // Additionally, this is the only callsite within the adapter so this should only be consumed once.
    // Systemd Socket config: ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter-metrics.socket
    // Systemd Service config: ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.service
    let stream = unsafe { incoming_from_nth_systemd_socket(1) };
    start_metrics_grpc(metrics_registry.clone(), logger.clone(), stream);

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

    // Continuously collect and send reports. There are 2 types of metrics - sampled and non-sampled.
    // Sampled will be collected periodically and averaged at the end of the reporting interval.
    // Non-sampled will be collected at the end and the delta will be computed from previous baseline.
    // On failure, the report publish will be skipped and attempted again at the next interval.

    let mut sampling_interval = interval(config.sampling_interval_sec);
    sampling_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut sampler = SampledMetricsCollector::new(
        grpc_client.clone(),
        onchain_observability_adapter_metrics.clone(),
    );
    let mut non_sampled_metrics_baseline_opt = None;
    let mut start_time = SystemTime::now();
    let mut report_duration = config.report_length_sec;

    loop {
        sampling_interval.tick().await;
        if let Err(e) = sampler.sample().await {
            error!(logger, "sampling failed {:?}", e);
        }
        if start_time
            .elapsed()
            .expect("Negative system time must not happen")
            >= report_duration
            || non_sampled_metrics_baseline_opt.is_none()
        {
            onchain_observability_adapter_metrics
                .report_interval_elapsed_total
                .inc();

            // Refresh peer ids. TODO(NET-1384) if fetching peer id fails, either fallback to old peers or skip report
            let peer_ids = get_peer_ids(node_id, &registry_client);

            let non_sampled_metrics_at_report_end_result = collect_metrics_for_peers(
                grpc_client.clone(),
                &peer_ids,
                &onchain_observability_adapter_metrics,
            )
            .await;

            if let Err(e) = non_sampled_metrics_at_report_end_result {
                // On failure, retry data collection and publish on next interval. Note that start time / baseline counters are preserved and we simply extend the report end time.
                onchain_observability_adapter_metrics
                    .reports_delayed_total
                    .inc();
                error!(
                    logger,
                    "Failed to collect non-sampled metrics, defering report to next interval: {:?}",
                    e.to_string()
                );
                report_duration += config.report_length_sec;
                continue;
            }
            let non_sampled_metrics_at_report_end =
                non_sampled_metrics_at_report_end_result.unwrap();

            // If the report start is unset, this implies we haven't established a baseline yet, so we must wait
            // until the next iteration before we can compute the delta and publish the report.
            if let Some(non_sampled_metrics_baseline) = non_sampled_metrics_baseline_opt {
                let end_time = SystemTime::now();

                // The gRPC response provides cumulative metric counts since replica last restart, so we may need to adjust counts for the current reporting window.
                let peer_counters_for_current_interval =
                    derive_peer_counters_for_current_report_interval(
                        &non_sampled_metrics_baseline,
                        &non_sampled_metrics_at_report_end,
                    );
                let replica_last_start_time =
                    non_sampled_metrics_at_report_end.replica_last_start_time;

                let up_time_peer_labels = sampler.aggregate();

                let report = prepare_report(
                    node_id,
                    start_time,
                    end_time,
                    replica_last_start_time,
                    peer_counters_for_current_interval,
                    up_time_peer_labels,
                    &peer_ids,
                );

                info!(logger, "Completed Report: report {:?}", report);

                for signature_attempts in 0..MAX_CRYPTO_SIGNATURE_ATTEMPTS {
                    match sign_report(crypto_component.clone(), report.clone(), node_id).await {
                        Ok(signed_report) => {
                            if let Err(e) = send_report_to_canister(
                                &canister_client,
                                canister_id,
                                &signed_report,
                                &logger,
                            )
                            .await
                            {
                                warn!(logger, "Send report may have failed: {:?}", e);
                            }
                            // Add a delay to allocate sufficient time in case data is commited by another node
                            sleep(FIND_REPORT_SLEEP_DURATION).await;

                            let publish_result = match is_report_published(
                                &canister_client,
                                canister_id,
                                &signed_report,
                            )
                            .await
                            {
                                Ok(is_published) => is_published.to_string(),
                                Err(e) => {
                                    error!(
                                        logger,
                                        "Could not check whether report was published {:?}", e
                                    );
                                    "unknown".to_string()
                                }
                            };
                            onchain_observability_adapter_metrics
                                .find_published_report_in_canister_requests_total
                                .with_label_values(&[&publish_result])
                                .inc();

                            break;
                        }
                        Err(e) => {
                            if e.is_reproducible()
                                || signature_attempts == MAX_CRYPTO_SIGNATURE_ATTEMPTS - 1
                            {
                                // "Reproducible" represents a fundamental issue with the crypto setup
                                onchain_observability_adapter_metrics
                                    .failed_crypto_signatures_total
                                    .inc();
                                error!(logger, "Failed to sign report, skipping {:?}", e);
                                break;
                            }
                            // Otherwise, if we receive sporadic error, re-try a limited number of times.
                            warn!(logger, "Received sporadic crypto signature failure {:?}", e);
                        }
                    }
                }
            }
            // Reset the baseline counts
            non_sampled_metrics_baseline_opt = Some(non_sampled_metrics_at_report_end);
            sampler.clear();
            start_time = SystemTime::now();
            report_duration = config.report_length_sec;
        }
    }
}

async fn is_report_published(
    canister_client: &Agent,
    canister_id: CanisterId,
    report: &SignedReport,
) -> Result<bool, CanisterPublishError> {
    let encoded_report = Encode!(&report).or_else(|_| {
        Err(CanisterPublishError::SerializationFailure(
            "Report encoding".to_string(),
        ))
    })?;

    let hash: [u8; 32] = sha2::Sha256::digest(&encoded_report).into();

    let encoded_arg = Encode!(&hash).or_else(|_| {
        Err(CanisterPublishError::SerializationFailure(
            "Find query arg encoding".to_string(),
        ))
    })?;

    // Running as replicated query to avoid hitting a lagging node
    let encoded_option = canister_client
        .execute_update(
            &canister_id,
            &canister_id,
            FIND_METHOD,
            encoded_arg,
            generate_nonce(),
        )
        .await
        .map_err(|e| {
            CanisterPublishError::CanisterClientFailure(format!("find() query failed: {:?}", e))
        })?
        .ok_or_else(|| {
            CanisterPublishError::CanisterClientFailure("Empty response from find()".to_string())
        })?;

    let index_option = Decode!(&encoded_option, Option<u64>).or_else(|_| {
        Err(CanisterPublishError::SerializationFailure(
            "Canister client response decoding".to_string(),
        ))
    })?;

    match index_option {
        Some(_) => Ok(true),
        None => Ok(false),
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
    let data_provider = Arc::new(LocalStoreImpl::new(config.registry_config.local_store));
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
    replica_last_start_time: SystemTime,
    counter_metrics: HashMap<NodeId, PeerCounterMetrics>,
    uptime_peer_labels: HashMap<String, f32>,
    peer_ids: &HashSet<NodeId>,
) -> Report {
    // Convert uptime from peer label into peer ids
    let uptime_peer_ids: HashMap<NodeId, f32> = uptime_peer_labels
        .iter()
        .filter_map(|(node_label, percent)| {
            match convert_peer_label_to_node_id(node_label, peer_ids) {
                Ok(node_id) => Some((node_id, *percent)),
                Err(_) => None,
            }
        })
        .collect();

    let mut peer_reports: Vec<PeerReport> = vec![];
    for peer in peer_ids {
        if counter_metrics.get(peer).is_some() && uptime_peer_ids.get(peer).is_some() {
            peer_reports.push(PeerReport {
                peer_id_binary: peer.get().to_vec(),
                peer_uptime_percent: uptime_peer_ids[peer],
                num_retries: counter_metrics[peer].num_retries,
                connection_bytes_received: counter_metrics[peer].bytes_received,
                connection_bytes_sent: counter_metrics[peer].bytes_sent,
            });
        }
    }

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
    report: &SignedReport,
    logger: &ReplicaLogger,
) -> Result<(), CanisterPublishError> {
    // Introducing some jitter to break synchronization across replicas and reduce probability that multiple replicas
    // initiate a request at the same time, which can cause canister client calls to fail. TODO(NET-1343) - integrate into retry logic
    let mut rng = rand::thread_rng();
    let random_sleep_duration_sec = 2 * rng.gen_range(0..5);
    sleep(Duration::from_secs(random_sleep_duration_sec)).await;

    // Step 1 - the canister API requires us to call prepare_some(Vec<Vec<u8>>) to prepare the data. Note that this requires 2 levels of encoding.
    // First we encode the report itself to vec<u8>.  However, the API expects vec<vec<u8> so we must then wrap it in another vector.
    // Finally, the canister client expects a candid-encoded representation of the method arguments, so we must re-encode this back into another Vec<u8>.
    let encoded_report = Encode!(&report).or_else(|_| {
        Err(CanisterPublishError::SerializationFailure(
            "Report encoding".to_string(),
        ))
    })?;
    let candid_prepare_some_arg = Encode!(&vec![encoded_report]).or_else(|_| {
        Err(CanisterPublishError::SerializationFailure(
            "prepare_some() arg encoding".to_string(),
        ))
    })?;

    canister_client
        .execute_update(
            &canister_id,
            &canister_id,
            PREPARE_SOME_METHOD,
            candid_prepare_some_arg,
            generate_nonce(),
        )
        .await
        .map_err(|e| {
            CanisterPublishError::CanisterClientFailure(format!(
                "prepare_some() query failed: {:?}",
                e
            ))
        })?
        .ok_or_else(|| {
            CanisterPublishError::CanisterClientFailure(
                "Empty response from prepare_some()".to_string(),
            )
        })?;

    // Step 2 - We must call get_certificate() to obtain the certificate corresponding to the prepared data.
    // This is used later to confirm we are not attempting to publish stale data.
    let encoded_empty_arg = Encode!(&Vec::<u8>::new()).or_else(|_| {
        Err(CanisterPublishError::SerializationFailure(
            "get_certificate() args encoding".to_string(),
        ))
    })?;

    let encoded_certificate = canister_client
        .execute_query(&canister_id, GET_CERTIFICATE_METHOD, encoded_empty_arg)
        .await
        .map_err(|e| {
            CanisterPublishError::CanisterClientFailure(format!(
                "get_certificate() query failed: {:?}",
                e
            ))
        })?
        .ok_or_else(|| {
            CanisterPublishError::CanisterClientFailure(
                "Empty response from get_certificate()".to_string(),
            )
        })?;

    let decoded_certificate_opt = Decode!(&encoded_certificate, Option<Vec<u8>>).or_else(|_| {
        Err(CanisterPublishError::SerializationFailure(
            "Certificate decoding".to_string(),
        ))
    })?;

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

    let candid_commit_arg = Encode!(&certificate).or_else(|_| {
        Err(CanisterPublishError::SerializationFailure(
            "commit() args encoding".to_string(),
        ))
    })?;

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
            let decoded_result = Decode!(&encoded_block_number, Option<u64>).or_else(|_| {
                Err(CanisterPublishError::SerializationFailure(
                    "block decoding".to_string(),
                ))
            })?;
            if let Some(block) = decoded_result {
                info!(
                    logger,
                    "Successfully published data at block height: {:?}", block
                );
            } else {
                warn!(logger, "Commit was skipped due to no pending data");
            }
        }
        Ok(None) => {
            return Err(CanisterPublishError::CanisterClientFailure(
                "Commit() did not return a valid response".to_string(),
            ))
        }
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
