use crate::{error_types::MetricsCollectError, OnchainObservabilityAdapterMetrics};
use ic_base_types::{NodeId, PrincipalId};
use ic_onchain_observability_service::{
    onchain_observability_service_client::OnchainObservabilityServiceClient,
    OnchainObservabilityServiceGetMetricsDataRequest,
};
use prometheus_parse::{Sample, Scrape, Value, Value::Counter};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    time::{Duration, SystemTime},
};
use tonic::transport::Channel;

const PROCESS_START_TIME_METRIC: &str = "process_start_time_seconds";
const RETRY_CONNECTION_METRIC: &str = "transport_retry_connection";
const TOTAL_BYTES_SENT_METRIC: &str = "transport_write_bytes_total";
const TOTAL_BYTES_RECEIVED_METRIC: &str = "transport_read_bytes_total";
const PEER_ID_LABEL: &str = "peer_id";

// TODO make these config-based
const RETRY_INTERVAL_SEC: Duration = Duration::from_secs(30);
const TIMEOUT_LENGTH_SEC: Duration = Duration::from_secs(30);
const MAX_ATTEMPTS: u64 = 5;

// Represents the non-sampled metrics collected from replica from an individual gRPC request
#[derive(Clone, Debug, PartialEq)]

pub struct NonSampledMetrics {
    // Represents last restart time for the replica providing peer metrics. Can be used to
    // determine if metric counters were reset since last gRPC query.
    pub replica_last_start_time: SystemTime,
    pub peer_metrics: HashMap<NodeId, PeerCounterMetrics>,
}

// The non-sampled peer metrics obtained from gRPC request.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PeerCounterMetrics {
    // The number of times a peer connection was disconnected and a reconnect was attempted
    pub num_retries: u64,
    // Total bytes the reporting replica received from the peer
    pub bytes_received: u64,
    // Total bytes the reporting replica wrote to the peer
    pub bytes_sent: u64,
}

impl PeerCounterMetrics {
    pub fn subtract(&self, other: &Self) -> Self {
        PeerCounterMetrics {
            num_retries: self.num_retries - other.num_retries,
            bytes_received: self.bytes_received - other.bytes_received,
            bytes_sent: self.bytes_sent - other.bytes_sent,
        }
    }
}

// Sends a gRPC request to the replica to collect the relevant metrics.
// Response will be filtered on peer ids passed as a parameter.  This is to resolve any
// possible discrepancies between peers from latest registry version (source of truth) and prometheus metrics.
pub async fn collect_metrics_for_peers(
    mut client: OnchainObservabilityServiceClient<Channel>,
    peer_ids: &HashSet<NodeId>,
    adapter_metrics: &OnchainObservabilityAdapterMetrics,
) -> Result<NonSampledMetrics, MetricsCollectError> {
    let request = OnchainObservabilityServiceGetMetricsDataRequest {
        requested_metrics: vec![
            PROCESS_START_TIME_METRIC.to_string(),
            RETRY_CONNECTION_METRIC.to_string(),
            TOTAL_BYTES_SENT_METRIC.to_string(),
            TOTAL_BYTES_RECEIVED_METRIC.to_string(),
        ],
    };

    for _ in 0..MAX_ATTEMPTS {
        let mut tonic_request = tonic::Request::new(request.clone());
        tonic_request.set_timeout(TIMEOUT_LENGTH_SEC);

        match client.get_metrics_data(tonic_request).await {
            Ok(response) => {
                return parse_metrics_response(response.into_inner().metrics_data, peer_ids)
            }
            Err(status) => {
                adapter_metrics
                    .failed_grpc_requests_total
                    .with_label_values(&["non_sampled", &status.code().to_string()])
                    .inc();
            }
        }
        tokio::time::sleep(RETRY_INTERVAL_SEC).await;
    }
    Err(MetricsCollectError::RpcRequestFailure(format!(
        "Max attempts ({:?}) exceeded",
        MAX_ATTEMPTS
    )))
}

// Takes raw string gRPC response and converts into NonSampledMetrics struct
pub fn parse_metrics_response(
    response: String,
    peer_ids: &HashSet<NodeId>,
) -> Result<NonSampledMetrics, MetricsCollectError> {
    let lines = response.lines().map(|s| Ok(s.to_string()));
    let scraped_metrics = Scrape::parse(lines).map_err(|_| {
        MetricsCollectError::MetricParseFailure("prometheus scrape error".to_string())
    })?;

    let replica_last_start_time = extract_replica_last_start(&scraped_metrics).map_err(|e| {
        MetricsCollectError::MetricParseFailure(format!(
            "Failed to parse replica last start: {:?}",
            e
        ))
    })?;

    // If parsing the prometheus metrics data fails, then a log entry will not be created
    // TODO (NET-1338) Add counter to track metric parse failure
    let bytes_sent_for_peers =
        extract_peer_counts_for_metric(&scraped_metrics, TOTAL_BYTES_SENT_METRIC)?;

    let bytes_received_for_peers =
        extract_peer_counts_for_metric(&scraped_metrics, TOTAL_BYTES_RECEIVED_METRIC)?;

    let retry_count_for_peers =
        extract_peer_counts_for_metric(&scraped_metrics, RETRY_CONNECTION_METRIC)?;

    let mut peer_metrics_map = HashMap::new();

    for peer_id in peer_ids.iter() {
        let num_retries = *retry_count_for_peers.get(peer_id).unwrap_or(&0);
        let bytes_received = *bytes_received_for_peers.get(peer_id).unwrap_or(&0);
        let bytes_sent = *bytes_sent_for_peers.get(peer_id).unwrap_or(&0);

        let current_peer_metrics = PeerCounterMetrics {
            num_retries,
            bytes_received,
            bytes_sent,
        };
        peer_metrics_map.insert(*peer_id, current_peer_metrics);
    }

    Ok(NonSampledMetrics {
        replica_last_start_time,
        peer_metrics: peer_metrics_map,
    })
}

// Returns the replica last start time from the prometheus scrape
fn extract_replica_last_start(parse: &Scrape) -> Result<SystemTime, MetricsCollectError> {
    let replica_last_start_time_vec: Vec<&Value> = parse
        .samples
        .iter()
        .filter(|&sample| sample.metric == PROCESS_START_TIME_METRIC)
        .map(|sample| &sample.value)
        .collect();

    if replica_last_start_time_vec.len() != 1 {
        return Err(MetricsCollectError::MetricParseFailure(format!(
            "Expected exactly 1 field for replica start time, found {:?}",
            replica_last_start_time_vec.len()
        )));
    }

    if let Value::Gauge(last_start) = replica_last_start_time_vec[0] {
        let time = *last_start as u64;
        return SystemTime::UNIX_EPOCH
            .checked_add(Duration::new(time, 0))
            .ok_or_else(|| {
                MetricsCollectError::MetricParseFailure(
                    "Replica last start value not convertible into system time".to_string(),
                )
            });
    }

    Err(MetricsCollectError::MetricParseFailure(
        "Replica last start metric key found, but missing value".to_string(),
    ))
}

fn extract_peer_counts_for_metric(
    parse: &Scrape,
    metric_name: &str,
) -> Result<HashMap<NodeId, u64>, MetricsCollectError> {
    let filtered_prometheus_scrape: Vec<&Sample> = parse
        .samples
        .iter()
        .filter(|&sample| sample.metric == metric_name)
        .collect();

    let mut metric_for_peers = HashMap::new();

    if filtered_prometheus_scrape.is_empty() {
        // A missing metric may or may not be interpreted as an error.  Pass an empty response and let the caller decide
        return Ok(metric_for_peers);
    }

    for sample in filtered_prometheus_scrape {
        let node_id_str = sample.labels.get(PEER_ID_LABEL).ok_or_else(|| {
            MetricsCollectError::MetricParseFailure(format!(
                "Missing peer id label for metric {:?}",
                metric_name
            ))
        })?;
        // convert node id str into NodeId
        let principal_id = PrincipalId::from_str(node_id_str).map_err(|e| {
            MetricsCollectError::MetricParseFailure(format!(
                "Could not convert string to Principal Id {:?}",
                e
            ))
        })?;
        let node_id = NodeId::from(principal_id);

        let count = match sample.value {
            Counter(count) | Value::Gauge(count) => {
                // TODO(NET-1366): Handle any unexpected negative numbers
                count as u64
            }
            _ => {
                return Err(MetricsCollectError::MetricParseFailure(format!(
                    "Unsupported value for metric {:?} could not be converted into count",
                    metric_name
                )))
            }
        };
        metric_for_peers.insert(node_id, count);
    }

    Ok(metric_for_peers)
}

// A helper function to isolate the counts for the current reporting interval.
// If replica restarted since the last report, then the latest cumulative counts are already within
// the report window
pub fn derive_peer_counters_for_current_report_interval(
    metrics_report_start: &NonSampledMetrics,
    metrics_report_end: &NonSampledMetrics,
) -> HashMap<NodeId, PeerCounterMetrics> {
    if metrics_report_end.replica_last_start_time > metrics_report_start.replica_last_start_time {
        return metrics_report_end.peer_metrics.clone();
    }

    // Used as a no-op baseline if a new peer is added between reports
    let zero_counters = PeerCounterMetrics::default();

    let delta_peer_metrics_map = metrics_report_end
        .peer_metrics
        .iter()
        .map(|(peer_id, latest_metric_counts)| {
            let baseline_counts = metrics_report_start
                .peer_metrics
                .get(peer_id)
                .unwrap_or(&zero_counters);
            (*peer_id, latest_metric_counts.subtract(baseline_counts))
        })
        .collect();

    // We cannot modify the existing struct directly since we need to preserve the cumulative counts
    // as a baseline for the following report, so store the delta counts as a new struct
    delta_peer_metrics_map
}
