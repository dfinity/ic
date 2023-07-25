use crate::{error_types::MetricsCollectError, OnchainObservabilityAdapterMetrics};
use ic_onchain_observability_service::{
    onchain_observability_service_client::OnchainObservabilityServiceClient,
    OnchainObservabilityServiceGetMetricsDataRequest,
};
use prometheus_parse::{Sample, Scrape, Value};
use std::{collections::HashMap, time::Duration};
use tonic::transport::Channel;

const CONNECTED_STATE: u64 = 3;
const CONNECTION_STATE_METRIC: &str = "transport_connection_state";
const PEER_ID: &str = "peer_id";
const TIMEOUT_LENGTH_SEC: Duration = Duration::from_secs(30);

// TODO(NET-1365) Come up with more generic interface for fetching multiple metrics + consolidate shared code with sampling code

// Provides an API for fetching metrics periodically and aggregating results.
// Intended usage: Call sample() until desire sample size is received. Then call aggregate() to return result.  Finally, call clear() to reset the counters.
pub struct SampledMetricsCollector {
    num_samples: u64,
    connected_state_count: HashMap<String, usize>,
    client: OnchainObservabilityServiceClient<Channel>,
    adapter_metrics: OnchainObservabilityAdapterMetrics,
}

impl SampledMetricsCollector {
    pub fn new(
        client: OnchainObservabilityServiceClient<Channel>,
        adapter_metrics: OnchainObservabilityAdapterMetrics,
    ) -> Self {
        SampledMetricsCollector {
            num_samples: 0,
            connected_state_count: HashMap::new(),
            client,
            adapter_metrics,
        }
    }

    pub async fn sample(&mut self) -> Result<(), MetricsCollectError> {
        let request = OnchainObservabilityServiceGetMetricsDataRequest {
            requested_metrics: vec![CONNECTION_STATE_METRIC.to_string()],
        };

        let mut tonic_request = tonic::Request::new(request.clone());
        tonic_request.set_timeout(TIMEOUT_LENGTH_SEC);

        match self.client.clone().get_metrics_data(tonic_request).await {
            Ok(response) => {
                let parsed_data = peer_label_and_connected_state_from_raw_response(
                    response.into_inner().metrics_data,
                )?;
                // Track the counts of "connected state". Later, we will transform into a %
                for (peer_label, connection_state) in parsed_data {
                    if connection_state == CONNECTED_STATE {
                        *self.connected_state_count.entry(peer_label).or_insert(0) += 1;
                    }
                }
                self.num_samples += 1;
                Ok(())
            }
            Err(status) => {
                self.adapter_metrics
                    .failed_grpc_requests_total
                    .with_label_values(&["sampled", &status.code().to_string()])
                    .inc();

                Err(MetricsCollectError::RpcRequestFailure(format!(
                    "Request failed {:?}",
                    status.code()
                )))
            }
        }
    }

    pub fn aggregate(&mut self) -> HashMap<String, f32> {
        // Peer up time = (# responses in connected state) / (total responses)
        let mut up_time = HashMap::new();
        if self.num_samples == 0 {
            return up_time;
        }

        for (peer_id, connected_count) in self.connected_state_count.iter() {
            let percent = ((*connected_count as f32) * 100.0) / (self.num_samples as f32);
            up_time.insert(peer_id.clone(), percent);
        }
        up_time
    }

    pub fn clear(&mut self) {
        self.num_samples = 0;
        self.connected_state_count = HashMap::new();
    }
}

// Since metrics endpoint is a giant string, we must manually scrape relevant data
// Derive connection state using the transport_connection_state metrics
// Assumes endpoint response is well formatted
fn peer_label_and_connected_state_from_raw_response(
    response: String,
) -> Result<Vec<(String, u64)>, MetricsCollectError> {
    let mut res = vec![];

    let lines = response.lines().map(|s| Ok(s.to_string()));
    let metrics = Scrape::parse(lines).map_err(|_| {
        MetricsCollectError::RpcRequestFailure("prometheus scrape error".to_string())
    })?;

    // Get peer *label* and connected state from transport connection state metric
    let connection_state_metric: Vec<_> = metrics
        .samples
        .iter()
        .filter(|&sample| sample.metric == CONNECTION_STATE_METRIC)
        .collect();

    for sample in connection_state_metric {
        let peer_label = sample.labels.get(PEER_ID).ok_or_else(|| {
            MetricsCollectError::MetricParseFailure("Failed to get peer id label".to_string())
        })?;
        let connection_state = get_connection_state(sample)?;
        res.push((peer_label.to_string(), connection_state));
    }
    Ok(res)
}

fn get_connection_state(sample: &Sample) -> Result<u64, MetricsCollectError> {
    if let Value::Gauge(connection_state) = sample.value {
        return Ok(connection_state as u64);
    }
    Err(MetricsCollectError::MetricParseFailure(
        ("Failed to find connection state").to_string(),
    ))
}
