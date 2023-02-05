use crate::metrics_parse_error::MetricsParseError;
use hyper::client::HttpConnector;
use hyper::{Client, StatusCode, Uri};
use prometheus_parse::{Sample, Scrape, Value};
use std::collections::HashMap;

const CONNECTED_STATE: u64 = 3;

const FLOW_STATE_METRIC: &str = "transport_flow_state";
const PEER_ID: &str = "flow_peer_id";

// Fetches metrics through http requests to [node ip]:9090
// Note: This approach will be replaced by gRPC call to replica
#[derive(Default)]
pub struct SampledMetricsCollector {
    num_samples: u64,
    connected_state_count: HashMap<String, usize>,
    client: Client<HttpConnector>,
}

impl SampledMetricsCollector {
    pub fn new_with_client(client: Client<HttpConnector>) -> Self {
        SampledMetricsCollector {
            num_samples: 0,
            connected_state_count: HashMap::new(),
            client,
        }
    }

    pub async fn sample(&mut self) -> Result<(), MetricsParseError> {
        let uri: Uri = "http://127.0.0.1:9090".parse().unwrap();

        let http_response =
            self.client
                .get(uri.clone())
                .await
                .or(Err(MetricsParseError::HttpResponseError(
                    "Error with fetching metrics endpoint".to_string(),
                )))?;

        if http_response.status() != StatusCode::OK {
            let error_msg = format!(
                "Invalid status code: {:?}",
                http_response.status().to_string()
            );
            return Err(MetricsParseError::HttpResponseError(error_msg));
        }

        let body_bytes = hyper::body::to_bytes(http_response.into_body())
            .await
            .or(Err(MetricsParseError::HttpResponseError(
                "Error with bytes conversion".to_string(),
            )))?;

        let resp = String::from_utf8(body_bytes.to_vec()).map_err(|_| {
            MetricsParseError::HttpResponseError("Error with utf8 conversion".to_string())
        })?;

        // Manually scrape the http endpoint response
        let parsed_data = peer_label_and_connected_state_from_raw_response(resp)?;

        for (peer_label, connection_state) in parsed_data {
            // Originally store the counts of "connected state". Later, we will transform into a %
            if connection_state == CONNECTED_STATE {
                *self.connected_state_count.entry(peer_label).or_insert(0) += 1;
            }
        }

        self.num_samples += 1;
        Ok(())
    }

    pub fn aggregate(&mut self) -> HashMap<String, f32> {
        // Peer up time = (# responses in connected state) / (total responses)
        let mut up_time = HashMap::new();

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
// Derive connection state using the transport_flow_state metrics
// Assumes endpoint response is well formatted
fn peer_label_and_connected_state_from_raw_response(
    response: String,
) -> Result<Vec<(String, u64)>, MetricsParseError> {
    let mut res = vec![];

    let lines = response.lines().map(|s| Ok(s.to_string()));
    let metrics = Scrape::parse(lines)
        .map_err(|_| MetricsParseError::HttpResponseError("prometheus scrape error".to_string()))?;

    // Get peer *label* and connected state from transport flow state metric
    let flow_state_metric: Vec<_> = metrics
        .samples
        .iter()
        .filter(|&sample| sample.metric == FLOW_STATE_METRIC)
        .collect();

    for sample in flow_state_metric {
        let peer_label = sample
            .labels
            .get(PEER_ID)
            .ok_or(MetricsParseError::MetricLabelNotFound)?;
        let connection_state = get_connection_state(sample)?;
        res.push((peer_label.to_string(), connection_state));
    }
    Ok(res)
}

fn get_connection_state(sample: &Sample) -> Result<u64, MetricsParseError> {
    if let Value::Gauge(connection_state) = sample.value {
        return Ok(connection_state as u64);
    }
    Err(MetricsParseError::ConnectionStateParseFailure)
}
