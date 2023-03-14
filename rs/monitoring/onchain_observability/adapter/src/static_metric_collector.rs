use crate::metrics_parse_error::MetricsCollectError;
use ic_onchain_observability_service::{
    onchain_observability_service_client::OnchainObservabilityServiceClient,
    OnchainObservabilityServiceGetMetricsDataRequest,
};
use prometheus_parse::{Scrape, Value};
use std::time::{Duration, SystemTime};
use tonic::transport::Channel;

const PROCESS_START_TIME_METRIC: &str = "process_start_time_seconds";
// TODO make these config-based
const RETRY_INTERVAL_SEC: Duration = Duration::from_secs(30);
const TIMEOUT_LENGTH_SEC: Duration = Duration::from_secs(30);
const MAX_ATTEMPTS: u64 = 5;

// TODO(NET-1365) Come up with more generic interface for fetching multiple metrics + consolidate shared code with sampling code
pub async fn get_replica_last_start_time(
    mut client: OnchainObservabilityServiceClient<Channel>,
) -> Result<SystemTime, MetricsCollectError> {
    let request = OnchainObservabilityServiceGetMetricsDataRequest {
        requested_metrics: vec![PROCESS_START_TIME_METRIC.to_string()],
    };

    for attempt in 0..MAX_ATTEMPTS {
        let mut tonic_request = tonic::Request::new(request.clone());
        tonic_request.set_timeout(TIMEOUT_LENGTH_SEC);

        match client.get_metrics_data(tonic_request).await {
            Ok(response) => {
                return replica_last_start_from_raw_response(response.into_inner().metrics_data)
            }
            Err(e) => {
                // TODO(NET-1338) add metric to track when grpc fails
                if attempt == MAX_ATTEMPTS - 1 {
                    return Err(MetricsCollectError::RpcRequestFailure(format!(
                        "Request failed: {:?}",
                        e
                    )));
                }
            }
        }
        tokio::time::sleep(RETRY_INTERVAL_SEC).await;
    }
    Err(MetricsCollectError::RpcRequestFailure(
        "No requests were sent: MAX_ATTEMPTS must be > 0".to_string(),
    ))
}

// Since metrics endpoint is a giant string, we must manually scrape relevant data
// Assumes endpoint response is well formatted
fn replica_last_start_from_raw_response(
    response: String,
) -> Result<SystemTime, MetricsCollectError> {
    let lines = response.lines().map(|s| Ok(s.to_string()));
    let metrics = Scrape::parse(lines).map_err(|_| {
        MetricsCollectError::RpcRequestFailure("prometheus scrape error".to_string())
    })?;

    let replica_last_start_time_vec: Vec<&Value> = metrics
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
