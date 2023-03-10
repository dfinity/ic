use crate::metrics_parse_error::MetricsParseError;
use hyper::client::HttpConnector;
use hyper::{Client, StatusCode, Uri};
use prometheus_parse::{Scrape, Value};
use std::time::{Duration, SystemTime};

const PROCESS_START_TIME_METRIC: &str = "process_start_time_seconds";
const RETRY_INTERVAL_SEC: Duration = Duration::from_secs(30);

pub async fn get_replica_last_start_time(
    client: Client<HttpConnector>,
) -> Result<SystemTime, MetricsParseError> {
    let uri: Uri = "http://127.0.0.1:9090".parse().unwrap();

    // May need to wait until metrics endpoint is running.  Retry until response received
    loop {
        if let Ok(response) = client.get(uri.clone()).await {
            match response.status() {
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                    // Do nothing here to trigger retry loop
                }
                StatusCode::OK => {
                    let body_bytes = hyper::body::to_bytes(response.into_body()).await.or(Err(
                        MetricsParseError::HttpResponseError(
                            "Error with http response".to_string(),
                        ),
                    ))?;
                    let resp = String::from_utf8(body_bytes.to_vec()).map_err(|_| {
                        MetricsParseError::HttpResponseError(
                            "Error with bytes conversion".to_string(),
                        )
                    })?;
                    return replica_last_start_from_raw_response(resp);
                }
                _ => {
                    let error_msg =
                        format!("Invalid status code: {:?}", response.status().to_string());
                    return Err(MetricsParseError::HttpResponseError(error_msg));
                }
            }
        }
        tokio::time::sleep(RETRY_INTERVAL_SEC).await;
    }
}

// Since metrics endpoint is a giant string, we must manually scrape relevant data
// Assumes endpoint response is well formatted
fn replica_last_start_from_raw_response(response: String) -> Result<SystemTime, MetricsParseError> {
    let lines = response.lines().map(|s| Ok(s.to_string()));
    let metrics = Scrape::parse(lines)
        .map_err(|_| MetricsParseError::HttpResponseError("prometheus scrape error".to_string()))?;

    let replica_last_start_time_vec: Vec<&Value> = metrics
        .samples
        .iter()
        .filter(|&sample| sample.metric == PROCESS_START_TIME_METRIC)
        .map(|sample| &sample.value)
        .collect();

    if replica_last_start_time_vec.len() != 1 {
        return Err(MetricsParseError::MetricParseFailure(format!(
            "Expected exactly 1 field for replica start time, found {:?}",
            replica_last_start_time_vec.len()
        )));
    }

    if let Value::Gauge(last_start) = replica_last_start_time_vec[0] {
        let time = *last_start as u64;
        return SystemTime::UNIX_EPOCH
            .checked_add(Duration::new(time, 0))
            .ok_or_else(|| {
                MetricsParseError::MetricParseFailure(
                    "Replica last start value not convertible into system time".to_string(),
                )
            });
    }

    Err(MetricsParseError::MetricParseFailure(
        "Replica last start metric key found, but missing value".to_string(),
    ))
}
