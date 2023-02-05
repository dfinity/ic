use crate::metrics_parse_error::MetricsParseError;
use hyper::client::HttpConnector;
use hyper::{Client, StatusCode, Uri};
use ic_base_types::{NodeId, PrincipalId};
use itertools::Itertools;
use prometheus_parse::Scrape;
use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

const RETRY_INTERVAL_SEC: Duration = Duration::from_secs(30);

const ADVERT_QUEUE_ADD_METRIC: &str = "advert_queue_add";
const PEER_LABEL: &str = "peer";

pub async fn get_peer_ids(
    client: Client<HttpConnector>,
) -> Result<HashSet<NodeId>, MetricsParseError> {
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
                    return peer_id_from_raw_response(resp);
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
// Derive peer id  using the advert_queue_add metrics
// Assumes endpoint response is well formatted
fn peer_id_from_raw_response(response: String) -> Result<HashSet<NodeId>, MetricsParseError> {
    let lines = response.lines().map(|s| Ok(s.to_string()));
    let metrics = Scrape::parse(lines)
        .map_err(|_| MetricsParseError::HttpResponseError("prometheus scrape error".to_string()))?;

    // Get full list of peer ids from "advert_queue_add" metric
    let mut node_ids_iter = metrics
        .samples
        .iter()
        .filter(|&sample| sample.metric == ADVERT_QUEUE_ADD_METRIC)
        .map(|sample| sample.labels.get(PEER_LABEL));

    if node_ids_iter.all(|x| x.is_none()) {
        return Err(MetricsParseError::MetricLabelNotFound);
    }

    let node_ids_vec: Vec<&str> = node_ids_iter.flatten().unique().collect();
    let mut node_ids = HashSet::new();

    for node_id in node_ids_vec {
        let principal_id = PrincipalId::from_str(node_id).map_err(|_| {
            MetricsParseError::PeerLabelToIdConversionFailure(
                "Could not convert string to Principal Id".to_string(),
            )
        })?;
        node_ids.insert(NodeId::from(principal_id));
    }
    Ok(node_ids)
}
