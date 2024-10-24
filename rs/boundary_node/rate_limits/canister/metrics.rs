use crate::storage::API_BOUNDARY_NODE_PRINCIPALS;
use ic_canisters_http_types::{HttpResponse, HttpResponseBuilder};

/// Encode the metrics in a format that can be understood by Prometheus
pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    // retrieve the count of boundary nodes with full access
    let api_bns_count = API_BOUNDARY_NODE_PRINCIPALS.with(|cell| cell.borrow().len());

    // Encode the gauge for Prometheus
    w.encode_gauge(
        "rate_limit_canister_api_boundary_nodes_total",
        api_bns_count as f64,
        "Number of API boundary nodes with full read access permission to rate-limit config",
    )?;
    Ok(())
}

/// Serve the encoded metrics as an HTTP response.
pub fn serve_metrics(
    time: i64,
    encode_metrics: impl FnOnce(&mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()>,
) -> HttpResponse {
    let mut writer = ic_metrics_encoder::MetricsEncoder::new(vec![], time);

    // TODO: Consider implementing metrics versioning

    match encode_metrics(&mut writer) {
        Ok(()) => HttpResponseBuilder::ok()
            .header("Content-Type", "text/plain")
            .with_body_and_content_length(writer.into_inner())
            .build(),
        Err(err) => {
            // Return an HTTP 500 error with detailed error information
            HttpResponseBuilder::server_error(format!("Failed to encode metrics: {:?}", err))
                .build()
        }
    }
}
