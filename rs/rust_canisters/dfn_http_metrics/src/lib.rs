use dfn_http::types::{HttpRequest, HttpResponse};
use serde_bytes::ByteBuf;

/// Implements an HTTP endpoint that handles /metrics requests and return 404
/// for all other paths.
pub fn serve_metrics(
    encode_metrics: impl FnOnce(&mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()>,
) {
    dfn_core::over(
        dfn_candid::candid,
        |(req,): (HttpRequest,)| -> HttpResponse {
            let path = match req.url.find('?') {
                None => &req.url[..],
                Some(index) => &req.url[..index],
            };

            if path == "/metrics" {
                let mut writer = ic_metrics_encoder::MetricsEncoder::new(
                    vec![],
                    dfn_core::api::time_nanos() as i64 / 1_000_000,
                );
                match encode_metrics(&mut writer) {
                    Ok(()) => {
                        let body = writer.into_inner();
                        HttpResponse {
                            status_code: 200,
                            headers: vec![
                                (
                                    "Content-Type".to_string(),
                                    "text/plain; version=0.0.4".to_string(),
                                ),
                                ("Content-Length".to_string(), body.len().to_string()),
                            ],
                            body: ByteBuf::from(body),
                            streaming_strategy: None,
                        }
                    }
                    Err(err) => HttpResponse {
                        status_code: 500,
                        headers: vec![],
                        body: ByteBuf::from(format!("Failed to encode metrics: {}", err)),
                        streaming_strategy: None,
                    },
                }
            } else {
                HttpResponse {
                    status_code: 404,
                    headers: vec![],
                    body: ByteBuf::from("not found"),
                    streaming_strategy: None,
                }
            }
        },
    );
}
