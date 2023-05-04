use axum::{
    body::Body,
    http::{Response, StatusCode},
};
use prometheus::{Encoder, Registry, TextEncoder};

pub async fn handler(registry: &Registry) -> Response<Body> {
    let metric_families = registry.gather();

    let encoder = TextEncoder::new();

    let mut metrics_text = Vec::new();
    if encoder.encode(&metric_families, &mut metrics_text).is_err() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Internal Server Error".into())
            .unwrap();
    };

    Response::builder()
        .status(200)
        .body(metrics_text.into())
        .unwrap()
}
