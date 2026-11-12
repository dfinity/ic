use super::*;
use actix_web::dev::Service as _;
use axum::{Router, http::Method, routing::post};
use prometheus::proto::MetricFamily;
use tower::ServiceExt;

const NUM_REQUESTS: usize = 20;

fn label_value<'a>(metric: &'a prometheus::proto::Metric, name: &str) -> Option<&'a str> {
    metric
        .get_label()
        .iter()
        .find(|label| label.name() == name)
        .map(|label| label.value())
}

fn series<'a>(
    families: &'a [MetricFamily],
    family_name: &str,
) -> Vec<&'a prometheus::proto::Metric> {
    families
        .iter()
        .filter(|family| family.name() == family_name)
        .flat_map(|family| family.get_metric().iter())
        .collect()
}

fn axum_series_labels(token_display_name: &str) -> Vec<(String, String)> {
    let families = prometheus::default_registry().gather();
    series(&families, "rosetta_http_request_duration_seconds")
        .into_iter()
        .filter(|metric| label_value(metric, "token_display_name") == Some(token_display_name))
        .map(|metric| {
            (
                label_value(metric, "endpoint").unwrap().to_string(),
                label_value(metric, "method").unwrap().to_string(),
            )
        })
        .collect()
}

fn axum_router(token_display_name: &str) -> Router {
    let metrics = RosettaMetrics::new(
        token_display_name.to_string(),
        format!("{token_display_name}_canister"),
    );
    Router::new()
        .route("/block", post(|| async { "ok" }))
        .layer(metrics.metrics_layer())
}

async fn send_axum_request(router: &Router, method: Method, path: &str) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    router.clone().oneshot(request).await.unwrap();
}

#[tokio::test]
async fn axum_registered_route_keeps_its_labels() {
    let token = "axum_registered_route_keeps_its_labels";
    let router = axum_router(token);

    send_axum_request(&router, Method::POST, "/block").await;

    assert_eq!(
        axum_series_labels(token),
        vec![("/block".to_string(), "POST".to_string())]
    );
}

#[tokio::test]
async fn axum_unmatched_paths_share_a_single_label() {
    let token = "axum_unmatched_paths_share_a_single_label";
    let router = axum_router(token);

    for i in 0..NUM_REQUESTS {
        send_axum_request(&router, Method::POST, &format!("/unknown/{i}")).await;
    }

    assert_eq!(
        axum_series_labels(token),
        vec![(UNMATCHED_ENDPOINT_LABEL.to_string(), "POST".to_string())]
    );
}

#[tokio::test]
async fn axum_non_standard_methods_share_a_single_label() {
    let token = "axum_non_standard_methods_share_a_single_label";
    let router = axum_router(token);

    for i in 0..NUM_REQUESTS {
        let method = Method::from_bytes(format!("CUSTOM{i}").as_bytes()).unwrap();
        send_axum_request(&router, method, "/block").await;
    }

    assert_eq!(
        axum_series_labels(token),
        vec![("/block".to_string(), OTHER_METHOD_LABEL.to_string())]
    );
}

fn actix_series_labels(registry: &Registry) -> Vec<(String, String)> {
    let families = registry.gather();
    let mut labels: Vec<_> = series(&families, "rosetta_http_requests_total")
        .into_iter()
        .map(|metric| {
            (
                label_value(metric, "endpoint").unwrap().to_string(),
                label_value(metric, "method").unwrap().to_string(),
            )
        })
        .collect();
    labels.sort();
    labels
}

async fn actix_series_after_requests(
    requests: impl IntoIterator<Item = (ActixMethod, String)>,
) -> Vec<(String, String)> {
    let registry = Registry::new();
    let prometheus_metrics = http_metrics_builder(registry.clone()).build().unwrap();
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .wrap(prometheus_metrics)
            .wrap_fn(|mut req, srv| {
                normalize_http_method(&mut req);
                srv.call(req)
            })
            .service(
                actix_web::web::resource("/block")
                    .route(actix_web::web::post().to(|| async { "ok" })),
            ),
    )
    .await;

    for (method, path) in requests {
        let request = actix_web::test::TestRequest::with_uri(&path)
            .method(method)
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        actix_web::test::read_body(response).await;
    }

    actix_series_labels(&registry)
}

#[actix_web::test]
async fn actix_registered_route_keeps_its_labels() {
    let labels = actix_series_after_requests([(ActixMethod::POST, "/block".to_string())]).await;

    assert_eq!(labels, vec![("/block".to_string(), "POST".to_string())]);
}

#[actix_web::test]
async fn actix_unmatched_paths_share_a_single_label() {
    let labels = actix_series_after_requests(
        (0..NUM_REQUESTS).map(|i| (ActixMethod::POST, format!("/unknown/{i}"))),
    )
    .await;

    assert_eq!(
        labels,
        vec![(UNMATCHED_ENDPOINT_LABEL.to_string(), "POST".to_string())]
    );
}

#[actix_web::test]
async fn actix_non_standard_methods_share_a_single_label() {
    let labels = actix_series_after_requests((0..NUM_REQUESTS).map(|i| {
        (
            ActixMethod::from_bytes(format!("CUSTOM{i}").as_bytes()).unwrap(),
            "/block".to_string(),
        )
    }))
    .await;

    assert_eq!(
        labels,
        vec![("/block".to_string(), OTHER_METHOD_LABEL.to_string())]
    );
}

#[test]
fn standard_methods_keep_their_label() {
    for method in [
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    ] {
        assert_eq!(http_method_label(method), method);
    }
    assert_eq!(http_method_label("get"), OTHER_METHOD_LABEL);
    assert_eq!(http_method_label("CUSTOM"), OTHER_METHOD_LABEL);
}
