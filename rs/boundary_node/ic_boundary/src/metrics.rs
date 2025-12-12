use std::{
    sync::{Arc, RwLock},
    time::{Instant, SystemTime},
};

use anyhow::Error;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use axum::{
    Extension,
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use candid::Principal;
use http::header::CONTENT_TYPE;
use humantime::format_rfc3339;
use ic_bn_lib::http::{body::CountingBody, cache::CacheStatus, http_version};
use ic_bn_lib::{
    prometheus::{
        Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Registry,
        TextEncoder, proto::MetricFamily, register_histogram_vec_with_registry,
        register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
        register_int_gauge_with_registry,
    },
    pubsub::Broker,
};
use ic_bn_lib_common::{traits::Run, types::http::ConnInfo};
use ic_types::{CanisterId, SubnetId, messages::ReplicaHealthStatus};
use serde_json::json;
use sha3::{Digest, Sha3_256};
use tikv_jemalloc_ctl::{epoch, stats};
use tokio_util::sync::CancellationToken;
use tower_http::request_id::RequestId;
use tracing::info;

use crate::{
    errors::ErrorCause,
    http::{
        RequestType,
        middleware::{cache::CacheState, geoip, retry::RetryResult},
    },
    routes::{Health, RequestContext},
    snapshot::{Node, RegistrySnapshot, Subnet},
};

const KB: f64 = 1024.0;

pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.2, 0.5, 1.0, 2.0, 4.0, 7.0, 11.0];
pub const HTTP_REQUEST_SIZE_BUCKETS: &[f64] = &[128.0, KB, 2.0 * KB, 4.0 * KB, 8.0 * KB];
pub const HTTP_RESPONSE_SIZE_BUCKETS: &[f64] = &[1.0 * KB, 8.0 * KB, 64.0 * KB, 256.0 * KB];

// https://prometheus.io/docs/instrumenting/exposition_formats/#basic-info
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

const NODE_ID_LABEL: &str = "node_id";
const SUBNET_ID_LABEL: &str = "subnet_id";
const SUBNET_ID_UNKNOWN: &str = "unknown";

pub(crate) const MAX_LOGGING_METHOD_NAME_LENGTH: usize = 50;

/// Stores the serialized metrics for a faster scraping
pub struct MetricsCache {
    buffer: Vec<u8>,
}

impl MetricsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            // Preallocate a large enough vector, it'll be expanded if needed
            buffer: Vec::with_capacity(capacity),
        }
    }
}

/// Iterates over given metric families and removes metrics that have
/// node_id+subnet_id labels and where the corresponding nodes are
/// no longer present in the given registry snapshot.
/// This helps to keep the metrics clean of obsolete nodes.
fn remove_stale_metrics(
    snapshot: Arc<RegistrySnapshot>,
    mut mfs: Vec<MetricFamily>,
) -> Vec<MetricFamily> {
    mfs.iter_mut().for_each(|mf| {
        // Iterate over the metrics in the metric family
        let metrics = mf
            .take_metric()
            .into_iter()
            .filter(|v| {
                // See if this metric has node_id/subnet_id labels
                let node_id = v
                    .get_label()
                    .iter()
                    .find(|&v| v.name() == NODE_ID_LABEL)
                    .map(|x| x.value());

                let subnet_id = v
                    .get_label()
                    .iter()
                    .find(|&v| v.name() == SUBNET_ID_LABEL)
                    .map(|x| x.value());

                match (node_id, subnet_id) {
                    // Check if we got both node_id and subnet_id labels
                    (Some(node_id), Some(subnet_id)) => snapshot
                        .nodes
                        // Check if the node_id is in the snapshot
                        .get(node_id)
                        // Check if its subnet_id matches, otherwise the metric needs to be removed
                        .map(|x| x.subnet_id.to_string() == subnet_id)
                        .unwrap_or(false),

                    // If there's only subnet_id label - check if this subnet exists.
                    // TODO create a hashmap of subnets in snapshot for faster lookup, currently complexity is O(n)
                    // but since we have very few subnets currently (<40) probably it's Ok
                    (None, Some(subnet_id)) => {
                        subnet_id == SUBNET_ID_UNKNOWN
                            || snapshot
                                .subnets
                                .iter()
                                .any(|x| x.id.to_string() == subnet_id)
                    }

                    // Otherwise just pass this metric through
                    _ => true,
                }
            })
            .collect();

        mf.set_metric(metrics);
    });

    mfs
}

/// Snapshots & encodes the metrics for the handler to export
pub struct MetricsRunner {
    metrics_cache: Arc<RwLock<MetricsCache>>,
    registry: Registry,
    encoder: TextEncoder,

    cache_state: Option<Arc<CacheState>>,

    mem_allocated: IntGauge,
    mem_resident: IntGauge,
    healthy: IntGauge,

    published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    health: Arc<dyn Health>,
}

impl MetricsRunner {
    pub fn new(
        metrics_cache: Arc<RwLock<MetricsCache>>,
        registry: Registry,
        cache_state: Option<Arc<CacheState>>,
        published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
        health: Arc<dyn Health>,
    ) -> Self {
        let mem_allocated = register_int_gauge_with_registry!(
            format!("memory_allocated"),
            format!("Allocated memory in bytes"),
            registry
        )
        .unwrap();

        let mem_resident = register_int_gauge_with_registry!(
            format!("memory_resident"),
            format!("Resident memory in bytes"),
            registry
        )
        .unwrap();

        let healthy = register_int_gauge_with_registry!(
            format!("healthy"),
            format!("Node health status"),
            registry
        )
        .unwrap();

        Self {
            metrics_cache,
            registry,
            encoder: TextEncoder::new(),
            cache_state,
            mem_allocated,
            mem_resident,
            healthy,
            published_registry_snapshot,
            health,
        }
    }
}

#[async_trait]
impl Run for MetricsRunner {
    async fn run(&self, _: CancellationToken) -> Result<(), Error> {
        // Record jemalloc memory usage
        epoch::advance().unwrap();
        self.mem_allocated
            .set(stats::allocated::read().unwrap() as i64);
        self.mem_resident
            .set(stats::resident::read().unwrap() as i64);

        if let Some(v) = &self.cache_state {
            v.update_metrics().await;
        }

        // Record health metric
        let healthy: i64 = (self.health.health() == ReplicaHealthStatus::Healthy).into();
        self.healthy.set(healthy);

        // Get a snapshot of metrics
        let mut metric_families = self.registry.gather();

        // If we have a published snapshot - use it to remove the metrics not present anymore
        if let Some(snapshot) = self.published_registry_snapshot.load_full() {
            metric_families = remove_stale_metrics(snapshot, metric_families);
        }

        // Take a write lock, truncate the vector and encode the metrics into it
        let mut metrics_cache = self.metrics_cache.write().unwrap();
        metrics_cache.buffer.clear();
        self.encoder
            .encode(&metric_families, &mut metrics_cache.buffer)?;

        Ok(())
    }
}

pub struct WithMetricsPersist<T>(pub T, pub MetricParamsPersist);

#[derive(Clone)]
pub struct MetricParamsPersist {
    pub ranges: IntGauge,
    pub nodes: IntGauge,
}

impl MetricParamsPersist {
    pub fn new(registry: &Registry) -> Self {
        Self {
            // Number of ranges
            ranges: register_int_gauge_with_registry!(
                format!("persist_ranges"),
                format!("Number of canister ranges currently published"),
                registry
            )
            .unwrap(),

            // Number of nodes
            nodes: register_int_gauge_with_registry!(
                format!("persist_nodes"),
                format!("Number of nodes currently published"),
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct WithMetricsCheck<T>(pub T, pub MetricParamsCheck);

#[derive(Clone)]
pub struct MetricParamsCheck {
    pub counter: IntCounterVec,
    pub recorder: HistogramVec,
    pub status: IntGaugeVec,
}

impl MetricParamsCheck {
    pub fn new(registry: &Registry) -> Self {
        let mut opts = HistogramOpts::new(
            "check_duration_sec",
            "Records the duration of check calls in seconds",
        );
        opts.buckets = HTTP_DURATION_BUCKETS.to_vec();

        let labels = &["status", NODE_ID_LABEL, SUBNET_ID_LABEL, "addr"];

        Self {
            counter: register_int_counter_vec_with_registry!(
                "check_total",
                "Counts occurrences of check calls",
                labels,
                registry
            )
            .unwrap(),

            // Duration
            recorder: register_histogram_vec_with_registry!(opts, labels, registry).unwrap(),

            // Status of node
            status: register_int_gauge_vec_with_registry!(
                "check_status",
                "Last check result of a given node",
                &labels[1..4],
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct HttpMetricParams {
    pub action: String,
    pub log_failed_requests_only: bool,
    pub counter: IntCounterVec,
    pub durationer: HistogramVec,
    pub request_sizer: HistogramVec,
    pub response_sizer: HistogramVec,
    pub anonymization_salt: Arc<ArcSwapOption<Vec<u8>>>,
    pub logs_broker: Option<Arc<Broker<Bytes, Principal>>>,
}

impl HttpMetricParams {
    pub fn new(
        registry: &Registry,
        action: &str,
        log_failed_requests_only: bool,
        anonymization_salt: Arc<ArcSwapOption<Vec<u8>>>,
        logs_broker: Option<Arc<Broker<Bytes, Principal>>>,
    ) -> Self {
        const LABELS_HTTP: &[&str] = &[
            "request_type",
            "status_code",
            SUBNET_ID_LABEL,
            "error_cause",
            "cache_status",
            "cache_bypass",
            "retry",
        ];

        Self {
            action: action.to_string(),
            log_failed_requests_only,

            counter: register_int_counter_vec_with_registry!(
                format!("{action}_total"),
                format!("Counts occurrences of {action} calls"),
                LABELS_HTTP,
                registry
            )
            .unwrap(),

            durationer: register_histogram_vec_with_registry!(
                format!("{action}_duration_sec"),
                format!("Records the duration of {action} request processing in seconds"),
                LABELS_HTTP,
                HTTP_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            request_sizer: register_histogram_vec_with_registry!(
                format!("{action}_request_size"),
                format!("Records the size of {action} requests"),
                LABELS_HTTP,
                HTTP_REQUEST_SIZE_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            response_sizer: register_histogram_vec_with_registry!(
                format!("{action}_response_size"),
                format!("Records the size of {action} responses"),
                LABELS_HTTP,
                HTTP_RESPONSE_SIZE_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            anonymization_salt,
            logs_broker,
        }
    }
}

pub struct WithMetricsSnapshot<T>(pub T, pub MetricParamsSnapshot);

#[derive(Clone)]
pub struct MetricParamsSnapshot {
    pub version: IntGauge,
    pub timestamp: IntGauge,
}

impl MetricParamsSnapshot {
    pub fn new(registry: &Registry) -> Self {
        Self {
            version: register_int_gauge_with_registry!(
                format!("registry_version"),
                format!("Currently published registry version"),
                registry
            )
            .unwrap(),

            timestamp: register_int_gauge_with_registry!(
                format!("registry_timestamp"),
                format!("Timestamp of the last registry update"),
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct HttpMetricParamsStatus {
    pub counter: IntCounterVec,
}

impl HttpMetricParamsStatus {
    pub fn new(registry: &Registry) -> Self {
        Self {
            counter: register_int_counter_vec_with_registry!(
                format!("http_request_status_total"),
                format!("Counts occurrences of status calls"),
                &["health"],
                registry
            )
            .unwrap(),
        }
    }
}

pub async fn metrics_middleware_status(
    State(metric_params): State<HttpMetricParamsStatus>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let response = next.run(request).await;
    let health = response
        .extensions()
        .get::<ReplicaHealthStatus>()
        .unwrap()
        .as_ref();

    let HttpMetricParamsStatus { counter } = metric_params;
    counter.with_label_values(&[health]).inc();

    response
}

/// Middleware to log and measure proxied requests
pub async fn metrics_middleware(
    State(metric_params): State<HttpMetricParams>,
    Extension(request_id): Extension<RequestId>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let request_id = request_id.header_value().to_str().unwrap_or("").to_string();

    let ip_family = request
        .extensions()
        .get::<Arc<ConnInfo>>()
        .map(|x| {
            let f = x.remote_addr.family();
            if f == "v4" {
                4
            } else if f == "v6" {
                6
            } else {
                0
            }
        })
        .unwrap_or(0);

    let remote_addr = request
        .extensions()
        .get::<Arc<ConnInfo>>()
        .map(|x| x.remote_addr.ip().to_canonical().to_string())
        .unwrap_or_default();

    let request_type = &request
        .extensions()
        .get::<RequestType>()
        .cloned()
        .unwrap_or_default();
    let request_type: &'static str = request_type.into();

    let country_code = request
        .extensions()
        .get::<geoip::GeoData>()
        .map(|x| x.country_code.clone())
        .unwrap_or("N/A".into());

    // for canister requests we extract canister_id
    let canister_id = request.extensions().get::<CanisterId>().map(|x| x.get().0);
    let canister_id_str = canister_id.map(|x| x.to_string());

    // for /api/v2/subnet requests we extract subnet_id directly from extension
    let subnet_id = request.extensions().get::<SubnetId>().map(|x| x.get().0);
    let subnet_id_str = subnet_id.map(|x| x.to_string());

    let http_version = http_version(request.version());

    // Perform the request & measure duration
    let start_time = Instant::now();
    let response = next.run(request).await;
    let proc_duration = start_time.elapsed().as_secs_f64();

    // in case subnet_id=None (i.e. for /api/v2/canister/... request), we get the target subnet_id from the Subnet extension
    let subnet_id = subnet_id.or(response.extensions().get::<Arc<Subnet>>().map(|x| x.id));
    let subnet_id_str = subnet_id_str.or(subnet_id.map(|x| x.to_string()));

    // Extract extensions
    let ctx = response
        .extensions()
        .get::<Arc<RequestContext>>()
        .cloned()
        .unwrap_or_default();

    // Actual canister id is the one the request was routed to.
    // Might be different from request canister id
    let canister_id_actual = response.extensions().get::<CanisterId>().cloned();
    let error_cause = response.extensions().get::<ErrorCause>().cloned();
    let retry_result = response.extensions().get::<RetryResult>().cloned();
    let node = response.extensions().get::<Arc<Node>>();
    let cache_status = response
        .extensions()
        .get::<CacheStatus>()
        .cloned()
        .unwrap_or_default();

    // Prepare fields
    let status_code = response.status();
    let sender = ctx.sender.map(|x| x.to_string()).unwrap_or_default();
    let node_id = node.as_ref().map(|x| x.id.to_string());

    let HttpMetricParams {
        action,
        log_failed_requests_only,
        counter,
        durationer,
        request_sizer,
        response_sizer,
        anonymization_salt,
        logs_broker,
    } = metric_params;

    let (parts, body) = response.into_parts();
    let (body, rx) = CountingBody::new(body);

    tokio::spawn(async move {
        // Wait for the streaming to finish
        let response_size = rx.await.unwrap_or(Ok(0)).unwrap_or(0);

        let full_duration = start_time.elapsed().as_secs_f64();
        let failed = error_cause.is_some() || !status_code.is_success();

        let (error_cause, error_details) = match &error_cause {
            Some(v) => (Some(v.to_string()), v.details()),
            None => (None, None),
        };

        let cache_bypass_reason = match &cache_status {
            CacheStatus::Bypass(v) => Some(v.to_string()),
            _ => None,
        };

        let retry_result = retry_result.clone();

        // Prepare labels
        // Otherwise "temporary value dropped" error occurs
        let error_cause_lbl = error_cause.clone().unwrap_or("none".to_string());
        let subnet_id_lbl = subnet_id_str
            .clone()
            .unwrap_or_else(|| SUBNET_ID_UNKNOWN.to_string());
        let cache_status_lbl = &cache_status.to_string();
        let cache_bypass_reason_lbl = cache_bypass_reason.clone().unwrap_or("none".to_string());
        let retry_lbl =
            // Check if retry happened and if it succeeded
            if let Some(v) = &retry_result {
                if v.success {
                    "ok"
                } else {
                    "fail"
                }
            } else {
                "no"
            };

        // Average cardinality up to 150k
        let labels = &[
            request_type,                     // x3
            status_code.as_str(),             // x27 but usually x8
            subnet_id_lbl.as_str(),           // x37 as of now
            error_cause_lbl.as_str(),         // x15 but usually x6
            cache_status_lbl.as_str(),        // x4
            cache_bypass_reason_lbl.as_str(), // x6 but since it relates only to BYPASS cache status -> total for 2 fields is x9
            retry_lbl,                        // x3
        ];

        counter.with_label_values(labels).inc();
        durationer.with_label_values(labels).observe(proc_duration);
        request_sizer
            .with_label_values(labels)
            .observe(ctx.request_size as f64);
        response_sizer
            .with_label_values(labels)
            .observe(response_size as f64);

        // Anonymization
        let salt = anonymization_salt.load();

        let hash_fn = |input: &str| -> String {
            let mut hasher = Sha3_256::new();

            if let Some(v) = salt.as_ref() {
                hasher.update(v.as_slice());
            } else {
                return "N/A".to_string();
            }

            hasher.update(input);
            let result = hasher.finalize();

            // SHA3-256 is guaranteed to be 32 bytes, so this is safe
            hex::encode(&result[..16])
        };

        let remote_addr_hashed = hash_fn(&remote_addr);
        let sender_hashed = hash_fn(&sender);

        let method_name = ctx.method_name.as_ref().map(|name| {
            let truncated_len = name.len().min(MAX_LOGGING_METHOD_NAME_LENGTH);
            name[..truncated_len].to_string()
        });

        // Log
        if !log_failed_requests_only || failed {
            info!(
                action,
                request_id,
                http = http_version,
                request_type,
                error_cause,
                error_details,
                status = status_code.as_u16(),
                subnet_id_str,
                node_id,
                canister_id_str,
                canister_id_actual = canister_id_actual.map(|x| x.to_string()),
                canister_id_cbor = ctx.canister_id.map(|x| x.to_string()),
                sender_hashed,
                remote_addr_hashed,
                method = method_name,
                duration = proc_duration,
                duration_full = full_duration,
                request_size = ctx.request_size,
                response_size,
                retry_count = &retry_result.as_ref().map(|x| x.retries),
                retry_success = &retry_result.as_ref().map(|x| x.success),
                %cache_status,
                cache_bypass_reason = cache_bypass_reason_lbl,
                country_code,
                client_ip_family = ip_family,
            );
        }

        // See if have a broker, a canister_id and then extract the topic
        if let Some(topic) = logs_broker
            .zip(canister_id)
            .and_then(|(broker, id)| broker.topic_get(&id))
        {
            let ts = format_rfc3339(SystemTime::now()).to_string();
            let client_id = hash_fn(&format!("{sender}{remote_addr}"));

            let msg = json!({
                "cache_status": cache_status_lbl,
                "cache_bypass_reason": cache_bypass_reason_lbl,
                "client_id": client_id,
                "client_ip_family": ip_family,
                "client_country_code": country_code,
                "duration": proc_duration,
                "error_cause": error_cause,
                "error_details": error_details,
                "http_status": status_code.as_u16(),
                "http_version": http_version,
                "ic_canister_id": canister_id_str,
                "ic_node_id": node_id.unwrap_or_default(),
                "ic_subnet_id": subnet_id_str,
                "ic_method": method_name,
                "request_id": request_id,
                "request_size": ctx.request_size,
                "request_type": request_type,
                "response_size": response_size,
                "timestamp": ts,
            });

            // We don't care for errors in this case
            let _ = topic.publish(Bytes::from(msg.to_string()));
        }
    });

    Response::from_parts(parts, body)
}

#[derive(Clone)]
pub struct MetricsHandlerArgs {
    pub cache: Arc<RwLock<MetricsCache>>,
}

/// Axum handler for /metrics endpoint
pub async fn metrics_handler(
    State(MetricsHandlerArgs { cache }): State<MetricsHandlerArgs>,
) -> impl IntoResponse {
    // Get a read lock and clone the buffer contents
    (
        [(CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        cache.read().unwrap().buffer.clone(),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::check::test::generate_custom_registry_snapshot;
    use ic_bn_lib::prometheus::proto::{LabelPair, Metric};

    // node_id, subnet_id
    const NODES: &[(&str, &str)] = &[
        ("y7s52-3xjam-aaaaa-aaaap-2ai", "fscpm-uiaaa-aaaaa-aaaap-yai"),
        ("ftjgm-3pkam-aaaaa-aaaap-2ai", "fscpm-uiaaa-aaaaa-aaaap-yai"),
        ("fat3m-uhiam-aaaaa-aaaap-2ai", "fscpm-uiaaa-aaaaa-aaaap-yai"),
        ("fat3m-uhiam-aaaaa-aaaap-2ai", "ascpm-uiaaa-aaaaa-aaaap-yai"), // node in snapshot, but in different subnet
        ("fat3n-uhiam-aaaaa-aaaap-2ai", "fscpm-uiaaa-aaaaa-aaaap-yai"), // node not in snapshot
        ("fat3o-uhiam-aaaaa-aaaap-2ai", "fscpm-uiaaa-aaaaa-aaaap-yai"), // node not in snapshot
    ];

    fn gen_metric(node_id: Option<String>, subnet_id: Option<String>) -> Metric {
        let mut m = Metric::new();

        let mut lbl = LabelPair::new();
        lbl.set_name("foo".into());
        lbl.set_value("bar".into());

        let mut lbls = vec![lbl];

        if let Some(v) = node_id {
            let mut lbl = LabelPair::new();
            lbl.set_name(NODE_ID_LABEL.into());
            lbl.set_value(v);
            lbls.push(lbl);
        }

        if let Some(v) = subnet_id {
            let mut lbl = LabelPair::new();
            lbl.set_name(SUBNET_ID_LABEL.into());
            lbl.set_value(v);
            lbls.push(lbl);
        }

        m.set_label(lbls);

        m
    }

    fn gen_metric_family(
        name: String,
        nodes: &[(&str, &str)],
        add_node_id: bool,
        add_subnet_id: bool,
    ) -> MetricFamily {
        let metrics = nodes
            .iter()
            .map(|&(node_id, subnet_id)| {
                gen_metric(
                    if add_node_id {
                        Some(node_id.into())
                    } else {
                        None
                    },
                    if add_subnet_id {
                        Some(subnet_id.into())
                    } else {
                        None
                    },
                )
            })
            .collect::<Vec<_>>();

        let mut mf = MetricFamily::new();
        mf.set_name(name);
        mf.set_metric(metrics);
        mf
    }

    fn gen_metric_families() -> Vec<MetricFamily> {
        let mut mfs = Vec::new();

        // These are with both labels defined
        for n in &["foobar", "foobaz", "fooboo"] {
            mfs.push(gen_metric_family((*n).into(), NODES, true, true));
        }

        // These with one of them
        mfs.push(gen_metric_family("boo".into(), NODES, false, true));
        mfs.push(gen_metric_family("goo".into(), NODES, true, false));

        // This without both them
        mfs.push(gen_metric_family("zoo".into(), NODES, false, false));

        mfs
    }

    #[test]
    fn test_remove_stale_metrics() -> Result<(), Error> {
        // subnet id: fscpm-uiaaa-aaaaa-aaaap-yai
        // node ids in a snapshot:
        // - y7s52-3xjam-aaaaa-aaaap-2ai
        // - ftjgm-3pkam-aaaaa-aaaap-2ai
        // - fat3m-uhiam-aaaaa-aaaap-2ai
        let snapshot = Arc::new(generate_custom_registry_snapshot(1, 3, 0));
        let mfs = remove_stale_metrics(snapshot.clone(), gen_metric_families());
        assert_eq!(mfs.len(), 6);

        let mut only_node_id = 0;
        let mut only_subnet_id = 0;
        let mut no_ids = 0;

        // Check that the metric families now contain only metrics with node_id+subnet_id from the snapshot
        // and other metrics are untouched
        for mf in mfs {
            for m in mf.get_metric() {
                let node_id = m
                    .get_label()
                    .iter()
                    .find(|&v| v.name() == NODE_ID_LABEL)
                    .map(|x| x.value());

                let subnet_id = m
                    .get_label()
                    .iter()
                    .find(|&v| v.name() == SUBNET_ID_LABEL)
                    .map(|x| x.value());

                match (node_id, subnet_id) {
                    (Some(node_id), Some(subnet_id)) => assert!(
                        snapshot
                            .nodes
                            .get(node_id)
                            .map(|x| x.subnet_id.to_string() == subnet_id)
                            .unwrap_or(false)
                    ),

                    (Some(_), None) => only_node_id += 1,
                    (None, Some(_)) => only_subnet_id += 1,
                    _ => no_ids += 1,
                }
            }
        }

        assert_eq!(only_node_id, NODES.len());
        assert_eq!(only_subnet_id, NODES.len() - 1);
        assert_eq!(no_ids, NODES.len());

        Ok(())
    }
}
