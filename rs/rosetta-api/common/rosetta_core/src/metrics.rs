use actix_web_prom::{PrometheusMetrics, PrometheusMetricsBuilder};
use axum::{
    body::{Body, to_bytes},
    extract::Request,
    response::Response,
};
use bytes::Bytes;
use prometheus::{
    Encoder, GaugeVec, HistogramTimer, HistogramVec, IntCounterVec, IntGaugeVec,
    register_gauge_vec, register_histogram_vec, register_int_counter_vec, register_int_gauge_vec,
};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;
use strum_macros::IntoStaticStr;
use tower::{Layer, Service};

use lazy_static::lazy_static;
use tracing::log::warn;

lazy_static! {
    static ref ENDPOINTS_METRICS: RosettaEndpointsMetrics = RosettaEndpointsMetrics::new();

    static ref DATABASE_METRICS: RosettaDatabaseMetrics = RosettaDatabaseMetrics::new();

    static ref VERIFIED_HEIGHT: IntGaugeVec = register_int_gauge_vec!(
        "rosetta_verified_block_height",
        "Verified block height (index of the most recent block verified locally by Rosetta - all blocks with lower index will also have been verified)",
        &["token_display_name"]
    ).unwrap();
    static ref SYNCED_HEIGHT: IntGaugeVec = register_int_gauge_vec!(
        "rosetta_synched_block_height",
        "Synced block height (index of the most recent block synced by Rosetta - note that there may be gaps in the database)",
        &["token_display_name"]
    ).unwrap();
    static ref TARGET_HEIGHT: IntGaugeVec = register_int_gauge_vec!(
        "rosetta_target_block_height",
        "Target height / tip (the index of the most recent block in the ledger)",
        &["token_display_name"]
    ).unwrap();
    static ref SYNC_ERR_COUNTER: IntCounterVec = register_int_counter_vec!(
        "blockchain_sync_errors_total",
        "Number of times synchronization failed",
        &["token_display_name"],
    )
    .unwrap();
    static ref OUT_OF_SYNC_TIME: GaugeVec = register_gauge_vec!(
        "ledger_sync_attempt_duration_seconds",
        "Number of seconds since the last successful sync",
        &["token_display_name"],
    )
    .unwrap();
    static ref OUT_OF_SYNC_TIME_HIST: HistogramVec = register_histogram_vec!(
        "ledger_sync_attempt_duration_seconds_hist",
        "Number of seconds since last successful sync",
        &["token_display_name"],
        vec![0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 5.0, 10.0, 15.0],
    )
    .unwrap();
    static ref BLOCKS_FETCHED_COUNTER: IntCounterVec = register_int_counter_vec!(
        "ledger_sync_blocks_fetched_total",
        "Number of blocks fetched from the ledger",
        &["token_display_name"],
    ).unwrap();
    // Counter for number of retries when fetching blocks from the canister.
    static ref BLOCKS_FETCH_RETRIES_COUNTER: IntCounterVec = register_int_counter_vec!(
        "ledger_sync_blocks_fetch_retries_total",
        "Number of retries when fetching blocks from the ledger",
        &["token_display_name"],
    ).unwrap();

    pub static ref SYNC_THREAD_RESTARTS: IntCounterVec = register_int_counter_vec!(
        "blockchain_sync_thread_restarts_total",
        "Number of times the sync thread has been restarted",
        &["token_display_name"],
    )
    .unwrap();

    static ref METRICS: Mutex<Option<PrometheusMetrics>> = Mutex::new(None);

    // Map that associates canister ID strings with their display names
    static ref CANISTER_DISPLAY_NAMES: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

struct RosettaEndpointsMetrics {
    pub request_duration: HistogramVec,
    pub rosetta_api_status_total: IntCounterVec,
}

impl RosettaEndpointsMetrics {
    pub fn new() -> Self {
        Self {
            request_duration: register_histogram_vec!(
                "rosetta_http_request_duration_seconds",
                "HTTP request latency in seconds",
                &["token_display_name", "endpoint", "method", "status"]
            )
            .unwrap(),
            rosetta_api_status_total: register_int_counter_vec!(
                "rosetta_api_status_total",
                "Response status for ic-rosetta-api endpoints",
                &["token_display_name", "status_code"]
            )
            .unwrap(),
        }
    }
}

struct RosettaDatabaseMetrics {
    pub db_connection_lock_acquisition_duration: HistogramVec,
    pub db_operation_duration: HistogramVec,
}

impl RosettaDatabaseMetrics {
    pub fn new() -> Self {
        Self {
            db_connection_lock_acquisition_duration: register_histogram_vec!(
                "rosetta_db_connection_lock_acquisition_duration_seconds",
                "Database lock acquisition duration in seconds",
                &["token_display_name", "access_type", "operation"],
                vec![0.1, 1.0, 10.0, 100.0],
            )
            .unwrap(),
            db_operation_duration: register_histogram_vec!(
                "rosetta_db_operation_duration_seconds",
                "Database operation duration in seconds",
                &["token_display_name", "access_type", "operation"],
                vec![0.1, 1.0, 10.0, 100.0],
            )
            .unwrap(),
        }
    }
}

#[derive(Clone, Copy, IntoStaticStr)]
#[strum(serialize_all = "lowercase")]
pub enum AccessType {
    Read,
    Write,
}

#[derive(Clone, Copy, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum DatabaseOperation {
    GetAccountBalance,
    GetAccountBalanceAtBlockIdx,
    GetAggregatedBalanceForPrincipalAtBlockIdx,
    GetBlockAtIdx,
    GetBlockByHash,
    GetBlockchainGaps,
    GetBlockCount,
    GetBlocksByCustomQuery,
    GetBlocksByIndexRange,
    GetBlocksByTransactionHash,
    GetBlockWithHighestBlockIdx,
    GetBlockWithLowestBlockIdx,
    GetHighestBlockIdx,
    GetHighestBlockIdxInAccountBalanceTable,
    GetMetadata,
    RepairFeeCollectorBalances,
    ResetBlocksCounter,
    StoreBlocks,
    UpdateAccountBalances,
    WriteMetadata,
}

const DURATION_WARN_LOG_THRESHOLD: Duration = Duration::from_secs(10);

pub struct DbOperationMetrics {
    metrics: RosettaMetrics,
    access_type: AccessType,
    operation: DatabaseOperation,
    phase_start: std::time::Instant,
    operation_started: bool,
}

impl DbOperationMetrics {
    /// Starts measuring lock acquisition time.
    ///
    /// Call this before acquiring the database lock. The timer starts immediately.
    pub fn start(
        metrics: RosettaMetrics,
        access_type: AccessType,
        operation: DatabaseOperation,
    ) -> Self {
        Self {
            metrics,
            access_type,
            operation,
            phase_start: std::time::Instant::now(),
            operation_started: false,
        }
    }

    /// Records the lock acquisition duration and starts measuring the operation.
    ///
    /// Call this immediately after acquiring the database lock.
    pub fn lock_acquired(&mut self) {
        let lock_duration = self.phase_start.elapsed();
        if lock_duration > DURATION_WARN_LOG_THRESHOLD {
            let operation: &str = self.operation.into();
            let access_type: &str = self.access_type.into();
            warn!(
                "Long database lock acquisition: {} for {} took {:?}",
                operation, access_type, lock_duration
            );
        }
        self.metrics.observe_lock_acquisition_duration(
            self.access_type,
            self.operation,
            lock_duration.as_secs_f64(),
        );
        self.phase_start = std::time::Instant::now();
        self.operation_started = true;
    }
}

impl Drop for DbOperationMetrics {
    fn drop(&mut self) {
        if self.operation_started {
            let operation_duration = self.phase_start.elapsed();
            if operation_duration > DURATION_WARN_LOG_THRESHOLD {
                let operation: &str = self.operation.into();
                let access_type: &str = self.access_type.into();
                warn!(
                    "Long database operation: {} for {} took {:?}",
                    operation, access_type, operation_duration
                );
            }
            self.metrics.observe_db_operation_duration(
                self.access_type,
                self.operation,
                operation_duration.as_secs_f64(),
            );
        }
    }
}

/// Metrics accessor for the Rosetta endpoints.
/// This format is consistent across both Axum and Actix middleware implementations.
#[derive(Clone, Debug)]
pub struct RosettaMetrics {
    token_display_name: String,
    canister_id: String,
}

impl RosettaMetrics {
    pub fn new(token_display_name: String, canister_id: String) -> Self {
        // Add entry to map associating the canister ID with the display name
        let mut map = CANISTER_DISPLAY_NAMES.lock().unwrap();
        map.insert(canister_id.clone(), token_display_name.clone());

        Self {
            token_display_name,
            canister_id,
        }
    }

    pub fn token_display_name(&self) -> &str {
        &self.token_display_name
    }

    pub fn canister_id(&self) -> &str {
        &self.canister_id
    }

    pub fn inc_api_status_count(&self, status: &str) {
        let labels = &[self.token_display_name.as_str(), status];
        ENDPOINTS_METRICS
            .rosetta_api_status_total
            .with_label_values(labels)
            .inc();
    }

    // This method is deprecated and will be removed in a future version
    // It's kept for backward compatibility with existing code
    pub fn start_request_duration_timer(&self, endpoint: &str) -> HistogramTimer {
        let labels = &[
            self.token_display_name.as_str(),
            endpoint,
            "unknown",
            "unknown",
        ];
        ENDPOINTS_METRICS
            .request_duration
            .with_label_values(labels)
            .start_timer()
    }

    // New method to record request duration directly
    pub fn observe_request_duration(
        &self,
        endpoint: &str,
        method: &str,
        status: &str,
        duration: f64,
    ) {
        let labels = &[self.token_display_name.as_str(), endpoint, method, status];
        ENDPOINTS_METRICS
            .request_duration
            .with_label_values(labels)
            .observe(duration);
    }

    pub fn observe_lock_acquisition_duration(
        &self,
        access_type: AccessType,
        operation: DatabaseOperation,
        duration: f64,
    ) {
        let labels = &[
            self.token_display_name.as_str(),
            access_type.into(),
            operation.into(),
        ];
        DATABASE_METRICS
            .db_connection_lock_acquisition_duration
            .with_label_values(labels)
            .observe(duration);
    }

    pub fn observe_db_operation_duration(
        &self,
        access_type: AccessType,
        operation: DatabaseOperation,
        duration: f64,
    ) {
        let labels = &[
            self.token_display_name.as_str(),
            access_type.into(),
            operation.into(),
        ];
        DATABASE_METRICS
            .db_operation_duration
            .with_label_values(labels)
            .observe(duration);
    }

    pub fn set_target_height(&self, height: u64) {
        TARGET_HEIGHT
            .with_label_values(&[self.token_display_name.as_str()])
            .set(height.try_into().unwrap());
    }

    pub fn set_synced_height(&self, height: u64) {
        SYNCED_HEIGHT
            .with_label_values(&[self.token_display_name.as_str()])
            .set(height.try_into().unwrap());
    }

    pub fn set_verified_height(&self, height: u64) {
        VERIFIED_HEIGHT
            .with_label_values(&[self.token_display_name.as_str()])
            .set(height.try_into().unwrap());
    }

    pub fn set_out_of_sync_time(&self, seconds: f64) {
        OUT_OF_SYNC_TIME
            .with_label_values(&[self.token_display_name.as_str()])
            .set(seconds);
        OUT_OF_SYNC_TIME_HIST
            .with_label_values(&[self.token_display_name.as_str()])
            .observe(seconds);
    }

    pub fn add_blocks_fetched(&self, count: u64) {
        BLOCKS_FETCHED_COUNTER
            .with_label_values(&[self.token_display_name.as_str()])
            .inc_by(count);
    }

    pub fn inc_fetch_retries(&self) {
        BLOCKS_FETCH_RETRIES_COUNTER
            .with_label_values(&[self.token_display_name.as_str()])
            .inc();
    }

    pub fn inc_sync_errors(&self) {
        SYNC_ERR_COUNTER
            .with_label_values(&[self.token_display_name.as_str()])
            .inc();
    }

    pub fn inc_sync_thread_restarts(&self) {
        SYNC_THREAD_RESTARTS
            .with_label_values(&[self.token_display_name.as_str()])
            .inc();
    }

    pub fn http_metrics_wrapper(expose: bool) -> PrometheusMetrics {
        let mut metrics_guard = METRICS.lock().unwrap();
        if let Some(metrics) = &*metrics_guard {
            return metrics.clone();
        }

        let registry = prometheus::default_registry().clone();
        let metrics = PrometheusMetricsBuilder::new("rosetta").registry(registry);

        let metrics = if expose {
            metrics.endpoint("/metrics").build().unwrap()
        } else {
            metrics.build().unwrap()
        };

        *metrics_guard = Some(metrics.clone());
        metrics
    }

    /// Creates a metrics middleware layer
    pub fn metrics_layer(&self) -> RosettaMetricsLayer {
        RosettaMetricsLayer {
            default_metrics: self.clone(),
        }
    }

    /// Gets a display name for a canister ID from the global registry.
    /// Returns the canister ID itself if no mapping exists.
    pub fn get_display_name_from_canister_id(canister_id: &str) -> String {
        let map = CANISTER_DISPLAY_NAMES.lock().unwrap();
        map.get(canister_id)
            .map(|s| s.to_string())
            .unwrap_or_else(|| canister_id.to_string())
    }

    /// Registers a mapping between canister ID and display name in the global registry.
    /// This can be used to associate readable names with canister IDs for metrics.
    pub fn register_canister_display_name(canister_id: String, display_name: String) {
        let mut map = CANISTER_DISPLAY_NAMES.lock().unwrap();
        map.insert(canister_id, display_name);
    }
}

// Axum middleware implementation for Rosetta metrics
#[derive(Clone)]
pub struct RosettaMetricsLayer {
    default_metrics: RosettaMetrics,
}

impl<S> Layer<S> for RosettaMetricsLayer {
    type Service = RosettaMetricsMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RosettaMetricsMiddleware {
            inner,
            default_metrics: self.default_metrics.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RosettaMetricsMiddleware<S> {
    inner: S,
    default_metrics: RosettaMetrics,
}

impl<S> Service<Request<Body>> for RosettaMetricsMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static + Clone,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // If this is a metrics request, handle it directly
        if req.uri().path() == "/metrics" {
            // Gather metrics from the default registry which includes our metrics
            let encoder = prometheus::TextEncoder::new();
            let metric_families = prometheus::default_registry().gather();
            let mut buffer = Vec::new();
            encoder
                .encode(&metric_families, &mut buffer)
                .unwrap_or_default();

            // Build response
            let response = Response::builder()
                .header("Content-Type", "text/plain; version=0.0.4")
                .header("Cache-Control", "no-store")
                .body(Body::from(buffer))
                .unwrap();

            // Return the metrics response
            return Box::pin(async { Ok(response) });
        }

        let path = req.uri().path().to_owned();
        let method = req.method().to_string();
        let default_metrics = self.default_metrics.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Need to buffer the body to extract the canister ID
            let (parts, body) = req.into_parts();

            // Extract canister ID from body if possible
            let (canister_id, reconstructed_body) = match extract_canister_id(body).await {
                Ok((canister_id, body_bytes)) => (canister_id, Body::from(body_bytes)),
                Err(_) => (None, Body::empty()),
            };

            // Use display name from map or default
            let metrics = match canister_id {
                Some(id) => {
                    let display_name = RosettaMetrics::get_display_name_from_canister_id(&id);
                    RosettaMetrics::new(display_name, id)
                }
                None => default_metrics,
            };

            // Reconstruct request with the buffered body
            let req = Request::from_parts(parts, reconstructed_body);

            // Track start time
            let start_time = std::time::Instant::now();

            // Process the request
            let result = inner.call(req).await;

            // Calculate duration
            let duration = start_time.elapsed().as_secs_f64();

            // Record status in metrics
            match &result {
                Ok(response) => {
                    let status = response.status().as_u16().to_string();
                    metrics.inc_api_status_count(&status);

                    // Record request duration with status
                    metrics.observe_request_duration(&path, &method, &status, duration);
                }
                Err(_) => {
                    metrics.inc_api_status_count("error");

                    // Record request duration with error status
                    metrics.observe_request_duration(&path, &method, "error", duration);
                }
            }

            result
        })
    }
}

// Helper function to extract canister ID from request body
async fn extract_canister_id(
    body: Body,
) -> Result<(Option<String>, Bytes), Box<dyn std::error::Error + Send + Sync>> {
    // Read body bytes
    let bytes = to_bytes(body, usize::MAX).await?;

    // Don't attempt to parse if empty
    if bytes.is_empty() {
        return Ok((None, bytes));
    }

    // Try to parse as JSON
    let canister_id = match serde_json::from_slice::<Value>(&bytes) {
        Ok(json) => json
            .get("network_identifier")
            .and_then(|ni| ni.get("network"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string()),
        Err(_) => None,
    };

    Ok((canister_id, bytes))
}
