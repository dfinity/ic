use ic_adapter_metrics::AdapterMetrics;
use ic_async_utils::incoming_from_first_systemd_socket;
use ic_metrics::MetricsRegistry;
use ic_onchain_observability_service::{
    onchain_observability_service_server::{
        OnchainObservabilityService, OnchainObservabilityServiceServer,
    },
    OnchainObservabilityServiceGetMetricsDataRequest,
    OnchainObservabilityServiceGetMetricsDataResponse,
};
use prometheus::{
    proto::MetricFamily,
    {Encoder, TextEncoder},
};
use std::{path::PathBuf, time::Duration};
use tonic::{transport::Server, Request, Response, Status};

// TODO add to config
const TIMEOUT_SECS: u64 = 30;

// Start the onchain observability server in a new task, which provides a mechanism to sends metrics to the onchain observability adapter.
// Intended to be called from replica.
// TODO: Use metrics registry to also record metrics for gRPC requests
pub fn spawn_onchain_observability_grpc_server_and_register_metrics(
    metrics_registry: MetricsRegistry,
    rt_handle: tokio::runtime::Handle,
    metrics_socket_path: Option<PathBuf>,
) {
    if let Some(socket_path) = metrics_socket_path {
        metrics_registry.register_adapter(AdapterMetrics::new(
            "onchain_observability",
            socket_path,
            rt_handle.clone(),
        ));
    }

    let service_impl = OnchainObservabilityServiceImpl { metrics_registry };
    rt_handle.spawn(async move {
        Server::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .add_service(OnchainObservabilityServiceServer::new(service_impl))
            // SAFETY: The process is managed by systemd and is configured to start with at least one socket.
            // Additionally this function is only called once here.
            // Systemd Socket config: ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.socket
            // Systemd Service config: ic-os/guestos/rootfs/etc/systemd/system/ic-replica.service
            .serve_with_incoming(unsafe { incoming_from_first_systemd_socket() })
            .await
            .expect("gRPC server crashed");
    });
}

struct OnchainObservabilityServiceImpl {
    metrics_registry: MetricsRegistry,
}

#[tonic::async_trait]
// Returns the requested Prometheus metrics.  Client is expected to parse raw string
// into typed form.  If requested metrics are not found, an empty string will be returned
impl OnchainObservabilityService for OnchainObservabilityServiceImpl {
    async fn get_metrics_data(
        &self,
        request: Request<OnchainObservabilityServiceGetMetricsDataRequest>,
    ) -> Result<Response<OnchainObservabilityServiceGetMetricsDataResponse>, Status> {
        let requested_metrics = request.into_inner().requested_metrics;

        // Note that the gather() call below reads from a RWLock, which has the potential to block the thread if it collides with a write.
        // However, writes can only happen from the register() call, and registration is completed before we start the gRPC server.
        let filtered_metrics: Vec<MetricFamily> = self
            .metrics_registry
            .prometheus_registry()
            .gather()
            .into_iter()
            .filter(|metric| requested_metrics.contains(&metric.get_name().to_string()))
            .collect();

        // Write metrics to a string, adapted from how it is done for the MetricsEndpoint logs
        let mut buffer = Vec::with_capacity(filtered_metrics.len());
        let encoder = TextEncoder::new();
        encoder
            .encode(&filtered_metrics, &mut buffer)
            .map_err(|e| Status::unknown(format!("Failed to encode metrics: {:?} ", e)))?;

        let filtered_metrics_string = String::from_utf8(buffer).map_err(|e| {
            Status::unknown(format!(
                "Failed to convert metrics buffer to string: {:?}",
                e.to_string()
            ))
        })?;

        Ok(Response::new(
            OnchainObservabilityServiceGetMetricsDataResponse {
                metrics_data: filtered_metrics_string,
            },
        ))
    }
}
