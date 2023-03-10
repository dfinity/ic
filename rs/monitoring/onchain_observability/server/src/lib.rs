use ic_async_utils::incoming_from_first_systemd_socket;
use ic_metrics::MetricsRegistry;
use ic_onchain_observability_service::{
    onchain_observability_service_server::{
        OnchainObservabilityService, OnchainObservabilityServiceServer,
    },
    OnchainObservabilityServiceGetMetricsDataRequest,
    OnchainObservabilityServiceGetMetricsDataResponse,
};
use std::time::Duration;
use tonic::{transport::Server, Request, Response, Status};

// TODO add to config
const TIMEOUT_SECS: u64 = 30;

// Start the onchain observability server in a new task, which provides a mechanism to sends metrics to the onchain observability adapter.
// Intended to be called from replica.
// TODO: Use metrics registry to also record metrics for gRPC requests
pub fn spawn_onchain_observability_grpc_server(
    metrics_registry: MetricsRegistry,
    rt_handle: tokio::runtime::Handle,
) {
    let service_impl = OnchainObservabilityServiceImpl {
        _metrics_registry: metrics_registry,
    };
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
    _metrics_registry: MetricsRegistry,
}

#[tonic::async_trait]
// Returns the requested Prometheus metrics.  Client is expected to parse raw string
// into typed form.  If requested metrics are not found, an empty string will be returned
impl OnchainObservabilityService for OnchainObservabilityServiceImpl {
    async fn get_metrics_data(
        &self,
        _request: Request<OnchainObservabilityServiceGetMetricsDataRequest>,
    ) -> Result<Response<OnchainObservabilityServiceGetMetricsDataResponse>, Status> {
        // TODO implement (NET-1357)
        Err(Status::unknown("Implement"))
    }
}
