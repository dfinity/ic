use ic_adapter_metrics_service::{
    adapter_metrics_service_server::{AdapterMetricsService, AdapterMetricsServiceServer},
    ScrapeResponse,
};
use ic_async_utils::incoming_from_second_systemd_socket;
use ic_logger::{error, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use protobuf::Message;
use tonic::{transport::Server, Code, Request, Response, Status};

/// Adapter metrics server
///
/// Metrics server that serves local prometheus metrics over gRPC
struct Metrics {
    metrics: MetricsRegistry,
}

impl Metrics {
    pub fn new(metrics: MetricsRegistry) -> Self {
        Self { metrics }
    }
}

#[tonic::async_trait]
impl AdapterMetricsService for Metrics {
    async fn scrape(&self, _request: Request<()>) -> Result<Response<ScrapeResponse>, Status> {
        let metrics = self
            .metrics
            .prometheus_registry()
            .gather()
            .into_iter()
            .map(|mf| {
                mf.write_to_bytes()
                    .map_err(|_| Status::new(Code::Internal, "Failed to serialize metrics"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Response::new(ScrapeResponse { metrics }))
    }
}

/// Starts metrics gRPC server.
///
/// # Safety
/// Expects a socket FD at file descriptor location 4 for which it is the only consumer.
pub unsafe fn start_metrics_grpc(metrics: MetricsRegistry, logger: ReplicaLogger) {
    tokio::spawn(async move {
        let adapter_metrics = Metrics::new(metrics);

        // If metrics server shuts down we should not panic the adapter
        Server::builder()
            .add_service(AdapterMetricsServiceServer::new(adapter_metrics))
            // 'incoming_from_second_systemd_socket' is unsafe since it tries to convert FD(4) to
            // a unix listener. This only safe if FD(4) is presesnt and FD(4) is only consumed once.
            .serve_with_incoming(incoming_from_second_systemd_socket())
            .await
            .map_err(|e| error!(logger, "Canister Http adapter crashed: {}", e))
    });
}
