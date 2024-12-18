use futures::stream::Stream;
use ic_adapter_metrics_service::{
    adapter_metrics_service_server::{AdapterMetricsService, AdapterMetricsServiceServer},
    ScrapeRequest, ScrapeResponse,
};
use ic_logger::{error, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use protobuf::Message;
use std::error::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::{
    transport::{server::Connected, Server},
    Code, Request, Response, Status,
};

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
    async fn scrape(
        &self,
        _request: Request<ScrapeRequest>,
    ) -> Result<Response<ScrapeResponse>, Status> {
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

/// Starts metrics gRPC server with a valid stream (this can be used to configure which socket to listen to).
pub fn start_metrics_grpc<T, E>(
    metrics: MetricsRegistry,
    logger: ReplicaLogger,
    stream: impl Stream<Item = Result<T, E>> + Send + 'static,
) where
    T: Send + Sync + Unpin + AsyncRead + AsyncWrite + Connected + 'static,
    E: Send + Sync + Unpin + Error + 'static,
{
    tokio::spawn(async move {
        let adapter_metrics = Metrics::new(metrics);

        // If metrics server shuts down we should not panic the adapter
        Server::builder()
            .add_service(AdapterMetricsServiceServer::new(adapter_metrics))
            .serve_with_incoming(stream)
            .await
            .map_err(|e| error!(logger, "Metrics grpc server crashed: {}", e))
    });
}
