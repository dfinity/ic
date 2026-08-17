mod client;
mod metrics;
mod query_outcall;
#[cfg(test)]
mod test_support;

pub use crate::client::CanisterHttpAdapterClientImpl;
pub use crate::query_outcall::setup_query_outcall_service;

use crate::client::BrokenCanisterHttpClient;
use ic_adapter_metrics_client::AdapterMetrics;
use ic_config::adapters::AdaptersConfig;
use ic_http_endpoints_async_utils::ExecuteOnTokioRuntime;
use ic_interfaces::execution_environment::TransformExecutionService;
use ic_interfaces_adapter_client::NonBlockingChannel;
use ic_logger::{ReplicaLogger, error, info};
use ic_metrics::MetricsRegistry;
use ic_types::canister_http::{
    CanisterHttpPaymentReceipt, CanisterHttpRequest, CanisterHttpResponse,
};
use std::convert::TryFrom;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

/// Connects to the HTTPS outcalls adapter, or `None` if none is configured.
///
/// Lazy and independent of execution, so the components that need the adapter
/// can share one connection wherever they are constructed.
pub fn setup_canister_http_channel(
    rt_handle: tokio::runtime::Handle,
    metrics_registry: &MetricsRegistry,
    adapter_config: &AdaptersConfig,
    log: &ReplicaLogger,
) -> Option<Channel> {
    let uds_path = match &adapter_config.https_outcalls_uds_path {
        None => {
            error!(
                log,
                "Unable to connect to the canister http adapter. No UDS path provided."
            );
            return None;
        }
        Some(uds_path) => uds_path.clone(),
    };

    info!(
        log,
        "Starting Canister Http client. Connecting to Canister Http adapter: {:?}", uds_path
    );

    // We will ignore this uri because uds does not use it.
    let endpoint = match Endpoint::try_from("http://[::]:50151") {
        Ok(endpoint) => endpoint,
        Err(e) => {
            error!(
                log,
                "Unable to connect to the canister http adapter. Failed to create endpoint. {}", e
            );
            return None;
        }
    };

    let endpoint = endpoint.executor(ExecuteOnTokioRuntime(rt_handle.clone()));
    let channel = endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
        let uds_path = uds_path.clone();
        async move {
            // Connect to a Uds socket
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                UnixStream::connect(uds_path).await?,
            ))
        }
    }));

    // Register canister http adapter metrics with replica metrics. The adapter exposes a
    // UDS metrics endpoint that can be scraped by the replica process.
    if let Some(metrics_uds_path) = &adapter_config.https_outcalls_uds_metrics_path {
        metrics_registry.register_adapter(AdapterMetrics::new(
            "canisterhttp",
            metrics_uds_path.clone(),
            rt_handle,
        ));
    }

    Some(channel)
}

/// The client that consensus uses to make replicated HTTP outcalls. A `channel`
/// of `None` yields one that reports a broken connection for every request.
pub fn setup_canister_http_client(
    rt_handle: tokio::runtime::Handle,
    channel: Option<Channel>,
    transform_handler: TransformExecutionService,
    max_canister_http_requests_in_flight: usize,
    metrics_registry: &MetricsRegistry,
    log: ReplicaLogger,
) -> Box<
    dyn NonBlockingChannel<
            CanisterHttpRequest,
            Response = (CanisterHttpResponse, CanisterHttpPaymentReceipt),
        > + Send,
> {
    match channel {
        None => Box::new(BrokenCanisterHttpClient {}),
        Some(channel) => Box::new(CanisterHttpAdapterClientImpl::new(
            rt_handle,
            channel,
            transform_handler,
            max_canister_http_requests_in_flight,
            metrics_registry.clone(),
            log,
        )),
    }
}
