mod client;
mod metrics;

pub use crate::client::CanisterHttpAdapterClientImpl;

use crate::client::BrokenCanisterHttpClient;
use ic_adapter_metrics_client::AdapterMetrics;
use ic_config::adapters::AdaptersConfig;
use ic_http_endpoints_async_utils::ExecuteOnTokioRuntime;
use ic_interfaces::execution_environment::TransformExecutionService;
use ic_interfaces_adapter_client::NonBlockingChannel;
use ic_logger::{ReplicaLogger, error, info};
use ic_metrics::MetricsRegistry;
use ic_types::canister_http::{CanisterHttpRequest, CanisterHttpResponse};
use std::convert::TryFrom;
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

pub fn setup_canister_http_client(
    rt_handle: tokio::runtime::Handle,
    metrics_registry: &MetricsRegistry,
    adapter_config: AdaptersConfig,
    transform_handler: TransformExecutionService,
    max_canister_http_requests_in_flight: usize,
    log: ReplicaLogger,
) -> Box<dyn NonBlockingChannel<CanisterHttpRequest, Response = CanisterHttpResponse> + Send> {
    match adapter_config.https_outcalls_uds_path {
        None => {
            error!(
                log,
                "Unable to connect to the canister http adapter. No UDS path provided."
            );
            Box::new(BrokenCanisterHttpClient {})
        }
        Some(uds_path) => {
            info!(
                log,
                "Starting Canister Http client. Connecting to Canister Http adapter: {:?}",
                uds_path
            );

            // We will ignore this uri because uds does not use it.
            match Endpoint::try_from("http://[::]:50151") {
                Ok(endpoint) => {
                    let endpoint = endpoint.executor(ExecuteOnTokioRuntime(rt_handle.clone()));
                    let channel =
                        endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
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
                    if let Some(metrics_uds_path) = adapter_config.https_outcalls_uds_metrics_path {
                        metrics_registry.register_adapter(AdapterMetrics::new(
                            "canisterhttp",
                            metrics_uds_path,
                            rt_handle.clone(),
                        ));
                    }
                    Box::new(CanisterHttpAdapterClientImpl::new(
                        rt_handle,
                        channel,
                        transform_handler,
                        max_canister_http_requests_in_flight,
                        metrics_registry.clone(),
                        log,
                    ))
                }
                Err(e) => {
                    error!(
                        log,
                        "Unable to connect to the canister http adapter. Failed to create endpoint. {}",
                        e
                    );
                    Box::new(BrokenCanisterHttpClient {})
                }
            }
        }
    }
}
