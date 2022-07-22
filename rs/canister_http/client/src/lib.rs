mod client;

pub use crate::client::BrokenCanisterHttpClient;
use crate::client::CanisterHttpAdapterClientImpl;
use ic_adapter_metrics::AdapterMetrics;
use ic_async_utils::ExecuteOnTokioRuntime;
use ic_config::adapters::AdaptersConfig;
use ic_interfaces::execution_environment::AnonymousQueryService;
use ic_interfaces_canister_http_adapter_client::CanisterHttpAdapterClient;
use ic_logger::{error, info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use std::convert::TryFrom;
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

const CANISTER_HTTP_CLIENT_CHANNEL_CAPACITY: usize = 100;

pub fn setup_canister_http_client(
    rt_handle: tokio::runtime::Handle,
    metrics_registry: &MetricsRegistry,
    adapter_config: AdaptersConfig,
    anononymous_query_handler: AnonymousQueryService,
    log: ReplicaLogger,
) -> CanisterHttpAdapterClient {
    match adapter_config.canister_http_uds_path {
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
                            // Connect to a Uds socket
                            UnixStream::connect(uds_path.clone())
                        }));

                    // Register canister http adapter metrics with replica metrics. The adapter exposes a
                    // UDS metrics endpoint that can be scraped by the replica process.
                    if let Some(metrics_uds_path) = adapter_config.canister_http_uds_metrics_path {
                        metrics_registry.register_adapter(AdapterMetrics::new(
                            "canisterhttp",
                            metrics_uds_path,
                            rt_handle.clone(),
                        ));
                    }
                    Box::new(CanisterHttpAdapterClientImpl::new(
                        rt_handle,
                        channel,
                        anononymous_query_handler,
                        CANISTER_HTTP_CLIENT_CHANNEL_CAPACITY,
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
