mod client;
mod metrics;

pub use crate::client::{
    grpc_status_code_to_reject, BrokenCanisterHttpClient, CanisterHttpAdapterClientImpl,
};
use ic_adapter_metrics_client::AdapterMetrics;
use ic_async_utils::ExecuteOnTokioRuntime;
use ic_config::adapters::AdaptersConfig;
use ic_interfaces::execution_environment::QueryExecutionService;
use ic_interfaces_adapter_client::NonBlockingChannel;
use ic_logger::{error, info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    canister_http::{CanisterHttpRequest, CanisterHttpResponse},
    messages::CertificateDelegation,
};
use std::{convert::TryFrom, sync::Arc};
use tokio::{net::UnixStream, sync::OnceCell};
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

pub fn setup_canister_http_client(
    rt_handle: tokio::runtime::Handle,
    metrics_registry: &MetricsRegistry,
    adapter_config: AdaptersConfig,
    query_handler: QueryExecutionService,
    max_canister_http_requests_in_flight: usize,
    log: ReplicaLogger,
    subnet_type: SubnetType,
    delegation_from_nns: Arc<OnceCell<CertificateDelegation>>,
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
                            // Connect to a Uds socket
                            UnixStream::connect(uds_path.clone())
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
                        query_handler,
                        max_canister_http_requests_in_flight,
                        metrics_registry.clone(),
                        subnet_type,
                        delegation_from_nns,
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
