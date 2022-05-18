mod client;

use crate::client::{BrokenCanisterHttpClient, CanisterHttpAdapterClientImpl};
use ic_interfaces::execution_environment::AnonymousQueryService;
use ic_interfaces_canister_http_adapter_client::CanisterHttpAdapterClient;
use ic_logger::{error, info, ReplicaLogger};
use std::path::PathBuf;
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

const CANISTER_HTTP_CLIENT_CHANNEL_CAPACITY: usize = 100;

pub fn setup_canister_http_client(
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    uds_path: Option<PathBuf>,
    anononymous_query_handler: AnonymousQueryService,
) -> CanisterHttpAdapterClient {
    match uds_path {
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
                    match endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
                        // Connect to a Uds socket
                        UnixStream::connect(uds_path.clone())
                    })) {
                        Ok(channel) => Box::new(CanisterHttpAdapterClientImpl::new(
                            rt_handle,
                            channel,
                            anononymous_query_handler,
                            CANISTER_HTTP_CLIENT_CHANNEL_CAPACITY,
                        )),
                        Err(e) => {
                            error!(log, "Unable to connect to the canister http adapter. {}", e);
                            Box::new(BrokenCanisterHttpClient {})
                        }
                    }
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
