use ic_btc_adapter_service::btc_adapter_client::BtcAdapterClient;
use ic_interfaces::bitcoin_adapter_client::{BitcoinAdapterClient, Options, RpcError, RpcResult};
use ic_logger::{error, ReplicaLogger};
use ic_protobuf::bitcoin::v1::{
    bitcoin_adapter_request_wrapper, bitcoin_adapter_response_wrapper,
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper,
};
use std::{convert::TryFrom, path::PathBuf, sync::Arc};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

fn convert_tonic_error(status: tonic::Status) -> RpcError {
    RpcError::ServerError {
        status_code: status.code() as u16,
        message: status.message().to_string(),
        source: Box::new(status),
    }
}

struct BitcoinAdapterClientImpl {
    rt_handle: tokio::runtime::Handle,
    client: BtcAdapterClient<Channel>,
}

impl BitcoinAdapterClientImpl {
    fn new(rt_handle: tokio::runtime::Handle, channel: Channel) -> Self {
        let client = BtcAdapterClient::new(channel);
        Self { rt_handle, client }
    }
}

impl BitcoinAdapterClient for BitcoinAdapterClientImpl {
    fn send_request(
        &self,
        request: BitcoinAdapterRequestWrapper,
        opts: Options,
    ) -> RpcResult<BitcoinAdapterResponseWrapper> {
        let mut client = self.client.clone();
        self.rt_handle.block_on(async move {
            match request.r {
                Some(wrapped_request) => match wrapped_request {
                    bitcoin_adapter_request_wrapper::R::GetSuccessorsRequest(r) => {
                        let mut tonic_request = tonic::Request::new(r);
                        if let Some(timeout) = opts.timeout {
                            tonic_request.set_timeout(timeout);
                        }

                        client
                            .get_successors(tonic_request)
                            .await
                            .map(|tonic_response| BitcoinAdapterResponseWrapper {
                                r: Some(
                                    bitcoin_adapter_response_wrapper::R::GetSuccessorsResponse(
                                        tonic_response.into_inner(),
                                    ),
                                ),
                            })
                            .map_err(convert_tonic_error)
                    }
                    bitcoin_adapter_request_wrapper::R::SendTransactionRequest(r) => {
                        let mut tonic_request = tonic::Request::new(r);
                        if let Some(timeout) = opts.timeout {
                            tonic_request.set_timeout(timeout);
                        }

                        client
                            .send_transaction(tonic_request)
                            .await
                            .map(|tonic_response| BitcoinAdapterResponseWrapper {
                                r: Some(
                                    bitcoin_adapter_response_wrapper::R::SendTransactionResponse(
                                        tonic_response.into_inner(),
                                    ),
                                ),
                            })
                            .map_err(convert_tonic_error)
                    }
                },
                None => Err(RpcError::InvalidRequest(request)),
            }
        })
    }
}

struct BrokenConnectionBitcoinClient();

impl BitcoinAdapterClient for BrokenConnectionBitcoinClient {
    fn send_request(
        &self,
        _request: BitcoinAdapterRequestWrapper,
        _opts: Options,
    ) -> RpcResult<BitcoinAdapterResponseWrapper> {
        Err(RpcError::ConnectionBroken)
    }
}

pub fn setup_bitcoin_client(
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    uds_path: Option<PathBuf>,
) -> Arc<dyn BitcoinAdapterClient> {
    match uds_path {
        None => Arc::new(BrokenConnectionBitcoinClient()),
        Some(uds_path) => {
            // We will ignore this uri because uds do not use it
            // if your connector does use the uri it will be provided
            // as the request to the `MakeConnection`.
            match Endpoint::try_from("http://[::]:50051") {
                Ok(endpoint) => {
                    match endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
                        // Connect to a Uds socket
                        UnixStream::connect(uds_path.clone())
                    })) {
                        Ok(channel) => Arc::new(BitcoinAdapterClientImpl::new(rt_handle, channel)),
                        Err(_) => {
                            error!(log, "Could not connect endpoint.");
                            Arc::new(BrokenConnectionBitcoinClient())
                        }
                    }
                }
                Err(_) => {
                    error!(log, "Could not create an endpoint.");
                    Arc::new(BrokenConnectionBitcoinClient())
                }
            }
        }
    }
}
