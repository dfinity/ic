use ic_btc_adapter::BtcAdapterClient;
use ic_interfaces::bitcoin_adapter_client::{BitcoinAdapterClient, Options, RpcError, RpcResult};
use ic_logger::{error, ReplicaLogger};
use ic_protobuf::bitcoin::v1::{
    GetSuccessorsRequest, GetSuccessorsResponse, SendTransactionRequest, SendTransactionResponse,
};
use std::{convert::TryFrom, path::PathBuf, sync::Arc};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

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
    fn get_successors(
        &self,
        request: GetSuccessorsRequest,
        opts: Options,
    ) -> RpcResult<GetSuccessorsResponse> {
        let mut client = self.client.clone();
        self.rt_handle.block_on(async move {
            let mut tonic_request = tonic::Request::new(request);
            if let Some(timeout) = opts.timeout {
                tonic_request.set_timeout(timeout);
            }
            match client.get_successors(tonic_request).await {
                Ok(tonic_response) => Ok(tonic_response.into_inner()),
                Err(tonic_status) => Err(RpcError::ServerError(tonic_status)),
            }
        })
    }

    fn send_transaction(
        &self,
        request: SendTransactionRequest,
        opts: Options,
    ) -> RpcResult<SendTransactionResponse> {
        let mut client = self.client.clone();
        self.rt_handle.block_on(async move {
            let mut tonic_request = tonic::Request::new(request);
            if let Some(timeout) = opts.timeout {
                tonic_request.set_timeout(timeout);
            }
            match client.send_transaction(tonic_request).await {
                Ok(tonic_response) => Ok(tonic_response.into_inner()),
                Err(tonic_status) => Err(RpcError::ServerError(tonic_status)),
            }
        })
    }
}

struct BrokenConnectionBitcoinClient();

impl BitcoinAdapterClient for BrokenConnectionBitcoinClient {
    fn get_successors(
        &self,
        _request: GetSuccessorsRequest,
        _opts: Options,
    ) -> RpcResult<GetSuccessorsResponse> {
        Err(RpcError::ConnectionBroken)
    }

    fn send_transaction(
        &self,
        _request: SendTransactionRequest,
        _opts: Options,
    ) -> RpcResult<SendTransactionResponse> {
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
