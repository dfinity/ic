use ic_btc_adapter::BtcAdapterClient;
use ic_interfaces::bitcoin_adapter_client::{BitcoinAdapterClient, Options, RpcResult};
use ic_protobuf::bitcoin::v1::{
    GetSuccessorsRequest, GetSuccessorsResponse, SendTransactionRequest, SendTransactionResponse,
};
use tonic::transport::Channel;

struct BitcoinAdapterClientImpl {
    rt_handle: tokio::runtime::Handle,
    client: BtcAdapterClient<Channel>,
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
                Err(tonic_status) => Err(tonic_status),
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
                Err(tonic_status) => Err(tonic_status),
            }
        })
    }
}
