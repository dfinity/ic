use ic_interfaces::bitcoin_adapter_client::{BitcoinAdapterClient, Options, RpcResult};
use ic_protobuf::bitcoin::v1::{BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper};
use mockall::*;

mock! {
    pub BitcoinAdapterClient {}

    trait BitcoinAdapterClient {
        fn send_request(
            &self,
            request: BitcoinAdapterRequestWrapper,
            opts: Options,
        ) -> RpcResult<BitcoinAdapterResponseWrapper>;
    }
}
