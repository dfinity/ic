use ic_btc_types_internal::{BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper};
use ic_interfaces_bitcoin_adapter_client::{BitcoinAdapterClient, Options, RpcResult};
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
