use crate::eth_rpc::BlockSpec;
use ic_ethereum_types::Address;
use serde::Serialize;

/// Parameters of the [`eth_getTransactionCount`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_gettransactioncount) call.
#[derive(Debug, Serialize, Clone)]
#[serde(into = "(Address, BlockSpec)")]
pub struct GetTransactionCountParams {
    /// The address for which the transaction count is requested.
    pub address: Address,
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    pub block: BlockSpec,
}

impl From<GetTransactionCountParams> for (Address, BlockSpec) {
    fn from(params: GetTransactionCountParams) -> Self {
        (params.address, params.block)
    }
}
