use crate::{
    rpc_client::{
        json::{
            requests::{
                BlockSpec, EthCallParams, FeeHistoryParams, GetLogsParams,
                GetTransactionCountParams,
            },
            Hash,
        },
        EthRpcClient,
    },
    types::RpcMethod,
};
use candid::Nat;
use canhttp::{http::json::JsonRpcRequest, multi::Timestamp};
use ethers_core::{types::Transaction, utils::rlp};
use evm_rpc_types::{
    BlockTag, Hex, Hex32, MultiRpcResult, Nat256, RpcError, RpcResult, ValidationError,
};

/// Adapt the `EthRpcClient` to the `Candid` interface used by the EVM-RPC canister.
pub struct CandidRpcClient {
    client: EthRpcClient,
}

impl CandidRpcClient {
    pub fn new(
        source: evm_rpc_types::RpcServices,
        config: Option<evm_rpc_types::RpcConfig>,
        now: Timestamp,
    ) -> RpcResult<Self> {
        Ok(Self {
            client: EthRpcClient::new(source, config, now)?,
        })
    }

    pub async fn eth_get_logs(
        self,
        args: evm_rpc_types::GetLogsArgs,
    ) -> MultiRpcResult<Vec<evm_rpc_types::LogEntry>> {
        self.client
            .eth_get_logs(GetLogsParams::from(args))
            .send_and_reduce()
            .await
            .map(|entries| {
                entries
                    .into_iter()
                    .map(evm_rpc_types::LogEntry::from)
                    .collect()
            })
    }

    pub async fn eth_get_logs_cycles_cost(
        self,
        args: evm_rpc_types::GetLogsArgs,
    ) -> RpcResult<u128> {
        self.client
            .eth_get_logs(GetLogsParams::from(args))
            .cycles_cost()
            .await
    }

    pub async fn eth_get_block_by_number(
        self,
        block_tag: BlockTag,
    ) -> MultiRpcResult<evm_rpc_types::Block> {
        self.client
            .eth_get_block_by_number(BlockSpec::from(block_tag))
            .send_and_reduce()
            .await
            .map(evm_rpc_types::Block::from)
    }

    pub async fn eth_get_block_by_number_cycles_cost(self, block_tag: BlockTag) -> RpcResult<u128> {
        self.client
            .eth_get_block_by_number(BlockSpec::from(block_tag))
            .cycles_cost()
            .await
    }

    pub async fn eth_get_transaction_receipt(
        self,
        hash: Hex32,
    ) -> MultiRpcResult<Option<evm_rpc_types::TransactionReceipt>> {
        self.client
            .eth_get_transaction_receipt(Hash::from(hash))
            .send_and_reduce()
            .await
            .map(|maybe_receipt| maybe_receipt.map(evm_rpc_types::TransactionReceipt::from))
    }

    pub async fn eth_get_transaction_receipt_cycles_cost(self, hash: Hex32) -> RpcResult<u128> {
        self.client
            .eth_get_transaction_receipt(Hash::from(hash))
            .cycles_cost()
            .await
    }

    pub async fn eth_get_transaction_count(
        self,
        args: evm_rpc_types::GetTransactionCountArgs,
    ) -> MultiRpcResult<Nat256> {
        self.client
            .eth_get_transaction_count(GetTransactionCountParams::from(args))
            .send_and_reduce()
            .await
            .map(Nat256::from)
    }

    pub async fn eth_get_transaction_count_cycles_cost(
        self,
        args: evm_rpc_types::GetTransactionCountArgs,
    ) -> RpcResult<u128> {
        self.client
            .eth_get_transaction_count(GetTransactionCountParams::from(args))
            .cycles_cost()
            .await
    }

    pub async fn eth_fee_history(
        self,
        args: evm_rpc_types::FeeHistoryArgs,
    ) -> MultiRpcResult<evm_rpc_types::FeeHistory> {
        self.client
            .eth_fee_history(FeeHistoryParams::from(args))
            .send_and_reduce()
            .await
            .map(evm_rpc_types::FeeHistory::from)
    }

    pub async fn eth_fee_history_cycles_cost(
        self,
        args: evm_rpc_types::FeeHistoryArgs,
    ) -> RpcResult<u128> {
        self.client
            .eth_fee_history(FeeHistoryParams::from(args))
            .cycles_cost()
            .await
    }

    pub async fn eth_send_raw_transaction(
        self,
        raw_signed_transaction_hex: Hex,
    ) -> MultiRpcResult<evm_rpc_types::SendRawTransactionStatus> {
        let tx_hash = get_transaction_hash(&raw_signed_transaction_hex);
        self.client
            .eth_send_raw_transaction(raw_signed_transaction_hex.to_string())
            .send_and_reduce()
            .await
            .map(
                |result| match evm_rpc_types::SendRawTransactionStatus::from(result) {
                    evm_rpc_types::SendRawTransactionStatus::Ok(_) => {
                        evm_rpc_types::SendRawTransactionStatus::Ok(tx_hash.clone())
                    }
                    result => result,
                },
            )
    }

    pub async fn eth_send_raw_transaction_cycles_cost(
        self,
        raw_signed_transaction_hex: Hex,
    ) -> RpcResult<u128> {
        self.client
            .eth_send_raw_transaction(raw_signed_transaction_hex.to_string())
            .cycles_cost()
            .await
    }

    pub async fn eth_call(self, args: evm_rpc_types::CallArgs) -> MultiRpcResult<Hex> {
        self.client
            .eth_call(EthCallParams::from(args))
            .send_and_reduce()
            .await
            .map(Hex::from)
    }

    pub async fn eth_call_cycles_cost(self, args: evm_rpc_types::CallArgs) -> RpcResult<u128> {
        self.client
            .eth_call(EthCallParams::from(args))
            .cycles_cost()
            .await
    }

    pub async fn multi_request(self, json_rpc_payload: String) -> MultiRpcResult<String> {
        let request = match try_into_json_rpc_request(json_rpc_payload) {
            Ok(request) => request,
            Err(err) => return MultiRpcResult::Consistent(Err(err)),
        };
        self.client
            .multi_request(
                RpcMethod::Custom(request.method().to_string()),
                request.params(),
            )
            .send_and_reduce()
            .await
            .map(String::from)
    }

    pub async fn multi_cycles_cost(self, json_rpc_payload: String) -> RpcResult<u128> {
        let request = try_into_json_rpc_request(json_rpc_payload)?;
        self.client
            .multi_request(
                RpcMethod::Custom(request.method().to_string()),
                request.params(),
            )
            .cycles_cost()
            .await
    }
}

fn get_transaction_hash(raw_signed_transaction_hex: &Hex) -> Option<Hex32> {
    let transaction: Transaction = rlp::decode(raw_signed_transaction_hex.as_ref()).ok()?;
    Some(Hex32::from(transaction.hash.0))
}

pub fn validate_get_logs_block_range(
    args: &evm_rpc_types::GetLogsArgs,
    max_block_range: u32,
) -> RpcResult<()> {
    if let (Some(BlockTag::Number(from)), Some(BlockTag::Number(to))) =
        (&args.from_block, &args.to_block)
    {
        let from = Nat::from(from.clone());
        let to = Nat::from(to.clone());
        let block_count = if to > from { to - from } else { from - to };
        if block_count > max_block_range {
            return Err(ValidationError::Custom(format!(
                "Requested {} blocks; limited to {} when specifying a start and end block",
                block_count, max_block_range
            ))
            .into());
        }
    }
    Ok(())
}

fn try_into_json_rpc_request(
    json_rpc_payload: String,
) -> RpcResult<JsonRpcRequest<serde_json::Value>> {
    serde_json::from_str(&json_rpc_payload).map_err(|e| {
        RpcError::ValidationError(ValidationError::Custom(format!(
            "Invalid JSON RPC request: {e}"
        )))
    })
}
