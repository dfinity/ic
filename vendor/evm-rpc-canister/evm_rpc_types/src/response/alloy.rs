use crate::{
    Block, FeeHistory, Hex32, HexByte, LogEntry, Nat256, RpcError, RpcResult, TransactionReceipt,
    ValidationError,
};
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types::BlockTransactions;
use candid::Nat;
use num_bigint::BigUint;
use std::{any::type_name, fmt::Debug};

impl TryFrom<LogEntry> for alloy_rpc_types::Log {
    type Error = RpcError;

    fn try_from(entry: LogEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: alloy_primitives::Log {
                address: alloy_primitives::Address::from(entry.address),
                data: alloy_primitives::LogData::new(
                    entry
                        .topics
                        .into_iter()
                        .map(alloy_primitives::B256::from)
                        .collect(),
                    alloy_primitives::Bytes::from(entry.data),
                )
                .ok_or(RpcError::ValidationError(ValidationError::Custom(
                    "Invalid log data".to_string(),
                )))?,
            },
            block_hash: entry.block_hash.map(alloy_primitives::BlockHash::from),
            block_number: entry
                .block_number
                .map(|value| try_from_nat256(value, "block_number"))
                .transpose()?,
            block_timestamp: None,
            transaction_hash: entry.transaction_hash.map(alloy_primitives::TxHash::from),
            transaction_index: entry
                .transaction_index
                .map(|value| try_from_nat256(value, "transaction_index"))
                .transpose()?,
            log_index: entry
                .log_index
                .map(|value| try_from_nat256(value, "log_index"))
                .transpose()?,
            removed: entry.removed,
        })
    }
}

impl TryFrom<Block> for alloy_rpc_types::Block {
    type Error = RpcError;

    fn try_from(value: Block) -> Result<Self, Self::Error> {
        Ok(Self {
            header: alloy_rpc_types::Header {
                hash: alloy_primitives::BlockHash::from(value.hash),
                inner: alloy_consensus::Header {
                    parent_hash: alloy_primitives::BlockHash::from(value.parent_hash),
                    ommers_hash: alloy_primitives::BlockHash::from(value.sha3_uncles),
                    beneficiary: alloy_primitives::Address::from(value.miner),
                    state_root: alloy_primitives::B256::from(value.state_root),
                    transactions_root: validate_transactions_root(value.transactions_root)?,
                    receipts_root: alloy_primitives::B256::from(value.receipts_root),
                    logs_bloom: alloy_primitives::Bloom::from(value.logs_bloom),
                    difficulty: validate_difficulty(&value.number, value.difficulty)?,
                    number: try_from_nat256(value.number, "number")?,
                    gas_limit: try_from_nat256(value.gas_limit, "gas_limit")?,
                    gas_used: try_from_nat256(value.gas_used, "gas_used")?,
                    timestamp: try_from_nat256(value.timestamp, "timestamp")?,
                    extra_data: alloy_primitives::Bytes::from(value.extra_data),
                    mix_hash: alloy_primitives::B256::from(value.mix_hash),
                    nonce: alloy_primitives::B64::try_from(value.nonce)?,
                    base_fee_per_gas: value
                        .base_fee_per_gas
                        .map(|value| try_from_nat256(value, "base_fee_per_gas"))
                        .transpose()?,
                    withdrawals_root: None,
                    blob_gas_used: None,
                    excess_blob_gas: None,
                    parent_beacon_block_root: None,
                    requests_hash: None,
                },
                total_difficulty: value.total_difficulty.map(U256::from),
                size: Some(U256::from(value.size)),
            },
            uncles: value
                .uncles
                .into_iter()
                .map(alloy_primitives::B256::from)
                .collect(),
            transactions: BlockTransactions::Hashes(
                value
                    .transactions
                    .into_iter()
                    .map(alloy_primitives::B256::from)
                    .collect(),
            ),
            withdrawals: None,
        })
    }
}

impl TryFrom<FeeHistory> for alloy_rpc_types::FeeHistory {
    type Error = RpcError;

    fn try_from(value: FeeHistory) -> Result<Self, Self::Error> {
        Ok(Self {
            base_fee_per_gas: value
                .base_fee_per_gas
                .into_iter()
                .map(|reward| try_from_nat256(reward, "base_fee_per_gas"))
                .collect::<Result<Vec<_>, _>>()?,
            gas_used_ratio: value.gas_used_ratio,
            base_fee_per_blob_gas: vec![],
            blob_gas_used_ratio: vec![],
            oldest_block: try_from_nat256(value.oldest_block, "oldest_block")?,
            reward: Some(
                value
                    .reward
                    .into_iter()
                    .map(|rewards| {
                        rewards
                            .into_iter()
                            .map(|reward| try_from_nat256(reward, "reward"))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        })
    }
}

impl TryFrom<TransactionReceipt> for alloy_rpc_types::TransactionReceipt {
    type Error = RpcError;

    fn try_from(receipt: TransactionReceipt) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: alloy_consensus::ReceiptEnvelope::from_typed(
                alloy_consensus::TxType::try_from(receipt.tx_type)?,
                alloy_consensus::ReceiptWithBloom {
                    receipt: alloy_consensus::Receipt {
                        status: validate_receipt_status(
                            &receipt.block_number,
                            receipt.root,
                            receipt.status,
                        )?,
                        cumulative_gas_used: try_from_nat256(
                            receipt.cumulative_gas_used,
                            "cumulative_gas_used",
                        )?,
                        logs: receipt
                            .logs
                            .into_iter()
                            .map(alloy_rpc_types::Log::try_from)
                            .collect::<RpcResult<Vec<alloy_rpc_types::Log>>>()?,
                    },
                    logs_bloom: alloy_primitives::Bloom::from(receipt.logs_bloom),
                },
            ),
            transaction_hash: B256::from(receipt.transaction_hash),
            transaction_index: Some(try_from_nat256(
                receipt.transaction_index,
                "transaction_index",
            )?),
            block_hash: Some(B256::from(receipt.block_hash)),
            block_number: Some(try_from_nat256(receipt.block_number, "block_number")?),
            gas_used: try_from_nat256(receipt.gas_used, "gas_used")?,
            effective_gas_price: try_from_nat256(
                receipt.effective_gas_price,
                "effective_gas_price",
            )?,
            blob_gas_used: None,
            blob_gas_price: None,
            from: Address::from(receipt.from),
            to: receipt.to.map(Address::from),
            contract_address: receipt.contract_address.map(Address::from),
        })
    }
}

impl TryFrom<HexByte> for alloy_consensus::TxType {
    type Error = RpcError;

    fn try_from(value: HexByte) -> Result<Self, Self::Error> {
        alloy_consensus::TxType::try_from(value.into_byte()).map_err(|e| {
            RpcError::ValidationError(ValidationError::Custom(format!(
                "Unable to parse transaction type: {e:?}"
            )))
        })
    }
}

fn validate_difficulty(number: &Nat256, difficulty: Option<Nat256>) -> Result<U256, RpcError> {
    const PARIS_BLOCK: u64 = 15_537_394;
    if number.as_ref() < &Nat::from(PARIS_BLOCK) {
        difficulty
            .map(U256::from)
            .ok_or(RpcError::ValidationError(ValidationError::Custom(
                "Missing difficulty field in pre Paris upgrade block".into(),
            )))
    } else {
        match difficulty.map(U256::from) {
            None | Some(U256::ZERO) => Ok(U256::ZERO),
            _ => Err(RpcError::ValidationError(ValidationError::Custom(
                "Post Paris upgrade block has non-zero difficulty".into(),
            ))),
        }
    }
}

fn validate_receipt_status(
    number: &Nat256,
    root: Option<Hex32>,
    status: Option<Nat256>,
) -> Result<alloy_consensus::Eip658Value, RpcError> {
    const BYZANTIUM_BLOCK: u64 = 4_370_000;
    if number.as_ref() < &Nat::from(BYZANTIUM_BLOCK) {
        match root {
            None => Err(RpcError::ValidationError(ValidationError::Custom(
                "Missing root field in transaction included before the Byzantium upgrade".into(),
            ))),
            Some(root) => Ok(alloy_consensus::Eip658Value::PostState(B256::from(root))),
        }
    } else {
        match status.map(U256::from) {
            None => Err(RpcError::ValidationError(ValidationError::Custom(
                "Missing status field in transaction included after the Byzantium upgrade".into(),
            ))),
            Some(U256::ZERO) => Ok(alloy_consensus::Eip658Value::Eip658(false)),
            Some(U256::ONE) => Ok(alloy_consensus::Eip658Value::Eip658(true)),
            Some(_) => Err(RpcError::ValidationError(ValidationError::Custom(
                "Post-Byzantium receipt has invalid status (expected 0 or 1)".into(),
            ))),
        }
    }
}

fn validate_transactions_root(transactions_root: Option<Hex32>) -> Result<B256, RpcError> {
    transactions_root
        .map(alloy_primitives::B256::from)
        .ok_or(RpcError::ValidationError(ValidationError::Custom(
            "Block does not have a transactions root field".to_string(),
        )))
}

fn try_from_nat256<T: TryFrom<BigUint, Error = E>, E: Debug>(
    value: Nat256,
    field_name: &str,
) -> Result<T, RpcError> {
    T::try_from(Nat::from(value).0).map_err(|err| {
        RpcError::ValidationError(ValidationError::Custom(format!(
            "Failed to convert field `{}` to `{}`: {:?}",
            field_name,
            type_name::<T>(),
            err
        )))
    })
}
