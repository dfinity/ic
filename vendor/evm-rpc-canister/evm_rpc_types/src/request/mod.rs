#[cfg(test)]
mod tests;

#[cfg(feature = "alloy")]
mod alloy;

use crate::{Hex, Hex20, Hex32, HexByte, Nat256};
use candid::CandidType;
use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize, Default)]
pub enum BlockTag {
    #[default]
    Latest,
    Finalized,
    Safe,
    Earliest,
    Pending,
    Number(Nat256),
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct FeeHistoryArgs {
    /// Number of blocks in the requested range.
    /// Typically, providers request this to be between 1 and 1024.
    #[serde(rename = "blockCount")]
    pub block_count: Nat256,

    /// Highest block of the requested range.
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    #[serde(rename = "newestBlock")]
    pub newest_block: BlockTag,

    /// A monotonically increasing list of percentile values between 0 and 100.
    /// For each block in the requested range, the transactions will be sorted in ascending order
    /// by effective tip per gas and the corresponding effective tip for the percentile
    /// will be determined, accounting for gas consumed.
    #[serde(rename = "rewardPercentiles")]
    pub reward_percentiles: Option<Vec<u8>>,
}

impl<T, U> From<(T, U)> for FeeHistoryArgs
where
    T: Into<Nat256>,
    U: Into<BlockTag>,
{
    fn from((block_count, newest_block): (T, U)) -> Self {
        Self {
            block_count: block_count.into(),
            newest_block: newest_block.into(),
            reward_percentiles: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct GetLogsArgs {
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    #[serde(rename = "fromBlock")]
    pub from_block: Option<BlockTag>,

    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    #[serde(rename = "toBlock")]
    pub to_block: Option<BlockTag>,

    /// Contract address or a list of addresses from which logs should originate.
    pub addresses: Vec<Hex20>,

    /// Array of 32-byte DATA topics.
    /// Topics are order-dependent.
    /// Each topic can also be an array of DATA with "or" options.
    pub topics: Option<Vec<Vec<Hex32>>>,
}

impl<T: IntoIterator<Item = S>, S: Into<Hex20>> From<T> for GetLogsArgs {
    fn from(addresses: T) -> Self {
        Self {
            from_block: None,
            to_block: None,
            addresses: addresses.into_iter().map(Into::into).collect(),
            topics: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct GetTransactionCountArgs {
    pub address: Hex20,
    pub block: BlockTag,
}

impl<T, U> From<(T, U)> for GetTransactionCountArgs
where
    T: Into<Hex20>,
    U: Into<BlockTag>,
{
    fn from((address, block): (T, U)) -> Self {
        Self {
            address: address.into(),
            block: block.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct CallArgs {
    pub transaction: TransactionRequest,
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    /// Default to "latest" if unspecified, see <https://github.com/ethereum/execution-apis/issues/461>.
    pub block: Option<BlockTag>,
}

#[cfg_attr(test, derive(Serialize))]
#[derive(Clone, Debug, Default, PartialEq, Eq, CandidType, Deserialize)]
pub struct TransactionRequest {
    /// The type of the transaction:
    /// - "0x0" for legacy transactions (pre- EIP-2718)
    /// - "0x1" for access list transactions (EIP-2930)
    /// - "0x2" for EIP-1559 transactions
    #[serde(rename = "type")]
    pub tx_type: Option<HexByte>,

    /// Transaction nonce
    pub nonce: Option<Nat256>,

    /// Address of the receiver or `None` in a contract creation transaction.
    pub to: Option<Hex20>,

    /// The address of the sender.
    pub from: Option<Hex20>,

    /// Gas limit for the transaction.
    pub gas: Option<Nat256>,

    /// Amount of ETH sent with this transaction.
    pub value: Option<Nat256>,

    /// Transaction input data
    pub input: Option<Hex>,

    /// The legacy gas price willing to be paid by the sender in wei.
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<Nat256>,

    /// Maximum fee per gas the sender is willing to pay to miners in wei.
    #[serde(rename = "maxPriorityFeePerGas")]
    pub max_priority_fee_per_gas: Option<Nat256>,

    /// The maximum total fee per gas the sender is willing to pay (includes the network / base fee and miner / priority fee) in wei.
    #[serde(rename = "maxFeePerGas")]
    pub max_fee_per_gas: Option<Nat256>,

    /// The maximum total fee per gas the sender is willing to pay for blob gas in wei.
    #[serde(rename = "maxFeePerBlobGas")]
    pub max_fee_per_blob_gas: Option<Nat256>,

    /// EIP-2930 access list
    #[serde(rename = "accessList")]
    pub access_list: Option<AccessList>,

    /// List of versioned blob hashes associated with the transaction's EIP-4844 data blobs.
    #[serde(rename = "blobVersionedHashes")]
    pub blob_versioned_hashes: Option<Vec<Hex32>>,

    /// Raw blob data.
    pub blobs: Option<Vec<Hex>>,

    /// Chain ID that this transaction is valid on.
    #[serde(rename = "chainId")]
    pub chain_id: Option<Nat256>,
}

#[cfg_attr(test, derive(Serialize))]
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
#[serde(transparent)]
pub struct AccessList(pub Vec<AccessListEntry>);

#[cfg_attr(test, derive(Serialize))]
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct AccessListEntry {
    pub address: Hex20,
    #[serde(rename = "storageKeys")]
    pub storage_keys: Vec<Hex32>,
}
