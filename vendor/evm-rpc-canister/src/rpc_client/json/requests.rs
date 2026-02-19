use crate::rpc_client::{
    amount::Amount,
    json::{responses::Data, FixedSizeData, Hash, JsonByte, StorageKey},
    numeric::{BlockNumber, ChainId, GasAmount, NumBlocks, TransactionNonce, Wei, WeiPerGas},
};
use ic_ethereum_types::Address;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fmt::{Display, Formatter},
};

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

impl From<evm_rpc_types::GetTransactionCountArgs> for GetTransactionCountParams {
    fn from(args: evm_rpc_types::GetTransactionCountArgs) -> Self {
        Self {
            address: Address::new(<[u8; 20]>::from(args.address)),
            block: BlockSpec::from(args.block),
        }
    }
}

/// Parameters of the [`eth_getLogs`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getlogs) call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLogsParams {
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    #[serde(rename = "fromBlock")]
    pub from_block: BlockSpec,
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    #[serde(rename = "toBlock")]
    pub to_block: BlockSpec,
    /// Contract address or a list of addresses from which logs should originate.
    pub address: Vec<Address>,
    /// Array of 32 Bytes DATA topics.
    /// Topics are order-dependent.
    /// Each topic can also be an array of DATA with "or" options.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub topics: Vec<Vec<FixedSizeData>>,
}

impl From<evm_rpc_types::GetLogsArgs> for GetLogsParams {
    fn from(args: evm_rpc_types::GetLogsArgs) -> Self {
        Self {
            from_block: args.from_block.map(BlockSpec::from).unwrap_or_default(),
            to_block: args.to_block.map(BlockSpec::from).unwrap_or_default(),
            address: args
                .addresses
                .into_iter()
                .map(|address| Address::new(<[u8; 20]>::from(address)))
                .collect(),
            topics: args
                .topics
                .unwrap_or_default()
                .into_iter()
                .map(|topic| {
                    topic
                        .into_iter()
                        .map(|t| FixedSizeData::new(<[u8; 32]>::from(t)))
                        .collect()
                })
                .collect(),
        }
    }
}

/// Parameters of the [`eth_feeHistory`](https://ethereum.github.io/execution-apis/api-documentation/) call.
#[derive(Debug, Serialize, Clone)]
#[serde(into = "(NumBlocks, BlockSpec, Vec<u8>)")]
pub struct FeeHistoryParams {
    /// Number of blocks in the requested range.
    /// Typically providers request this to be between 1 and 1024.
    pub block_count: NumBlocks,
    /// Highest block of the requested range.
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    pub highest_block: BlockSpec,
    /// A monotonically increasing list of percentile values between 0 and 100.
    /// For each block in the requested range, the transactions will be sorted in ascending order
    /// by effective tip per gas and the corresponding effective tip for the percentile
    /// will be determined, accounting for gas consumed.
    pub reward_percentiles: Vec<u8>,
}

impl From<FeeHistoryParams> for (NumBlocks, BlockSpec, Vec<u8>) {
    fn from(value: FeeHistoryParams) -> Self {
        (
            value.block_count,
            value.highest_block,
            value.reward_percentiles,
        )
    }
}

impl From<evm_rpc_types::FeeHistoryArgs> for FeeHistoryParams {
    fn from(args: evm_rpc_types::FeeHistoryArgs) -> Self {
        Self {
            block_count: NumBlocks::from(args.block_count),
            highest_block: BlockSpec::from(args.newest_block),
            reward_percentiles: args.reward_percentiles.unwrap_or_default(),
        }
    }
}

/// The block specification indicating which block to query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BlockSpec {
    /// Query the block with the specified index.
    Number(BlockNumber),
    /// Query the block with the specified tag.
    Tag(BlockTag),
}

impl From<evm_rpc_types::BlockTag> for BlockSpec {
    fn from(value: evm_rpc_types::BlockTag) -> Self {
        match value {
            evm_rpc_types::BlockTag::Number(n) => Self::Number(BlockNumber::from(n)),
            evm_rpc_types::BlockTag::Latest => Self::Tag(BlockTag::Latest),
            evm_rpc_types::BlockTag::Safe => Self::Tag(BlockTag::Safe),
            evm_rpc_types::BlockTag::Finalized => Self::Tag(BlockTag::Finalized),
            evm_rpc_types::BlockTag::Earliest => Self::Tag(BlockTag::Earliest),
            evm_rpc_types::BlockTag::Pending => Self::Tag(BlockTag::Pending),
        }
    }
}

impl Default for BlockSpec {
    fn default() -> Self {
        Self::Tag(BlockTag::default())
    }
}

impl From<BlockNumber> for BlockSpec {
    fn from(value: BlockNumber) -> Self {
        BlockSpec::Number(value)
    }
}

/// Block tags.
/// See <https://ethereum.org/en/developers/docs/apis/json-rpc/#default-block>
#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockTag {
    /// The latest mined block.
    #[default]
    #[serde(rename = "latest")]
    Latest,
    /// The latest safe head block.
    /// See
    /// <https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels>
    #[serde(rename = "safe")]
    Safe,
    /// The latest finalized block.
    /// See
    /// <https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels>
    #[serde(rename = "finalized")]
    Finalized,
    /// Earliest/genesis block
    #[serde(rename = "earliest")]
    Earliest,
    /// Pending state/transactions
    #[serde(rename = "pending")]
    Pending,
}

impl Display for BlockTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Latest => write!(f, "latest"),
            Self::Safe => write!(f, "safe"),
            Self::Finalized => write!(f, "finalized"),
            Self::Earliest => write!(f, "earliest"),
            Self::Pending => write!(f, "pending"),
        }
    }
}

/// Parameters of the [`eth_getBlockByNumber`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getblockbynumber) call.
#[derive(Debug, Serialize, Clone)]
#[serde(into = "(BlockSpec, bool)")]
pub struct GetBlockByNumberParams {
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    pub block: BlockSpec,
    /// If true, returns the full transaction objects. If false, returns only the hashes of the transactions.
    pub include_full_transactions: bool,
}

impl From<GetBlockByNumberParams> for (BlockSpec, bool) {
    fn from(value: GetBlockByNumberParams) -> Self {
        (value.block, value.include_full_transactions)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(into = "(TransactionRequest, BlockSpec)")]
pub struct EthCallParams {
    pub transaction: TransactionRequest,
    pub block: BlockSpec,
}

impl From<evm_rpc_types::CallArgs> for EthCallParams {
    fn from(value: evm_rpc_types::CallArgs) -> Self {
        Self {
            transaction: TransactionRequest::from(value.transaction),
            block: BlockSpec::from(value.block.unwrap_or_default()),
        }
    }
}

impl From<EthCallParams> for (TransactionRequest, BlockSpec) {
    fn from(value: EthCallParams) -> Self {
        (value.transaction, value.block)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionRequest {
    /// The type of the transaction (e.g. "0x0" for legacy transactions, "0x2" for EIP-1559 transactions)
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub tx_type: Option<JsonByte>,

    /// Transaction nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<TransactionNonce>,

    /// Address of the receiver or `None` in a contract creation transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,

    /// The address of the sender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,

    /// Gas limit for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<GasAmount>,

    /// Amount of ETH sent with this transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Wei>,

    /// Transaction input data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<Data>,

    /// The legacy gas price willing to be paid by the sender in wei.
    #[serde(rename = "gasPrice", skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<WeiPerGas>,

    /// Maximum fee per gas the sender is willing to pay to miners in wei.
    #[serde(
        rename = "maxPriorityFeePerGas",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_priority_fee_per_gas: Option<WeiPerGas>,

    /// The maximum total fee per gas the sender is willing to pay (includes the network / base fee and miner / priority fee) in wei.
    #[serde(rename = "maxFeePerGas", skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<WeiPerGas>,

    /// The maximum total fee per gas the sender is willing to pay for blob gas in wei.
    #[serde(rename = "maxFeePerBlobGas", skip_serializing_if = "Option::is_none")]
    pub max_fee_per_blob_gas: Option<WeiPerGas>,

    /// EIP-2930 access list
    #[serde(rename = "accessList", skip_serializing_if = "Option::is_none")]
    pub access_list: Option<AccessList>,

    /// List of versioned blob hashes associated with the transaction's EIP-4844 data blobs.
    #[serde(
        rename = "blobVersionedHashes",
        skip_serializing_if = "Option::is_none"
    )]
    pub blob_versioned_hashes: Option<Vec<Hash>>,

    /// Raw blob data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blobs: Option<Vec<Data>>,

    /// Chain ID that this transaction is valid on.
    #[serde(rename = "chainId", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<ChainId>,
}

impl From<evm_rpc_types::TransactionRequest> for TransactionRequest {
    fn from(
        evm_rpc_types::TransactionRequest {
            tx_type,
            nonce,
            to,
            from,
            gas,
            value,
            input,
            gas_price,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            max_fee_per_blob_gas,
            access_list,
            blob_versioned_hashes,
            blobs,
            chain_id,
        }: evm_rpc_types::TransactionRequest,
    ) -> Self {
        fn map_access_list(list: evm_rpc_types::AccessList) -> AccessList {
            AccessList(
                list.0
                    .into_iter()
                    .map(|entry| AccessListItem {
                        address: Address::new(<[u8; 20]>::from(entry.address)),
                        storage_keys: entry
                            .storage_keys
                            .into_iter()
                            .map(|key| StorageKey::new(<[u8; 32]>::from(key)))
                            .collect(),
                    })
                    .collect(),
            )
        }
        Self {
            tx_type: tx_type.map(|t| JsonByte::new(u8::from(t))),
            nonce: nonce.map(Amount::from),
            to: to.map(|address| Address::new(<[u8; 20]>::from(address))),
            from: from.map(|address| Address::new(<[u8; 20]>::from(address))),
            gas: gas.map(Amount::from),
            value: value.map(Amount::from),
            input: input.map(Data::from),
            gas_price: gas_price.map(Amount::from),
            max_priority_fee_per_gas: max_priority_fee_per_gas.map(Amount::from),
            max_fee_per_gas: max_fee_per_gas.map(Amount::from),
            max_fee_per_blob_gas: max_fee_per_blob_gas.map(Amount::from),
            access_list: access_list.map(map_access_list),
            blob_versioned_hashes: blob_versioned_hashes
                .map(|hashes| hashes.into_iter().map(Hash::from).collect()),
            blobs: blobs.map(|blobs| blobs.into_iter().map(Data::from).collect()),
            chain_id: chain_id.map(Amount::from),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct AccessList(pub Vec<AccessListItem>);

impl AccessList {
    pub fn new() -> Self {
        Self(Vec::new())
    }
}

impl Default for AccessList {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessListItem {
    /// Accessed address
    pub address: Address,
    /// Accessed storage keys
    #[serde(rename = "storageKeys")]
    pub storage_keys: Vec<StorageKey>,
}
