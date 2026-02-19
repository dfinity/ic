use crate::rpc_client::{
    json::{FixedSizeData, Hash, JsonByte, LogsBloom},
    numeric::{
        BlockNonce, BlockNumber, Difficulty, GasAmount, LogIndex, NumBytes, Timestamp,
        TransactionIndex, Wei, WeiPerGas,
    },
};
use candid::Deserialize;
use evm_rpc_types::{Hex, Hex20, Hex256, Hex32, HexByte, Nat256};
use ic_ethereum_types::Address;
use serde::Serialize;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TransactionReceipt {
    /// The hash of the block containing the transaction.
    #[serde(rename = "blockHash")]
    pub block_hash: Hash,

    /// The number of the block containing the transaction.
    #[serde(rename = "blockNumber")]
    pub block_number: BlockNumber,

    /// The total base charge plus tip paid for each unit of gas.
    #[serde(rename = "effectiveGasPrice")]
    pub effective_gas_price: WeiPerGas,

    /// The sum of gas used by this transaction and all preceding transactions in the same block.
    #[serde(rename = "cumulativeGasUsed")]
    pub cumulative_gas_used: GasAmount,

    /// The amount of gas used for this specific transaction alone.
    #[serde(rename = "gasUsed")]
    pub gas_used: GasAmount,

    /// Status of the transaction.
    /// Only specified for transactions included after the Byzantium upgrade.
    pub status: Option<TransactionStatus>,

    /// The post-transaction state root.
    /// Only specified for transactions included before the Byzantium upgrade.
    pub root: Option<Hash>,

    /// The hash of the transaction
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Hash,

    /// The contract address created, if the transaction was a contract creation, otherwise null.
    #[serde(rename = "contractAddress")]
    pub contract_address: Option<Address>,

    /// Address of the sender.
    pub from: Address,

    /// An array of log objects that generated this transaction
    pub logs: Vec<LogEntry>,

    /// The bloom filter which is used to retrieve related logs
    #[serde(rename = "logsBloom")]
    pub logs_bloom: LogsBloom,

    /// Address of the receiver or null in a contract creation transaction.
    pub to: Option<Address>,

    /// The transactions index position in the block
    #[serde(rename = "transactionIndex")]
    pub transaction_index: TransactionIndex,

    /// The type of the transaction (e.g. "0x0" for legacy transactions, "0x2" for EIP-1559 transactions)
    #[serde(rename = "type")]
    pub tx_type: JsonByte,
}

impl From<TransactionReceipt> for evm_rpc_types::TransactionReceipt {
    fn from(value: TransactionReceipt) -> Self {
        Self {
            block_hash: Hex32::from(value.block_hash.into_bytes()),
            block_number: Nat256::from(value.block_number),
            effective_gas_price: Nat256::from(value.effective_gas_price),
            gas_used: Nat256::from(value.gas_used),
            cumulative_gas_used: Nat256::from(value.cumulative_gas_used),
            status: value.status.map(|v| match v {
                TransactionStatus::Success => Nat256::from(1_u8),
                TransactionStatus::Failure => Nat256::from(0_u8),
            }),
            root: value.root.map(Hash::into_bytes).map(Hex32::from),
            transaction_hash: Hex32::from(value.transaction_hash.into_bytes()),
            contract_address: value
                .contract_address
                .map(|address| Hex20::from(address.into_bytes())),
            from: Hex20::from(value.from.into_bytes()),
            logs: value
                .logs
                .into_iter()
                .map(evm_rpc_types::LogEntry::from)
                .collect(),
            logs_bloom: Hex256::from(value.logs_bloom.into_bytes()),
            to: value.to.map(|address| Hex20::from(address.into_bytes())),
            transaction_index: Nat256::from(value.transaction_index),
            tx_type: HexByte::from(value.tx_type.into_byte()),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(try_from = "ethnum::u256", into = "ethnum::u256")]
pub enum TransactionStatus {
    /// Transaction was mined and executed successfully.
    Success,

    /// Transaction was mined but execution failed (e.g., out-of-gas error).
    /// The amount of the transaction is returned to the sender but gas is consumed.
    /// Note that this is different from a transaction that is not mined at all: a failed transaction
    /// is part of the blockchain and the next transaction from the same sender should have an incremented
    /// transaction nonce.
    Failure,
}

impl From<TransactionStatus> for ethnum::u256 {
    fn from(value: TransactionStatus) -> Self {
        match value {
            TransactionStatus::Success => ethnum::u256::ONE,
            TransactionStatus::Failure => ethnum::u256::ZERO,
        }
    }
}

impl TryFrom<ethnum::u256> for TransactionStatus {
    type Error = String;

    fn try_from(value: ethnum::u256) -> Result<Self, Self::Error> {
        match value {
            ethnum::u256::ZERO => Ok(TransactionStatus::Failure),
            ethnum::u256::ONE => Ok(TransactionStatus::Success),
            _ => Err(format!("invalid transaction status: {}", value)),
        }
    }
}

impl Display for TransactionStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionStatus::Success => write!(f, "Success"),
            TransactionStatus::Failure => write!(f, "Failure"),
        }
    }
}

/// An entry of the [`eth_getLogs`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getlogs) call reply.
///
/// Example:
/// ```json
/// {
///    "address": "0x7e41257f7b5c3dd3313ef02b1f4c864fe95bec2b",
///    "topics": [
///      "0x2a2607d40f4a6feb97c36e0efd57e0aa3e42e0332af4fceb78f21b7dffcbd657"
///    ],
///    "data": "0x00000000000000000000000055654e7405fcb336386ea8f36954a211b2cda764000000000000000000000000000000000000000000000000002386f26fc100000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000003f62327071372d71677a7a692d74623564622d72357363692d637736736c2d6e646f756c2d666f7435742d347a7732702d657a6677692d74616a32792d76716500",
///    "blockNumber": "0x3aa4f4",
///    "transactionHash": "0x5618f72c485bd98a3df58d900eabe9e24bfaa972a6fe5227e02233fad2db1154",
///    "transactionIndex": "0x6",
///    "blockHash": "0x908e6b84d26d71421bfaa08e7966e0afcef3883a28a53a0a7a31104caf1e94c2",
///    "logIndex": "0x8",
///    "removed": false
///  }
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LogEntry {
    /// The address from which this log originated.
    pub address: Address,
    /// Array of 0 to 4 32 Bytes DATA of indexed log arguments.
    /// In solidity: The first topic is the event signature hash (e.g. Deposit(address,bytes32,uint256)),
    /// unless you declared the event with the anonymous specifier.
    pub topics: Vec<FixedSizeData>,
    /// Contains one or more 32-byte non-indexed log arguments.
    pub data: Data,
    /// The block number in which this log appeared.
    /// None if the block is pending.
    #[serde(rename = "blockNumber")]
    pub block_number: Option<BlockNumber>,
    /// 32 Bytes - hash of the transactions from which this log was created.
    /// None when its pending log.
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<Hash>,
    /// Integer of the transactions position within the block the log was created from.
    /// None if the log is pending.
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Option<TransactionIndex>,
    /// 32 Bytes - hash of the block in which this log appeared.
    /// None if the block is pending.
    #[serde(rename = "blockHash")]
    pub block_hash: Option<Hash>,
    /// Integer of the log index position in the block.
    /// None if the log is pending.
    #[serde(rename = "logIndex")]
    pub log_index: Option<LogIndex>,
    /// "true" when the log was removed due to a chain reorganization.
    /// "false" if it's a valid log.
    #[serde(default)]
    pub removed: bool,
}

impl From<LogEntry> for evm_rpc_types::LogEntry {
    fn from(value: LogEntry) -> Self {
        Self {
            address: evm_rpc_types::Hex20::from(value.address.into_bytes()),
            topics: value
                .topics
                .into_iter()
                .map(|t| t.into_bytes().into())
                .collect(),
            data: Hex::from(value.data),
            block_hash: value.block_hash.map(|x| x.into_bytes().into()),
            block_number: value.block_number.map(Nat256::from),
            transaction_hash: value.transaction_hash.map(|x| x.into_bytes().into()),
            transaction_index: value.transaction_index.map(Nat256::from),
            log_index: value.log_index.map(Nat256::from),
            removed: value.removed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    /// Base fee per gas
    /// Only included for blocks after the London Upgrade / EIP-1559.
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: Option<Wei>,

    /// Block number
    pub number: BlockNumber,

    /// Difficulty
    pub difficulty: Option<Difficulty>,

    /// Extra data
    #[serde(rename = "extraData")]
    pub extra_data: Data,

    /// Maximum gas allowed in this block
    #[serde(rename = "gasLimit")]
    pub gas_limit: GasAmount,

    /// Gas used by all transactions in this block
    #[serde(rename = "gasUsed")]
    pub gas_used: GasAmount,

    /// Block hash
    pub hash: Hash,

    /// Bloom filter for the logs.
    #[serde(rename = "logsBloom")]
    pub logs_bloom: LogsBloom,

    /// Miner
    pub miner: Address,

    /// Mix hash
    #[serde(rename = "mixHash")]
    pub mix_hash: Hash,

    /// Nonce
    pub nonce: BlockNonce,

    /// Parent block hash
    #[serde(rename = "parentHash")]
    pub parent_hash: Hash,

    /// Receipts root
    #[serde(rename = "receiptsRoot")]
    pub receipts_root: Hash,

    /// Ommers hash
    #[serde(rename = "sha3Uncles")]
    pub sha3_uncles: Hash,

    /// Block size
    pub size: NumBytes,

    /// State root
    #[serde(rename = "stateRoot")]
    pub state_root: Hash,

    /// Timestamp
    #[serde(rename = "timestamp")]
    pub timestamp: Timestamp,

    /// List of transactions in the block.
    /// Note that since `eth_get_block_by_number` sets `include_full_transactions` to false,
    /// this field only contains the transaction hashes and not the full transactions.
    #[serde(default)]
    pub transactions: Vec<Hash>,

    /// Transactions root
    #[serde(rename = "transactionsRoot")]
    pub transactions_root: Option<Hash>,

    /// Uncles
    #[serde(default)]
    pub uncles: Vec<Hash>,
}

impl From<Block> for evm_rpc_types::Block {
    fn from(value: Block) -> Self {
        Self {
            base_fee_per_gas: value.base_fee_per_gas.map(Nat256::from),
            number: Nat256::from(value.number),
            difficulty: value.difficulty.map(Nat256::from),
            extra_data: Hex::from(value.extra_data.0),
            gas_limit: Nat256::from(value.gas_limit),
            gas_used: Nat256::from(value.gas_used),
            hash: Hex32::from(value.hash.into_bytes()),
            logs_bloom: Hex256::from(value.logs_bloom.into_bytes()),
            miner: Hex20::from(value.miner.into_bytes()),
            mix_hash: Hex32::from(value.mix_hash.into_bytes()),
            nonce: Nat256::from(value.nonce),
            parent_hash: Hex32::from(value.parent_hash.into_bytes()),
            receipts_root: Hex32::from(value.receipts_root.into_bytes()),
            sha3_uncles: Hex32::from(value.sha3_uncles.into_bytes()),
            size: Nat256::from(value.size),
            state_root: Hex32::from(value.state_root.into_bytes()),
            timestamp: Nat256::from(value.timestamp),
            // The field totalDifficulty was removed from the official Ethereum JSON RPC Block schema in
            // https://github.com/ethereum/execution-apis/pull/570 and as a consequence is inconsistent between different providers.
            // See https://github.com/internet-computer-protocol/evm-rpc-canister/issues/311.
            total_difficulty: None,
            transactions: value
                .transactions
                .into_iter()
                .map(|tx| Hex32::from(tx.into_bytes()))
                .collect(),
            transactions_root: value.transactions_root.map(|x| Hex32::from(x.into_bytes())),
            uncles: value
                .uncles
                .into_iter()
                .map(|tx| Hex32::from(tx.into_bytes()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeeHistory {
    /// Lowest number block of the returned range.
    #[serde(rename = "oldestBlock")]
    pub oldest_block: BlockNumber,
    /// An array of block base fees per gas.
    /// This includes the next block after the newest of the returned range,
    /// because this value can be derived from the newest block.
    /// Zeroes are returned for pre-EIP-1559 blocks.
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: Vec<WeiPerGas>,
    /// An array of block gas used ratios (gasUsed / gasLimit).
    #[serde(default)]
    #[serde(rename = "gasUsedRatio")]
    pub gas_used_ratio: Vec<f64>,
    /// A two-dimensional array of effective priority fees per gas at the requested block percentiles.
    #[serde(default)]
    #[serde(rename = "reward")]
    pub reward: Vec<Vec<WeiPerGas>>,
}

impl From<FeeHistory> for evm_rpc_types::FeeHistory {
    fn from(value: FeeHistory) -> Self {
        Self {
            oldest_block: Nat256::from(value.oldest_block),
            base_fee_per_gas: value
                .base_fee_per_gas
                .into_iter()
                .map(Nat256::from)
                .collect(),
            gas_used_ratio: value.gas_used_ratio,
            reward: value
                .reward
                .into_iter()
                .map(|x| x.into_iter().map(Nat256::from).collect())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum SendRawTransactionResult {
    Ok,
    InsufficientFunds,
    NonceTooLow,
    NonceTooHigh,
}

impl From<SendRawTransactionResult> for evm_rpc_types::SendRawTransactionStatus {
    fn from(status: SendRawTransactionResult) -> Self {
        match status {
            SendRawTransactionResult::Ok => Self::Ok(None),
            SendRawTransactionResult::InsufficientFunds => Self::InsufficientFunds,
            SendRawTransactionResult::NonceTooLow => Self::NonceTooLow,
            SendRawTransactionResult::NonceTooHigh => Self::NonceTooHigh,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Data(#[serde(with = "ic_ethereum_types::serde_data")] pub Vec<u8>);

impl From<Vec<u8>> for Data {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Hex> for Data {
    fn from(hex: Hex) -> Self {
        Self::from(Vec::<u8>::from(hex))
    }
}

impl From<Data> for Hex {
    fn from(data: Data) -> Self {
        Self::from(data.0)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct RawJson(pub String);

impl From<RawJson> for String {
    fn from(value: RawJson) -> Self {
        value.0
    }
}
