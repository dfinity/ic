//! This module contains definitions for communicating with an Ethereum API using the [JSON RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/)
//! interface.

use crate::endpoints::CandidBlockTag;
use crate::numeric::{BlockNumber, LogIndex, Wei, WeiPerGas};
use candid::CandidType;
use ethnum;
use evm_rpc_client::BlockTag as EvmBlockTag;
use evm_rpc_client::{
    HttpOutcallError as EvmHttpOutcallError,
    SendRawTransactionStatus as EvmSendRawTransactionStatus,
};
use ic_cdk::api::call::RejectionCode;
use ic_ethereum_types::Address;
pub use metrics::encode as encode_metrics;
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};

#[cfg(test)]
mod tests;

// This constant is our approximation of the expected header size.
// The HTTP standard doesn't define any limit, and many implementations limit
// the headers size to 8 KiB. We chose a lower limit because headers observed on most providers
// fit in the constant defined below, and if there is spike, then the payload size adjustment
// should take care of that.
pub const HEADER_SIZE_LIMIT: u64 = 2 * 1024;

// This constant comes from the IC specification:
// > If provided, the value must not exceed 2MB
const HTTP_MAX_SIZE: u64 = 2_000_000;

pub const MAX_PAYLOAD_SIZE: u64 = HTTP_MAX_SIZE - HEADER_SIZE_LIMIT;

pub type Quantity = ethnum::u256;

pub fn into_nat(quantity: Quantity) -> candid::Nat {
    use num_bigint::BigUint;
    candid::Nat::from(BigUint::from_bytes_be(&quantity.to_be_bytes()))
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Data(#[serde(with = "ic_ethereum_types::serde_data")] pub Vec<u8>);

impl std::str::FromStr for Data {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(Value::String(s.to_string()))
            .map_err(|e| format!("failed to parse data from string: {}", e))
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct FixedSizeData(#[serde(with = "ic_ethereum_types::serde_data")] pub [u8; 32]);

impl FixedSizeData {
    pub const ZERO: Self = Self([0u8; 32]);
}

impl AsRef<[u8]> for FixedSizeData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::str::FromStr for FixedSizeData {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err("Ethereum hex string doesn't start with 0x".to_string());
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&s[2..], &mut bytes)
            .map_err(|e| format!("failed to decode hash from hex: {}", e))?;
        Ok(Self(bytes))
    }
}

impl Debug for FixedSizeData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl Display for FixedSizeData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl LowerHex for FixedSizeData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl UpperHex for FixedSizeData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode_upper(self.0))
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum SendRawTransactionResult {
    Ok,
    InsufficientFunds,
    NonceTooLow,
    NonceTooHigh,
}

impl From<EvmSendRawTransactionStatus> for SendRawTransactionResult {
    fn from(value: EvmSendRawTransactionStatus) -> Self {
        match value {
            EvmSendRawTransactionStatus::Ok(_) => SendRawTransactionResult::Ok,
            EvmSendRawTransactionStatus::InsufficientFunds => {
                SendRawTransactionResult::InsufficientFunds
            }
            EvmSendRawTransactionStatus::NonceTooLow => SendRawTransactionResult::NonceTooLow,
            EvmSendRawTransactionStatus::NonceTooHigh => SendRawTransactionResult::NonceTooHigh,
        }
    }
}

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Decode, Deserialize, Encode, Serialize,
)]
#[serde(transparent)]
#[cbor(transparent)]
pub struct Hash(
    #[serde(with = "ic_ethereum_types::serde_data")]
    #[cbor(n(0), with = "minicbor::bytes")]
    pub [u8; 32],
);

impl Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl LowerHex for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl UpperHex for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode_upper(self.0))
    }
}

impl std::str::FromStr for Hash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err("Ethereum hash doesn't start with 0x".to_string());
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&s[2..], &mut bytes)
            .map_err(|e| format!("failed to decode hash from hex: {}", e))?;
        Ok(Self(bytes))
    }
}

/// Block tags.
/// See <https://ethereum.org/en/developers/docs/apis/json-rpc/#default-block>
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockTag {
    /// The latest mined block.
    #[default]
    Latest,
    /// The latest safe head block.
    /// See
    /// <https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels>
    Safe,
    /// The latest finalized block.
    /// See
    /// <https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels>
    Finalized,
}

impl From<BlockTag> for EvmBlockTag {
    fn from(block_tag: BlockTag) -> Self {
        match block_tag {
            BlockTag::Latest => EvmBlockTag::Latest,
            BlockTag::Safe => EvmBlockTag::Safe,
            BlockTag::Finalized => EvmBlockTag::Finalized,
        }
    }
}

impl From<CandidBlockTag> for BlockTag {
    fn from(block_tag: CandidBlockTag) -> BlockTag {
        match block_tag {
            CandidBlockTag::Latest => BlockTag::Latest,
            CandidBlockTag::Safe => BlockTag::Safe,
            CandidBlockTag::Finalized => BlockTag::Finalized,
        }
    }
}

impl From<BlockTag> for CandidBlockTag {
    fn from(value: BlockTag) -> Self {
        match value {
            BlockTag::Latest => CandidBlockTag::Latest,
            BlockTag::Safe => CandidBlockTag::Safe,
            BlockTag::Finalized => CandidBlockTag::Finalized,
        }
    }
}

impl Display for BlockTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Latest => write!(f, "latest"),
            Self::Safe => write!(f, "safe"),
            Self::Finalized => write!(f, "finalized"),
        }
    }
}

/// The block specification indicating which block to query.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BlockSpec {
    /// Query the block with the specified index.
    Number(BlockNumber),
    /// Query the block with the specified tag.
    Tag(BlockTag),
}

impl Default for BlockSpec {
    fn default() -> Self {
        Self::Tag(BlockTag::default())
    }
}

impl std::str::FromStr for BlockSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("0x") {
            let block_number = BlockNumber::from_str_hex(s)
                .map_err(|e| format!("failed to parse block number '{s}': {e}"))?;
            return Ok(BlockSpec::Number(block_number));
        }
        Ok(BlockSpec::Tag(match s {
            "latest" => BlockTag::Latest,
            "safe" => BlockTag::Safe,
            "finalized" => BlockTag::Finalized,
            _ => return Err(format!("unknown block tag '{s}'")),
        }))
    }
}

/// Parameters of the [`eth_getLogs`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getlogs) call.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLogsParam {
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    pub from_block: BlockSpec,
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    pub to_block: BlockSpec,
    /// Contract address or a list of addresses from which logs should originate.
    pub address: Vec<Address>,
    /// Array of 32 Bytes DATA topics.
    /// Topics are order-dependent.
    /// Each topic can also be an array of DATA with "or" options.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub topics: Vec<Topic>,
}

/// A topic is either a 32 Bytes DATA, or an array of 32 Bytes DATA with "or" options.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Topic {
    Single(FixedSizeData),
    Multiple(Vec<FixedSizeData>),
}

impl From<FixedSizeData> for Topic {
    fn from(data: FixedSizeData) -> Self {
        Topic::Single(data)
    }
}

impl From<Vec<FixedSizeData>> for Topic {
    fn from(data: Vec<FixedSizeData>) -> Self {
        Topic::Multiple(data)
    }
}

/// An entry of the [`eth_getLogs`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getlogs) call reply.
// Example:
// ```json
// {
//    "address": "0x7e41257f7b5c3dd3313ef02b1f4c864fe95bec2b",
//    "topics": [
//      "0x2a2607d40f4a6feb97c36e0efd57e0aa3e42e0332af4fceb78f21b7dffcbd657"
//    ],
//    "data": "0x00000000000000000000000055654e7405fcb336386ea8f36954a211b2cda764000000000000000000000000000000000000000000000000002386f26fc100000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000003f62327071372d71677a7a692d74623564622d72357363692d637736736c2d6e646f756c2d666f7435742d347a7732702d657a6677692d74616a32792d76716500",
//    "blockNumber": "0x3aa4f4",
//    "transactionHash": "0x5618f72c485bd98a3df58d900eabe9e24bfaa972a6fe5227e02233fad2db1154",
//    "transactionIndex": "0x6",
//    "blockHash": "0x908e6b84d26d71421bfaa08e7966e0afcef3883a28a53a0a7a31104caf1e94c2",
//    "logIndex": "0x8",
//    "removed": false
//  }
// ```
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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
    pub block_number: Option<BlockNumber>,
    // 32 Bytes - hash of the transactions from which this log was created.
    // None when its pending log.
    pub transaction_hash: Option<Hash>,
    // Integer of the transactions position within the block the log was created from.
    // None if the log is pending.
    pub transaction_index: Option<Quantity>,
    /// 32 Bytes - hash of the block in which this log appeared.
    /// None if the block is pending.
    pub block_hash: Option<Hash>,
    /// Integer of the log index position in the block.
    /// None if the log is pending.
    pub log_index: Option<LogIndex>,
    /// "true" when the log was removed due to a chain reorganization.
    /// "false" if it's a valid log.
    #[serde(default)]
    pub removed: bool,
}

/// Parameters of the [`eth_feeHistory`](https://ethereum.github.io/execution-apis/api-documentation/) call.
#[derive(Clone, Debug, Serialize)]
#[serde(into = "(Quantity, BlockSpec, Vec<u8>)")]
pub struct FeeHistoryParams {
    /// Number of blocks in the requested range.
    /// Typically providers request this to be between 1 and 1024.
    pub block_count: Quantity,
    /// Highest block of the requested range.
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    pub highest_block: BlockSpec,
    /// A monotonically increasing list of percentile values between 0 and 100.
    /// For each block in the requested range, the transactions will be sorted in ascending order
    /// by effective tip per gas and the corresponding effective tip for the percentile
    /// will be determined, accounting for gas consumed.
    pub reward_percentiles: Vec<u8>,
}

impl From<FeeHistoryParams> for (Quantity, BlockSpec, Vec<u8>) {
    fn from(value: FeeHistoryParams) -> Self {
        (
            value.block_count,
            value.highest_block,
            value.reward_percentiles,
        )
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeHistory {
    /// Lowest number block of the returned range.
    pub oldest_block: BlockNumber,
    /// An array of block base fees per gas.
    /// This includes the next block after the newest of the returned range,
    /// because this value can be derived from the newest block.
    /// Zeroes are returned for pre-EIP-1559 blocks.
    pub base_fee_per_gas: Vec<WeiPerGas>,
    /// A two-dimensional array of effective priority fees per gas at the requested block percentiles.
    pub reward: Vec<Vec<WeiPerGas>>,
}

impl From<BlockNumber> for BlockSpec {
    fn from(value: BlockNumber) -> Self {
        BlockSpec::Number(value)
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    ///The block number. `None` when its pending block.
    pub number: BlockNumber,
    /// Base fee value of this block
    pub base_fee_per_gas: Wei,
}

/// An envelope for all JSON-RPC replies.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JsonRpcResult<T> {
    Result(T),
    Error { code: i64, message: String },
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum HttpOutcallError {
    /// Error from the IC system API.
    IcError {
        code: RejectionCode,
        message: String,
    },
    /// Response is not a valid JSON-RPC response,
    /// which means that the response was not successful (status other than 2xx)
    /// or that the response body could not be deserialized into a JSON-RPC response.
    InvalidHttpJsonRpcResponse {
        status: u16,
        body: String,
        parsing_error: Option<String>,
    },
}

impl From<EvmHttpOutcallError> for HttpOutcallError {
    fn from(value: EvmHttpOutcallError) -> Self {
        match value {
            EvmHttpOutcallError::IcError { code, message } => Self::IcError { code, message },
            EvmHttpOutcallError::InvalidHttpJsonRpcResponse {
                status,
                body,
                parsing_error,
            } => Self::InvalidHttpJsonRpcResponse {
                status,
                body,
                parsing_error,
            },
        }
    }
}

impl HttpOutcallError {
    pub fn is_response_too_large(&self) -> bool {
        match self {
            Self::IcError { code, message } => is_response_too_large(code, message),
            _ => false,
        }
    }
}

pub fn is_response_too_large(code: &RejectionCode, message: &str) -> bool {
    code == &RejectionCode::SysFatal
        && (message.contains("size limit") || message.contains("length limit"))
}

pub type HttpOutcallResult<T> = Result<T, HttpOutcallError>;

pub(super) mod metrics {
    use ic_metrics_encoder::MetricsEncoder;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// The max number of RPC call retries we expect to see (plus one).
    const MAX_EXPECTED_RETRIES: usize = 20;

    #[derive(Default)]
    struct RetryHistogram {
        /// The histogram of HTTP call retry counts.
        /// The last bucket corresponds to the "infinite" value that exceeds the maximum number we
        /// expect to see in practice.
        retry_buckets: [u64; MAX_EXPECTED_RETRIES + 1],
        retry_count: u64,
    }

    impl RetryHistogram {
        /// Returns a iterator over the histrogram buckets in the format that ic-metrics-encoder
        /// expects.
        fn iter(&self) -> impl Iterator<Item = (f64, f64)> + '_ {
            (0..MAX_EXPECTED_RETRIES)
                .zip(self.retry_buckets[0..MAX_EXPECTED_RETRIES].iter().cloned())
                .map(|(k, v)| (k as f64, v as f64))
                .chain(std::iter::once((
                    f64::INFINITY,
                    self.retry_buckets[MAX_EXPECTED_RETRIES] as f64,
                )))
        }
    }

    #[derive(Default)]
    pub struct HttpMetrics {
        /// Retry counts histograms indexed by the ETH RCP method name.
        retry_histogram_per_method: BTreeMap<String, RetryHistogram>,
    }

    impl HttpMetrics {
        pub fn encode<W: std::io::Write>(
            &self,
            encoder: &mut MetricsEncoder<W>,
        ) -> std::io::Result<()> {
            if self.retry_histogram_per_method.is_empty() {
                return Ok(());
            }

            let mut histogram_vec = encoder.histogram_vec(
                "cketh_eth_rpc_call_retry_count",
                "The number of ETH RPC call retries by method.",
            )?;

            for (method, histogram) in &self.retry_histogram_per_method {
                histogram_vec = histogram_vec.histogram(
                    &[("method", method.as_str())],
                    histogram.iter(),
                    histogram.retry_count as f64,
                )?;
            }

            Ok(())
        }
    }

    thread_local! {
        static METRICS: RefCell<HttpMetrics> = RefCell::default();
    }

    /// Encodes the metrics related to ETH RPC method calls.
    pub fn encode<W: std::io::Write>(encoder: &mut MetricsEncoder<W>) -> std::io::Result<()> {
        METRICS.with(|metrics| metrics.borrow().encode(encoder))
    }
}
