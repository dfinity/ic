//! This module contains definitions for communicating with an Ethereum API using the [JSON RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/)
//! interface.

use crate::address::Address;
use crate::checked_amount::CheckedAmountOf;
use crate::endpoints::CandidBlockTag;
use crate::eth_rpc_client::providers::RpcService;
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::eth_rpc_client::RpcTransport;
use crate::eth_rpc_error::{sanitize_send_raw_transaction_result, Parser};
use crate::logs::{DEBUG, TRACE_HTTP};
use crate::numeric::{BlockNumber, LogIndex, TransactionCount, Wei, WeiPerGas};
use crate::state::{mutate_state, State};
use candid::{candid_method, CandidType};
use ethnum;
use ic_canister_log::log;
use ic_cdk::api::call::RejectionCode;
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext,
};
use ic_cdk_macros::query;
pub use metrics::encode as encode_metrics;
use minicbor::{Decode, Encode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;
use std::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
use thiserror::Error;

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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Data(#[serde(with = "crate::serde_data")] pub Vec<u8>);

impl CandidType for Data {
    fn _ty() -> candid::types::Type {
        String::_ty()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        serializer.serialize_text(&format!("0x{}", hex::encode(self)))
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct FixedSizeData(#[serde(with = "crate::serde_data")] pub [u8; 32]);

impl CandidType for FixedSizeData {
    fn _ty() -> candid::types::Type {
        String::_ty()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        serializer.serialize_text(&format!("{:#x}", self))
    }
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, CandidType)]
pub enum SendRawTransactionResult {
    Ok,
    InsufficientFunds,
    NonceTooLow,
    NonceTooHigh,
}

impl HttpResponsePayload for SendRawTransactionResult {
    fn response_transform() -> Option<ResponseTransform> {
        Some(ResponseTransform::SendRawTransaction)
    }
}

#[derive(
    Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, Ord, PartialOrd, Encode, Decode,
)]
#[serde(transparent)]
#[cbor(transparent)]
pub struct Hash(
    #[serde(with = "crate::serde_data")]
    #[cbor(n(0), with = "minicbor::bytes")]
    pub [u8; 32],
);

impl CandidType for Hash {
    fn _ty() -> candid::types::Type {
        String::_ty()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        serializer.serialize_text(&format!("{:#x}", self))
    }
}

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

impl HttpResponsePayload for Hash {}

/// Block tags.
/// See <https://ethereum.org/en/developers/docs/apis/json-rpc/#default-block>
#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, CandidType)]
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
    #[serde(rename = "earliest")]
    Earliest,
    #[serde(rename = "pending")]
    Pending,
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

/// The block specification indicating which block to query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, CandidType)]
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
#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct GetLogsParam {
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, CandidType)]
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
    // 32 Bytes - hash of the transactions from which this log was created.
    // None when its pending log.
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<Hash>,
    // Integer of the transactions position within the block the log was created from.
    // None if the log is pending.
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Option<CheckedAmountOf<()>>,
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

impl HttpResponsePayload for Vec<LogEntry> {
    fn response_transform() -> Option<ResponseTransform> {
        Some(ResponseTransform::LogEntries)
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

/// Parameters of the [`eth_feeHistory`](https://ethereum.github.io/execution-apis/api-documentation/) call.
#[derive(Debug, Serialize, Clone)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, CandidType)]
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

impl HttpResponsePayload for FeeHistory {
    fn response_transform() -> Option<ResponseTransform> {
        Some(ResponseTransform::FeeHistory)
    }
}

impl HttpResponsePayload for Wei {}

impl From<BlockNumber> for BlockSpec {
    fn from(value: BlockNumber) -> Self {
        BlockSpec::Number(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, CandidType)]
pub struct Block {
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: Option<Wei>,
    pub number: BlockNumber,
    pub difficulty: Option<CheckedAmountOf<()>>,
    #[serde(rename = "extraData")]
    pub extra_data: String,
    #[serde(rename = "gasLimit")]
    pub gas_limit: CheckedAmountOf<()>,
    #[serde(rename = "gasUsed")]
    pub gas_used: CheckedAmountOf<()>,
    pub hash: String,
    #[serde(rename = "logsBloom")]
    pub logs_bloom: String,
    pub miner: String,
    #[serde(rename = "mixHash")]
    pub mix_hash: String,
    pub nonce: CheckedAmountOf<()>,
    #[serde(rename = "parentHash")]
    pub parent_hash: String,
    #[serde(rename = "receiptsRoot")]
    pub receipts_root: String,
    #[serde(rename = "sha3Uncles")]
    pub sha3_uncles: String,
    pub size: CheckedAmountOf<()>,
    #[serde(rename = "stateRoot")]
    pub state_root: String,
    #[serde(rename = "timestamp")]
    pub timestamp: CheckedAmountOf<()>,
    #[serde(rename = "totalDifficulty")]
    pub total_difficulty: Option<CheckedAmountOf<()>>,
    #[serde(default)]
    pub transactions: Vec<String>,
    #[serde(rename = "transactionsRoot")]
    pub transactions_root: Option<String>,
    #[serde(default)]
    pub uncles: Vec<String>,
}

impl HttpResponsePayload for Block {
    fn response_transform() -> Option<ResponseTransform> {
        Some(ResponseTransform::Block)
    }
}

/// An envelope for all JSON-RPC requests.
#[derive(Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    jsonrpc: String,
    method: String,
    id: u64,
    pub params: T,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcReply<T> {
    pub id: u64,
    pub jsonrpc: String,
    #[serde(flatten)]
    pub result: JsonRpcResult<T>,
}

/// An envelope for all JSON-RPC replies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CandidType)]
pub enum JsonRpcResult<T> {
    #[serde(rename = "result")]
    Result(T),
    #[serde(rename = "error")]
    Error { code: i64, message: String },
}

impl<T> JsonRpcResult<T> {
    pub fn unwrap(self) -> T {
        match self {
            Self::Result(t) => t,
            Self::Error { code, message } => panic!(
                "expected JSON RPC call to succeed, got an error: error_code = {code}, message = {message}"
            ),
        }
    }
}

impl<T> From<JsonRpcResult<T>> for Result<T, RpcError> {
    fn from(result: JsonRpcResult<T>) -> Self {
        match result {
            JsonRpcResult::Result(r) => Ok(r),
            JsonRpcResult::Error { code, message } => Err(JsonRpcError { code, message }.into()),
        }
    }
}

/// Describes a payload transformation to execute before passing the HTTP response to consensus.
/// The purpose of these transformations is to ensure that the response encoding is deterministic
/// (the field order is the same).
#[derive(Encode, Decode, Debug)]
pub enum ResponseTransform {
    #[n(0)]
    Block,
    #[n(1)]
    LogEntries,
    #[n(2)]
    TransactionReceipt,
    #[n(3)]
    FeeHistory,
    #[n(4)]
    SendRawTransaction,
}

impl ResponseTransform {
    fn apply(&self, body_bytes: &mut Vec<u8>) {
        fn redact_response<T>(body: &mut Vec<u8>)
        where
            T: Serialize + DeserializeOwned,
        {
            let response: JsonRpcReply<T> = match serde_json::from_slice(body) {
                Ok(response) => response,
                Err(_) => return,
            };
            *body = serde_json::to_string(&response)
                .expect("BUG: failed to serialize response")
                .into_bytes();
        }

        fn redact_collection_response<T>(body: &mut Vec<u8>)
        where
            T: Serialize + DeserializeOwned,
        {
            let mut response: JsonRpcReply<Vec<T>> = match serde_json::from_slice(body) {
                Ok(response) => response,
                Err(_) => return,
            };

            if let JsonRpcResult::Result(ref mut result) = response.result {
                sort_by_hash(result);
            }

            *body = serde_json::to_string(&response)
                .expect("BUG: failed to serialize response")
                .into_bytes();
        }

        match self {
            Self::Block => redact_response::<Block>(body_bytes),
            Self::LogEntries => redact_collection_response::<LogEntry>(body_bytes),
            Self::TransactionReceipt => redact_response::<TransactionReceipt>(body_bytes),
            Self::FeeHistory => redact_response::<FeeHistory>(body_bytes),
            Self::SendRawTransaction => {
                sanitize_send_raw_transaction_result(body_bytes, Parser::new())
            }
        }
    }
}

#[query]
#[candid_method(query)]
fn cleanup_response(mut args: TransformArgs) -> HttpResponse {
    args.response.headers.clear();
    ic_cdk::println!(
        "RAW RESPONSE BEFORE TRANSFORM:\nstatus: {:?}\nbody:{:?}",
        args.response.status,
        String::from_utf8_lossy(&args.response.body).to_string()
    );
    let status_ok = args.response.status >= 200u16 && args.response.status < 300u16;
    if status_ok && !args.context.is_empty() {
        let maybe_transform: Result<ResponseTransform, _> = minicbor::decode(&args.context[..]);
        if let Ok(transform) = maybe_transform {
            transform.apply(&mut args.response.body);
        }
    }
    ic_cdk::println!(
        "RAW RESPONSE AFTER TRANSFORM:\nstatus: {:?}\nbody:{:?}",
        args.response.status,
        String::from_utf8_lossy(&args.response.body).to_string()
    );
    args.response
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub enum RpcError {
    // #[error("RPC provider error")]
    ProviderError(/* #[source] */ ProviderError),
    // #[error("HTTPS outcall error")]
    HttpOutcallError(/* #[source] */ HttpOutcallError),
    // #[error("JSON-RPC error")]
    JsonRpcError(/* #[source] */ JsonRpcError),
    // #[error("data format error")]
    ValidationError(/* #[source] */ ValidationError),
}

impl From<ProviderError> for RpcError {
    fn from(err: ProviderError) -> Self {
        RpcError::ProviderError(err)
    }
}

impl From<HttpOutcallError> for RpcError {
    fn from(err: HttpOutcallError) -> Self {
        RpcError::HttpOutcallError(err)
    }
}

impl From<JsonRpcError> for RpcError {
    fn from(err: JsonRpcError) -> Self {
        RpcError::JsonRpcError(err)
    }
}

impl From<ValidationError> for RpcError {
    fn from(err: ValidationError) -> Self {
        RpcError::ValidationError(err)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub enum ProviderError {
    // #[error("no permission")]
    NoPermission,
    // #[error("too few cycles (expected {expected}, received {received})")]
    TooFewCycles { expected: u128, received: u128 },
    // #[error("provider not found")]
    ProviderNotFound,
    // #[error("missing required provider")]
    MissingRequiredProvider,
}

#[derive(Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize)]
pub enum HttpOutcallError {
    /// Error from the IC system API.
    // #[error("IC system error code {}: {message}", *.code as i32)]
    IcError {
        code: RejectionCode,
        message: String,
    },
    /// Response is not a valid JSON-RPC response,
    /// which means that the response was not successful (status other than 2xx)
    /// or that the response body could not be deserialized into a JSON-RPC response.
    // #[error("invalid JSON-RPC response {status}: {})", .parsing_error.as_deref().unwrap_or(.body))]
    InvalidHttpJsonRpcResponse {
        status: u16,
        body: String,
        #[serde(rename = "parsingError")]
        parsing_error: Option<String>,
    },
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
        && (message.contains("size limit") || message.contains("length limit exceeded"))
}

pub type HttpOutcallResult<T> = Result<T, HttpOutcallError>;

#[derive(Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize)]
pub enum ValidationError {
    // #[error("{0}")]
    Custom(String),
    // #[error("invalid hex data: {0}")]
    InvalidHex(String),
}

pub fn are_errors_consistent<T: PartialEq>(
    left: &Result<T, RpcError>,
    right: &Result<T, RpcError>,
) -> bool {
    match (left, right) {
        (Ok(_), _) | (_, Ok(_)) => true,
        _ => left == right,
    }
}

#[derive(
    Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType, Serialize, Deserialize, Error,
)]
#[error("code {code}: {message}")]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResponseSizeEstimate(u64);

impl ResponseSizeEstimate {
    pub fn new(num_bytes: u64) -> Self {
        assert!(num_bytes > 0);
        assert!(num_bytes <= MAX_PAYLOAD_SIZE);
        Self(num_bytes)
    }

    /// Describes the expected (90th percentile) number of bytes in the HTTP response body.
    /// This number should be less than `MAX_PAYLOAD_SIZE`.
    pub fn get(self) -> u64 {
        self.0
    }

    /// Returns a higher estimate for the payload size.
    pub fn adjust(self) -> Self {
        Self(self.0.max(1024).saturating_mul(2).min(MAX_PAYLOAD_SIZE))
    }
}

impl fmt::Display for ResponseSizeEstimate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait HttpResponsePayload {
    fn response_transform() -> Option<ResponseTransform> {
        None
    }
}

impl<T: HttpResponsePayload> HttpResponsePayload for Option<T> {}

impl HttpResponsePayload for TransactionCount {}

/// Calls a JSON-RPC method on an Ethereum node at the specified URL.
pub async fn call<T, I, O>(
    provider: &RpcService,
    method: impl Into<String>,
    params: I,
    mut response_size_estimate: ResponseSizeEstimate,
) -> Result<O, RpcError>
where
    T: RpcTransport,
    I: Serialize,
    O: DeserializeOwned + HttpResponsePayload,
{
    let eth_method = method.into();
    let mut rpc_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        params,
        method: eth_method.clone(),
        id: 1,
    };
    let api = T::resolve_api(provider)?;
    let url = &api.url;
    let mut headers = vec![HttpHeader {
        name: "Content-Type".to_string(),
        value: "application/json".to_string(),
    }];
    if let Some(vec) = api.headers {
        headers.extend(vec);
    }
    let mut retries = 0;
    loop {
        rpc_request.id = mutate_state(State::next_request_id);
        let payload = serde_json::to_string(&rpc_request).unwrap();
        log!(TRACE_HTTP, "Calling url: {}, with payload: {payload}", url);

        let effective_size_estimate = response_size_estimate.get();
        let transform_op = O::response_transform()
            .as_ref()
            .map(|t| {
                let mut buf = vec![];
                minicbor::encode(t, &mut buf).unwrap();
                buf
            })
            .unwrap_or_default();

        let request = CanisterHttpRequestArgument {
            url: url.clone(),
            max_response_bytes: Some(effective_size_estimate),
            method: HttpMethod::POST,
            headers: headers.clone(),
            body: Some(payload.as_bytes().to_vec()),
            transform: Some(TransformContext::from_name(
                "cleanup_response".to_owned(),
                transform_op,
            )),
        };

        let response = match T::http_request(
            provider,
            &eth_method,
            request,
            effective_size_estimate,
        )
        .await
        {
            Err(RpcError::HttpOutcallError(HttpOutcallError::IcError { code, message }))
                if is_response_too_large(&code, &message) =>
            {
                let new_estimate = response_size_estimate.adjust();
                if response_size_estimate == new_estimate {
                    return Err(HttpOutcallError::IcError { code, message }.into());
                }
                log!(DEBUG, "The {eth_method} response didn't fit into {response_size_estimate} bytes, retrying with {new_estimate}");
                response_size_estimate = new_estimate;
                retries += 1;
                continue;
            }
            result => result?,
        };

        log!(
            TRACE_HTTP,
            "Got response (with {} bytes): {} from url: {} with status: {}",
            response.body.len(),
            String::from_utf8_lossy(&response.body),
            url,
            response.status
        );

        metrics::observe_retry_count(eth_method.clone(), retries);

        // JSON-RPC responses over HTTP should have a 2xx status code,
        // even if the contained JsonRpcResult is an error.
        // If the server is not available, it will sometimes (wrongly) return HTML that will fail parsing as JSON.
        let http_status_code = http_status_code(&response);
        if !is_successful_http_code(&http_status_code) {
            return Err(HttpOutcallError::InvalidHttpJsonRpcResponse {
                status: http_status_code,
                body: String::from_utf8_lossy(&response.body).to_string(),
                parsing_error: None,
            }
            .into());
        }

        let reply: JsonRpcReply<O> = serde_json::from_slice(&response.body).map_err(|e| {
            HttpOutcallError::InvalidHttpJsonRpcResponse {
                status: http_status_code,
                body: String::from_utf8_lossy(&response.body).to_string(),
                parsing_error: Some(e.to_string()),
            }
        })?;

        return reply.result.into();
    }
}

fn http_status_code(response: &HttpResponse) -> u16 {
    use num_traits::cast::ToPrimitive;
    // HTTP status code are always 3 decimal digits, hence at most 999.
    // See https://httpwg.org/specs/rfc9110.html#status.code.extensibility
    response.status.0.to_u16().expect("valid HTTP status code")
}

fn is_successful_http_code(status: &u16) -> bool {
    const OK: u16 = 200;
    const REDIRECTION: u16 = 300;
    (OK..REDIRECTION).contains(status)
}

fn sort_by_hash<T: Serialize + DeserializeOwned>(to_sort: &mut [T]) {
    use ic_crypto_sha3::Keccak256;
    to_sort.sort_by(|a, b| {
        let a_hash = Keccak256::hash(serde_json::to_vec(a).expect("BUG: failed to serialize"));
        let b_hash = Keccak256::hash(serde_json::to_vec(b).expect("BUG: failed to serialize"));
        a_hash.cmp(&b_hash)
    });
}

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
        fn observe_retry_count(&mut self, count: usize) {
            self.retry_buckets[count.min(MAX_EXPECTED_RETRIES)] += 1;
            self.retry_count += count as u64;
        }

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
        pub fn observe_retry_count(&mut self, method: String, count: usize) {
            self.retry_histogram_per_method
                .entry(method)
                .or_default()
                .observe_retry_count(count);
        }

        #[cfg(test)]
        pub fn count_retries_in_bucket(&self, method: &str, count: usize) -> u64 {
            match self.retry_histogram_per_method.get(method) {
                Some(histogram) => histogram.retry_buckets[count.min(MAX_EXPECTED_RETRIES)],
                None => 0,
            }
        }

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

    /// Record the retry count for the specified ETH RPC method.
    pub fn observe_retry_count(method: String, count: usize) {
        METRICS.with(|metrics| metrics.borrow_mut().observe_retry_count(method, count));
    }

    /// Encodes the metrics related to ETH RPC method calls.
    pub fn encode<W: std::io::Write>(encoder: &mut MetricsEncoder<W>) -> std::io::Result<()> {
        METRICS.with(|metrics| metrics.borrow().encode(encoder))
    }
}
