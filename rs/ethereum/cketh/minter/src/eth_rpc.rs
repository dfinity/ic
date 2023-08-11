//! This module contains definitions for communicating with an Ethereum API using the [JSON RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/)
//! interface.

use crate::address::Address;
use crate::numeric::Wei;
use candid::{candid_method, CandidType, Principal};
use ethnum::u256;
use ic_cdk::api::call::{call_with_payment128, CallResult};
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext,
};
use ic_cdk_macros::query;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
use std::ops::Add;

pub type Quantity = u256;

pub fn into_nat(quantity: Quantity) -> candid::Nat {
    use num_bigint::BigUint;
    candid::Nat::from(BigUint::from_bytes_be(&quantity.to_be_bytes()))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Data(#[serde(with = "crate::serde_data")] pub Vec<u8>);

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct FixedSizeData(#[serde(with = "crate::serde_data")] pub [u8; 32]);

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

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[serde(transparent)]
pub struct Hash(#[serde(with = "crate::serde_data")] pub [u8; 32]);

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

#[derive(Debug, Clone, Deserialize)]
pub struct BlockResponse {
    pub number: Quantity,
    pub hash: Data,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    /// The hash of the block containing the transaction.
    /// None if the transaction is pending.
    pub block_hash: Option<Hash>,

    /// The number of the block containing the transaction.
    /// None if the transaction is pending.
    pub block_number: Option<BlockNumber>,

    /// Gas provided by the sender.
    pub gas: Quantity,

    /// Gas price provided by the sender in Wei.
    pub gas_price: Quantity,

    /// The sender address.
    pub from: Address,

    /// The transaction hash.
    pub hash: Hash,

    /// The data send along with the transaction.
    pub input: Data,

    /// The number of transactions made by the sender prior to this one.
    pub nonce: Quantity,

    /// The receiver address.
    /// None if it's a contract creation transaction.
    pub to: Option<Address>,

    /// Integer of the transactions index position in the block.
    /// None if the transaction is pending.
    pub transaction_index: Option<Quantity>,

    /// Value transferred in Wei.
    pub value: Quantity,
}

impl Transaction {
    pub fn is_confirmed(&self) -> bool {
        self.block_hash.is_some() && self.block_number.is_some() && self.transaction_index.is_some()
    }
}

/// Block tags.
/// See https://ethereum.org/en/developers/docs/apis/json-rpc/#default-block
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlockTag {
    /// The earliest/genesis block.
    Earliest,
    /// The latest mined block.
    #[default]
    Latest,
    /// The latest safe head block.
    /// See
    /// https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels.
    Safe,
    /// The latest finalized block.
    /// See
    /// https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels.
    Finalized,
    /// The pending state.
    Pending,
}

/// The block specification indicating which block to query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BlockSpec {
    /// Query the block with the specified index.
    Number(Quantity),
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
            let quantity = Quantity::from_str_hex(s)
                .map_err(|e| format!("failed to parse block number '{s}': {e}"))?;
            return Ok(BlockSpec::Number(quantity));
        }
        Ok(BlockSpec::Tag(match s {
            "earliest" => BlockTag::Earliest,
            "latest" => BlockTag::Latest,
            "safe" => BlockTag::Safe,
            "finalized" => BlockTag::Finalized,
            "pending" => BlockTag::Pending,
            _ => return Err(format!("unknown block tag '{s}'")),
        }))
    }
}

/// Parameters of the [`eth_getLogs`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getlogs) call.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub topics: Vec<FixedSizeData>,
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
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
    // Integer of the transactions position withing the block the log was created from.
    // None if the log is pending.
    pub transaction_index: Option<Quantity>,
    /// 32 Bytes - hash of the block in which this log appeared.
    /// None if the block is pending.
    pub block_hash: Option<Hash>,
    /// Integer of the log index position in the block.
    /// None if the log is pending.
    pub log_index: Option<Quantity>,
    /// "true" when the log was removed due to a chain reorganization.
    /// "false" if it's a valid log.
    #[serde(default)]
    pub removed: bool,
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

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FeeHistory {
    /// Lowest number block of the returned range.
    pub oldest_block: BlockNumber,
    /// An array of block base fees per gas.
    /// This includes the next block after the newest of the returned range,
    /// because this value can be derived from the newest block.
    /// Zeroes are returned for pre-EIP-1559 blocks.
    pub base_fee_per_gas: Vec<Wei>,
    /// A two-dimensional array of effective priority fees per gas at the requested block percentiles.
    pub reward: Vec<Vec<Wei>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(transparent)]
pub struct BlockNumber(pub Quantity);

impl From<BlockNumber> for BlockSpec {
    fn from(value: BlockNumber) -> Self {
        BlockSpec::Number(value.0)
    }
}

impl BlockNumber {
    pub fn new(value: u128) -> Self {
        Self(Quantity::from(value))
    }

    pub fn as_f64(&self) -> f64 {
        self.0.as_f64()
    }
}

impl Add<u128> for BlockNumber {
    type Output = BlockNumber;

    fn add(self, rhs: u128) -> Self::Output {
        BlockNumber(self.0 + rhs)
    }
}

impl From<BlockNumber> for candid::Nat {
    fn from(value: BlockNumber) -> Self {
        into_nat(value.0)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    ///The block number. `None` when its pending block.
    pub number: BlockNumber,
    /// Base fee value of this block
    pub base_fee_per_gas: Wei,
}

/// An envelope for all JSON-RPC requests.
#[derive(Serialize)]
struct JsonRpcRequest<T> {
    jsonrpc: &'static str,
    method: String,
    id: u32,
    params: T,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonRpcReply<T> {
    pub id: u32,
    pub jsonrpc: String,
    #[serde(flatten)]
    pub result: JsonRpcResult<T>,
}

/// An envelope for all JSON-RPC replies.
#[derive(Debug, PartialEq, Eq, Deserialize, CandidType)]
#[serde(rename_all = "camelCase")]
pub enum JsonRpcResult<T> {
    Result(T),
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

#[query]
#[candid_method(query)]
fn cleanup_response(mut args: TransformArgs) -> HttpResponse {
    args.response.headers.clear();
    args.response
}

pub const BLOCK_PI_RPC_PROVIDER_URL: &str =
    "https://ethereum-sepolia.blockpi.network/v1/rpc/public";
/// Calls a JSON-RPC method on an Ethereum node at the specified URL.
pub async fn call<I: Serialize, O: DeserializeOwned>(
    url: &'static str,
    method: impl Into<String>,
    params: I,
) -> CallResult<JsonRpcResult<O>> {
    const KIB: u64 = 1024;
    let payload = serde_json::to_string(&JsonRpcRequest {
        jsonrpc: "2.0",
        params,
        method: method.into(),
        id: 1,
    })
    .unwrap();
    ic_cdk::println!("REQUEST: {payload}");
    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        max_response_bytes: Some(10 * KIB),
        method: HttpMethod::POST,
        headers: vec![HttpHeader {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }],
        body: Some(payload.into_bytes()),
        transform: Some(TransformContext::new(cleanup_response, vec![])),
    };

    // Details of the values used in the following lines can be found here:
    // https://internetcomputer.org/docs/current/developer-docs/production/computation-and-storage-costs
    const HTTP_MAX_SIZE: u128 = 2 * 1024 * 1024;
    let base_cycles = 400_000_000u128 + 100_000u128 * (2 * HTTP_MAX_SIZE);

    const BASE_SUBNET_SIZE: u128 = 13;
    const SUBNET_SIZE: u128 = 34;
    let cycles = base_cycles * SUBNET_SIZE / BASE_SUBNET_SIZE;
    let (response,): (HttpResponse,) = call_with_payment128(
        Principal::management_canister(),
        "http_request",
        (request,),
        cycles,
    )
    .await?;

    ic_cdk::println!("RESPONSE: {}", String::from_utf8_lossy(&response.body));

    let reply: JsonRpcReply<O> = serde_json::from_slice(&response.body).unwrap_or_else(|e| {
        panic!(
            "failed to decode response {}: {}",
            String::from_utf8_lossy(&response.body),
            e
        )
    });

    Ok(reply.result)
}
