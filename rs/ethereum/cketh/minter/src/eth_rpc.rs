//! This module contains definitions for communicating with an Ethereum API using the [JSON RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/)
//! interface.

use crate::numeric::{BlockNumber, LogIndex};
use candid::CandidType;
use ethnum;
use evm_rpc_client::{
    HttpOutcallError as EvmHttpOutcallError,
    SendRawTransactionStatus as EvmSendRawTransactionStatus,
};
use ic_cdk::api::call::RejectionCode;
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

/// A topic is either a 32 Bytes DATA, or an array of 32 Bytes DATA with "or" options.
#[derive(Clone, Debug, PartialEq, Eq)]
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
