//! This module contains definitions for communicating with an Ethereum API using the [JSON RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/)
//! interface.

use ethnum;
use evm_rpc_client::{Hex32, HttpOutcallError};
use ic_cdk::api::call::RejectionCode;
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
    Single(Hex32),
    Multiple(Vec<Hex32>),
}

impl From<Vec<Hex32>> for Topic {
    fn from(data: Vec<Hex32>) -> Self {
        Topic::Multiple(data)
    }
}

pub fn is_response_too_large(response: &HttpOutcallError) -> bool {
    match response {
        HttpOutcallError::IcError { code, message } => {
            code == &RejectionCode::SysFatal
                && (message.contains("size limit") || message.contains("length limit"))
        }
        _ => false,
    }
}
