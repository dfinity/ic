//! This module contains definitions for communicating with an Ethereum API using the [JSON RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/)
//! interface.

use evm_rpc_types::{Hex32, HttpOutcallError, LegacyRejectionCode};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};

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
        write!(f, "{self:x}")
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:x}")
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
            .map_err(|e| format!("failed to decode hash from hex: {e}"))?;
        Ok(Self(bytes))
    }
}

impl From<Hash> for evm_rpc_types::Hex32 {
    fn from(hash: Hash) -> Self {
        evm_rpc_types::Hex32::from(hash.0)
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
            code == &LegacyRejectionCode::SysFatal
                && (message.contains("size limit") || message.contains("length limit"))
        }
        _ => false,
    }
}
