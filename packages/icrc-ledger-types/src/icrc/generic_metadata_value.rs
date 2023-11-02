use candid::{CandidType, Deserialize, Int, Nat};
use serde_bytes::ByteBuf;

/// Variant type for the `metadata` endpoint values.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum MetadataValue {
    Nat(Nat),
    Int(Int),
    Text(String),
    Blob(ByteBuf),
}

impl MetadataValue {
    pub fn entry(key: impl ToString, val: impl Into<MetadataValue>) -> (String, Self) {
        (key.to_string(), val.into())
    }
}

impl From<i64> for MetadataValue {
    fn from(n: i64) -> Self {
        MetadataValue::Int(Int::from(n))
    }
}

impl From<i128> for MetadataValue {
    fn from(n: i128) -> Self {
        MetadataValue::Int(Int::from(n))
    }
}

impl From<u64> for MetadataValue {
    fn from(n: u64) -> Self {
        MetadataValue::Nat(Nat::from(n))
    }
}

impl From<u128> for MetadataValue {
    fn from(n: u128) -> Self {
        MetadataValue::Nat(Nat::from(n))
    }
}

impl From<Nat> for MetadataValue {
    fn from(n: Nat) -> Self {
        MetadataValue::Nat(n)
    }
}

impl From<String> for MetadataValue {
    fn from(s: String) -> Self {
        MetadataValue::Text(s)
    }
}

impl<'a> From<&'a str> for MetadataValue {
    fn from(s: &'a str) -> Self {
        MetadataValue::Text(s.to_string())
    }
}

impl From<Vec<u8>> for MetadataValue {
    fn from(bytes: Vec<u8>) -> MetadataValue {
        MetadataValue::Blob(ByteBuf::from(bytes))
    }
}

impl<'a> From<&'a [u8]> for MetadataValue {
    fn from(bytes: &'a [u8]) -> MetadataValue {
        MetadataValue::Blob(ByteBuf::from(bytes.to_vec()))
    }
}
