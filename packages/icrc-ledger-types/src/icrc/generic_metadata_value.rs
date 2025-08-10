use candid::{CandidType, Deserialize, Int, Nat};
use serde::Serialize;
use serde_bytes::ByteBuf;

/// Variant type for the `icrc1_metadata` endpoint values. The corresponding metadata keys are
/// arbitrary Unicode strings and must follow the pattern `<namespace>:<key>`, where `<namespace>`
/// is a string not containing colons. The namespace `icrc1` is reserved for keys defined in the
/// ICRC-1 standard. For more information, see the
/// [documentation of Metadata in the ICRC-1 standard](https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1#metadata).
/// Note that the `MetadataValue` type is a subset of the [`icrc_ledger_types::icrc::generic_value::ICRC3Value`] type.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum MetadataValue {
    Nat(Nat),
    Int(Int),
    Text(String),
    Blob(ByteBuf),
}

impl MetadataValue {
    /// Create a `(String, MetadataValue)` tuple for use in metadata maps.
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
