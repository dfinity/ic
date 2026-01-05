use candid::{CandidType, Deserialize, Int, Nat};
use serde::Serialize;
use serde_bytes::ByteBuf;

pub use crate::icrc::metadata_key::{MetadataKey, MetadataKeyError};

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
    /// Create a `(MetadataKey, MetadataValue)` tuple for use in metadata maps.
    ///
    /// The key must be a valid metadata key in the format `<namespace>:<key>`.
    /// This is typically used with the predefined constants like `MetadataKey::ICRC1_NAME`.
    ///
    /// # Panics
    ///
    /// Panics if the key is not a valid metadata key format.
    ///
    /// # Example
    ///
    /// ```
    /// use icrc_ledger_types::icrc::generic_metadata_value::{MetadataKey, MetadataValue};
    ///
    /// let entry = MetadataValue::entry(MetadataKey::ICRC1_NAME, "My Token");
    /// assert_eq!(entry.0.as_str(), "icrc1:name");
    /// ```
    pub fn entry(key: &str, val: impl Into<MetadataValue>) -> (MetadataKey, Self) {
        let metadata_key =
            MetadataKey::parse(key).unwrap_or_else(|e| panic!("invalid metadata key '{key}': {e}"));
        (metadata_key, val.into())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_value_entry() {
        let entry = MetadataValue::entry(MetadataKey::ICRC1_NAME, "My Token");
        assert_eq!(entry.0.as_str(), "icrc1:name");
        assert_eq!(entry.1, MetadataValue::Text("My Token".to_string()));
    }
}
