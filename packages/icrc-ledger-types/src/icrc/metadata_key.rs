//! Metadata key types for ICRC-1 ledger metadata.

use candid::{CandidType, Deserialize};
use serde::Serialize;
use std::fmt;

/// Error type for invalid metadata key format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataKeyError {
    /// The key does not contain a colon separator.
    MissingColon,
    /// The namespace (part before the first colon) contains a colon.
    ColonInNamespace,
    /// The namespace is empty.
    EmptyNamespace,
    /// The key part (after the colon) is empty.
    EmptyKey,
}

impl fmt::Display for MetadataKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetadataKeyError::MissingColon => {
                write!(f, "metadata key must contain a colon separator")
            }
            MetadataKeyError::ColonInNamespace => {
                write!(f, "namespace must not contain colons")
            }
            MetadataKeyError::EmptyNamespace => {
                write!(f, "namespace must not be empty")
            }
            MetadataKeyError::EmptyKey => {
                write!(f, "key part must not be empty")
            }
        }
    }
}

impl std::error::Error for MetadataKeyError {}

/// A validated metadata key following the ICRC-1 standard format `<namespace>:<key>`.
///
/// Metadata keys are arbitrary Unicode strings that must follow the pattern `<namespace>:<key>`,
/// where `<namespace>` is a string not containing colons. The namespace `icrc1` is reserved
/// for keys defined in the ICRC-1 standard.
///
/// For more information, see the
/// [documentation of Metadata in the ICRC-1 standard](https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1#metadata).
///
/// # Examples
///
/// ```
/// use icrc_ledger_types::icrc::metadata_key::MetadataKey;
///
/// // Valid keys
/// let key = MetadataKey::new("icrc1", "name").unwrap();
/// assert_eq!(key.namespace(), "icrc1");
/// assert_eq!(key.key(), "name");
/// assert_eq!(key.as_str(), "icrc1:name");
///
/// // Parse from string
/// let key = MetadataKey::parse("myapp:decimals").unwrap();
/// assert_eq!(key.namespace(), "myapp");
/// assert_eq!(key.key(), "decimals");
/// ```
#[derive(
    CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct MetadataKey(String);

impl MetadataKey {
    // ==================== ICRC-1 Standard Keys ====================

    /// The name of the token.
    /// When present, should be the same as the result of the icrc1_name query call.
    pub const ICRC1_NAME: &'static str = "icrc1:name";

    /// The token currency code (see ISO-4217).
    /// When present, should be the same as the result of the icrc1_symbol query call.
    pub const ICRC1_SYMBOL: &'static str = "icrc1:symbol";

    /// The number of decimals the token uses. For example, 8 means to divide the token amount by 108 to get its user representation.
    /// When present, should be the same as the result of the icrc1_decimals query call.
    pub const ICRC1_DECIMALS: &'static str = "icrc1:decimals";

    /// The default transfer fee.
    /// When present, should be the same as the result of the icrc1_fee query call.
    pub const ICRC1_FEE: &'static str = "icrc1:fee";

    /// The URL of the token logo. The value can contain the actual image if it's a Data URL.
    pub const ICRC1_LOGO: &'static str = "icrc1:logo";

    /// The maximum length of a memo in bytes.
    pub const ICRC1_MAX_MEMO_LENGTH: &'static str = "icrc1:max_memo_length";

    // ==================== ICRC-103 Keys ====================

    /// Whether allowance data is public or not.
    pub const ICRC103_PUBLIC_ALLOWANCES: &'static str = "icrc103:public_allowances";

    /// The maximum number of allowances the ledger will return in response to a query.
    pub const ICRC103_MAX_TAKE_VALUE: &'static str = "icrc103:max_take_value";

    // ==================== ICRC-106 Keys ====================

    /// The textual representation of the principal of the associated index canister.
    pub const ICRC106_INDEX_PRINCIPAL: &'static str = "icrc106:index_principal";

    /// Creates a new metadata key from namespace and key parts.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The namespace is empty
    /// - The namespace contains a colon
    /// - The key is empty
    pub fn new(namespace: &str, key: &str) -> Result<Self, MetadataKeyError> {
        if namespace.is_empty() {
            return Err(MetadataKeyError::EmptyNamespace);
        }
        if namespace.contains(':') {
            return Err(MetadataKeyError::ColonInNamespace);
        }
        if key.is_empty() {
            return Err(MetadataKeyError::EmptyKey);
        }
        Ok(Self(format!("{namespace}:{key}")))
    }

    /// Parses a metadata key from a string in the format `<namespace>:<key>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the string does not follow the required format.
    pub fn parse(s: &str) -> Result<Self, MetadataKeyError> {
        let colon_pos = s.find(':').ok_or(MetadataKeyError::MissingColon)?;
        let namespace = &s[..colon_pos];
        let key = &s[colon_pos + 1..];

        if namespace.is_empty() {
            return Err(MetadataKeyError::EmptyNamespace);
        }
        if key.is_empty() {
            return Err(MetadataKeyError::EmptyKey);
        }
        Ok(Self(s.to_string()))
    }

    /// Returns the namespace part of the key.
    pub fn namespace(&self) -> &str {
        self.0
            .find(':')
            .map(|pos| &self.0[..pos])
            .expect("BUG: MetadataKey should always contain a colon")
    }

    /// Returns the key part (after the namespace).
    pub fn key(&self) -> &str {
        self.0
            .find(':')
            .map(|pos| &self.0[pos + 1..])
            .expect("BUG: MetadataKey should always contain a colon")
    }

    /// Returns the full key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MetadataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for MetadataKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<MetadataKey> for String {
    fn from(key: MetadataKey) -> Self {
        key.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_key_new() {
        let key = MetadataKey::new("icrc1", "name").unwrap();
        assert_eq!(key.namespace(), "icrc1");
        assert_eq!(key.key(), "name");
        assert_eq!(key.as_str(), "icrc1:name");
    }

    #[test]
    fn test_metadata_key_parse() {
        let key = MetadataKey::parse("myapp:decimals").unwrap();
        assert_eq!(key.namespace(), "myapp");
        assert_eq!(key.key(), "decimals");
    }

    #[test]
    fn test_metadata_key_with_colons_in_value() {
        // Key part can contain colons
        let key = MetadataKey::parse("myapp:some:complex:key").unwrap();
        assert_eq!(key.namespace(), "myapp");
        assert_eq!(key.key(), "some:complex:key");
    }

    #[test]
    fn test_metadata_key_empty_namespace() {
        assert_eq!(
            MetadataKey::new("", "name"),
            Err(MetadataKeyError::EmptyNamespace)
        );
        assert_eq!(
            MetadataKey::parse(":name"),
            Err(MetadataKeyError::EmptyNamespace)
        );
    }

    #[test]
    fn test_metadata_key_empty_key() {
        assert_eq!(
            MetadataKey::new("icrc1", ""),
            Err(MetadataKeyError::EmptyKey)
        );
        assert_eq!(
            MetadataKey::parse("icrc1:"),
            Err(MetadataKeyError::EmptyKey)
        );
    }

    #[test]
    fn test_metadata_key_missing_colon() {
        assert_eq!(
            MetadataKey::parse("nonamespace"),
            Err(MetadataKeyError::MissingColon)
        );
    }

    #[test]
    fn test_metadata_key_colon_in_namespace() {
        assert_eq!(
            MetadataKey::new("bad:namespace", "key"),
            Err(MetadataKeyError::ColonInNamespace)
        );
    }

    #[test]
    fn test_metadata_key_display() {
        let key = MetadataKey::new("icrc1", "symbol").unwrap();
        assert_eq!(format!("{}", key), "icrc1:symbol");
    }

    #[test]
    fn test_metadata_key_into_string() {
        let key = MetadataKey::new("icrc1", "decimals").unwrap();
        let s: String = key.into();
        assert_eq!(s, "icrc1:decimals");
    }
}
