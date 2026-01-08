//! Metadata key types for ICRC-1 ledger metadata.
//!
//! This module provides a validated metadata key type for ICRC-1 ledger metadata.
//! Metadata keys should follow the pattern `<namespace>:<key>`, where `<namespace>`
//! is a string not containing colons.
//!
//! # Examples
//!
//! ```
//! use icrc_ledger_types::icrc::metadata_key::MetadataKey;
//!
//! // Parse a key (validates the format)
//! let key = MetadataKey::parse("icrc1:name").unwrap();
//! assert_eq!(key.namespace(), "icrc1");
//! assert_eq!(key.key(), "name");
//!
//! // Create from parts (validates the format)
//! let key = MetadataKey::new("myapp", "setting").unwrap();
//! assert_eq!(key.as_str(), "myapp:setting");
//! ```

use candid::CandidType;
use serde::{Deserialize, Serialize};
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

/// A metadata key for ICRC-1 ledger metadata.
///
/// Metadata keys should follow the pattern `<namespace>:<key>`, where `<namespace>` is a string
/// not containing colons. The namespace `icrc1` is reserved for keys defined in the ICRC-1 standard.
///
/// For more information, see the
/// [documentation of Metadata in the ICRC-1 standard](https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1#metadata).
///
/// # Examples
///
/// ```
/// use icrc_ledger_types::icrc::metadata_key::MetadataKey;
///
/// // Using parse (validates the format)
/// let key = MetadataKey::parse("icrc1:name").unwrap();
/// assert_eq!(key.namespace(), "icrc1");
/// assert_eq!(key.key(), "name");
///
/// // Using new (validates the format)
/// let key = MetadataKey::new("icrc1", "symbol").unwrap();
/// assert_eq!(key.as_str(), "icrc1:symbol");
/// ```
#[derive(
    CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct MetadataKey(String);

impl MetadataKey {
    // ==================== Standard Key Constants ====================

    /// The name of the token.
    /// When present, should be the same as the result of the icrc1_name query call.
    pub const ICRC1_NAME: &'static str = "icrc1:name";

    /// The token currency code (see ISO-4217).
    /// When present, should be the same as the result of the icrc1_symbol query call.
    pub const ICRC1_SYMBOL: &'static str = "icrc1:symbol";

    /// The number of decimals the token uses. For example, 8 means to divide the token amount by 10^8 to get its user representation.
    /// When present, should be the same as the result of the icrc1_decimals query call.
    pub const ICRC1_DECIMALS: &'static str = "icrc1:decimals";

    /// The default transfer fee.
    /// When present, should be the same as the result of the icrc1_fee query call.
    pub const ICRC1_FEE: &'static str = "icrc1:fee";

    /// The URL of the token logo. The value can contain the actual image if it's a Data URL.
    pub const ICRC1_LOGO: &'static str = "icrc1:logo";

    /// The maximum length of a memo in bytes.
    pub const ICRC1_MAX_MEMO_LENGTH: &'static str = "icrc1:max_memo_length";

    /// Whether allowance data is public or not.
    pub const ICRC103_PUBLIC_ALLOWANCES: &'static str = "icrc103:public_allowances";

    /// The maximum number of allowances the ledger will return in response to a query.
    pub const ICRC103_MAX_TAKE_VALUE: &'static str = "icrc103:max_take_value";

    /// The textual representation of the principal of the associated index canister.
    pub const ICRC106_INDEX_PRINCIPAL: &'static str = "icrc106:index_principal";

    // ==================== Constructors ====================

    /// Creates a new validated metadata key from namespace and key parts.
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
        validate_key_format(s)?;
        Ok(Self(s.to_string()))
    }

    /// Creates a metadata key from a string without validation.
    ///
    /// # Warning
    ///
    /// This bypasses validation. Using `namespace()` or `key()` on an invalid key will panic.
    /// This is intended for backwards compatibility with ledgers that may have stored
    /// invalid metadata keys.
    pub fn unchecked_from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    // ==================== Accessors ====================

    /// Returns the full key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if this key follows the valid `<namespace>:<key>` format.
    pub fn is_valid(&self) -> bool {
        validate_key_format(&self.0).is_ok()
    }

    /// Returns the namespace part of the key.
    ///
    /// # Panics
    ///
    /// Panics if the key does not contain a colon (i.e., was created with `unchecked_from_string`
    /// with an invalid format).
    pub fn namespace(&self) -> &str {
        self.0
            .find(':')
            .map(|pos| &self.0[..pos])
            .expect("BUG: MetadataKey should contain a colon; was this created with unchecked_from_string?")
    }

    /// Returns the key part (after the namespace).
    ///
    /// # Panics
    ///
    /// Panics if the key does not contain a colon (i.e., was created with `unchecked_from_string`
    /// with an invalid format).
    pub fn key(&self) -> &str {
        self.0
            .find(':')
            .map(|pos| &self.0[pos + 1..])
            .expect("BUG: MetadataKey should contain a colon; was this created with unchecked_from_string?")
    }
}

// ==================== Helper function ====================

fn validate_key_format(s: &str) -> Result<(), MetadataKeyError> {
    let colon_pos = s.find(':').ok_or(MetadataKeyError::MissingColon)?;
    let namespace = &s[..colon_pos];
    let key = &s[colon_pos + 1..];

    if namespace.is_empty() {
        return Err(MetadataKeyError::EmptyNamespace);
    }
    if key.is_empty() {
        return Err(MetadataKeyError::EmptyKey);
    }
    Ok(())
}

// ==================== Trait implementations ====================

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

    #[test]
    fn test_metadata_key_is_valid() {
        assert!(MetadataKey::new("icrc1", "name").unwrap().is_valid());
        assert!(MetadataKey::parse("app:key").unwrap().is_valid());

        let invalid = MetadataKey::unchecked_from_string("nocolon");
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_metadata_key_unchecked_from_string() {
        let key = MetadataKey::unchecked_from_string("icrc1:name");
        assert_eq!(key.namespace(), "icrc1");
        assert_eq!(key.key(), "name");
        assert!(key.is_valid());
    }

    #[test]
    fn test_metadata_key_serialize_deserialize() {
        let key = MetadataKey::parse("icrc1:name").unwrap();
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, "\"icrc1:name\"");

        let deserialized: MetadataKey = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, key);
    }
}
