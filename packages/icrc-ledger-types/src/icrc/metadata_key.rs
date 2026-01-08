//! Metadata key types for ICRC-1 ledger metadata.
//!
//! This module provides a type-safe metadata key implementation using a type-state pattern.
//! Metadata keys can be in one of two states:
//!
//! - [`Unchecked`]: The key has not been validated. Keys in this state are obtained from
//!   deserialization or by calling [`MetadataKey::from_str_unchecked`].
//! - [`Checked`]: The key has been validated to follow the `<namespace>:<key>` format.
//!   Keys in this state are obtained by parsing/constructing validated keys or by calling
//!   [`require_valid`](MetadataKey<Unchecked>::require_valid) on an unchecked key.
//!
//! # Examples
//!
//! ```
//! use icrc_ledger_types::icrc::metadata_key::{MetadataKey, Unchecked};
//!
//! // Parsing always gives a checked key
//! let key = MetadataKey::parse("icrc1:name").unwrap();
//! assert_eq!(key.namespace(), "icrc1");
//! assert_eq!(key.key(), "name");
//!
//! // Deserializing gives an unchecked key that needs validation
//! let unchecked: MetadataKey<Unchecked> = serde_json::from_str("\"icrc1:name\"").unwrap();
//! let checked = unchecked.require_valid().unwrap();
//! assert_eq!(checked.namespace(), "icrc1");
//! ```

use candid::CandidType;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::marker::PhantomData;

/// Marker type indicating a metadata key has been validated.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Checked {}

/// Marker type indicating a metadata key has not been validated.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unchecked {}

/// Sealed trait for validation state markers.
mod private {
    pub trait Sealed {}
    impl Sealed for super::Checked {}
    impl Sealed for super::Unchecked {}
}

/// Trait for metadata key validation state markers.
pub trait ValidationState: private::Sealed + Clone {}
impl ValidationState for Checked {}
impl ValidationState for Unchecked {}

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
/// The type parameter `V` indicates the validation state:
/// - [`Checked`]: The key has been validated to follow the correct format.
/// - [`Unchecked`]: The key may or may not follow the correct format.
///
/// For more information, see the
/// [documentation of Metadata in the ICRC-1 standard](https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1#metadata).
///
/// # Examples
///
/// ## Creating validated keys
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
///
/// ## Validating unchecked keys
///
/// ```
/// use icrc_ledger_types::icrc::metadata_key::{MetadataKey, Unchecked};
///
/// // Deserializing gives an unchecked key
/// let unchecked: MetadataKey<Unchecked> = serde_json::from_str("\"icrc1:name\"").unwrap();
///
/// // Validate to get a checked key
/// let checked = unchecked.require_valid().unwrap();
/// assert_eq!(checked.namespace(), "icrc1");
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetadataKey<V: ValidationState = Checked>(String, PhantomData<V>);

// ==================== Standard Key Constants ====================

impl MetadataKey<Checked> {
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
}

// ==================== Methods for all validation states ====================

impl<V: ValidationState> MetadataKey<V> {
    /// Returns the full key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if this key follows the valid `<namespace>:<key>` format.
    pub fn is_valid(&self) -> bool {
        validate_key_format(&self.0).is_ok()
    }

    /// Converts this key to an unchecked key.
    ///
    /// This is a no-op that just changes the type marker.
    pub fn into_unchecked(self) -> MetadataKey<Unchecked> {
        MetadataKey(self.0, PhantomData)
    }
}

// ==================== Methods for Checked keys ====================

impl MetadataKey<Checked> {
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
        Ok(Self(format!("{namespace}:{key}"), PhantomData))
    }

    /// Parses a metadata key from a string in the format `<namespace>:<key>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the string does not follow the required format.
    pub fn parse(s: &str) -> Result<Self, MetadataKeyError> {
        validate_key_format(s)?;
        Ok(Self(s.to_string(), PhantomData))
    }

    /// Returns the namespace part of the key.
    pub fn namespace(&self) -> &str {
        self.0
            .find(':')
            .map(|pos| &self.0[..pos])
            .expect("BUG: Checked MetadataKey should always contain a colon")
    }

    /// Returns the key part (after the namespace).
    pub fn key(&self) -> &str {
        self.0
            .find(':')
            .map(|pos| &self.0[pos + 1..])
            .expect("BUG: Checked MetadataKey should always contain a colon")
    }
}

// ==================== Methods for Unchecked keys ====================

impl MetadataKey<Unchecked> {
    /// Creates an unchecked metadata key from any string.
    ///
    /// This does not validate the format. Use [`require_valid`](Self::require_valid) to validate.
    pub fn from_str_unchecked(s: impl Into<String>) -> Self {
        Self(s.into(), PhantomData)
    }

    /// Validates this key and converts it to a checked key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not follow the `<namespace>:<key>` format.
    pub fn require_valid(self) -> Result<MetadataKey<Checked>, MetadataKeyError> {
        validate_key_format(&self.0)?;
        Ok(MetadataKey(self.0, PhantomData))
    }

    /// Converts this key to a checked key without validation.
    ///
    /// # Safety
    ///
    /// This is safe to call, but using the resulting key's `namespace()` or `key()` methods
    /// will panic if the key does not follow the `<namespace>:<key>` format.
    ///
    /// This is intended for backwards compatibility with ledgers that may have stored
    /// invalid metadata keys.
    pub fn assume_checked(self) -> MetadataKey<Checked> {
        MetadataKey(self.0, PhantomData)
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

impl fmt::Debug for MetadataKey<Checked> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for MetadataKey<Unchecked> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetadataKey<Unchecked>({})", self.0)
    }
}

impl fmt::Display for MetadataKey<Checked> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<V: ValidationState> AsRef<str> for MetadataKey<V> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<V: ValidationState> From<MetadataKey<V>> for String {
    fn from(key: MetadataKey<V>) -> Self {
        key.0
    }
}

// ==================== Serialization ====================

// Serialize works for both Checked and Unchecked
impl<V: ValidationState> Serialize for MetadataKey<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

// Deserialize for Unchecked keys - used for external input (Candid args)
impl<'de> Deserialize<'de> for MetadataKey<Unchecked> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(s, PhantomData))
    }
}

// Deserialize for Checked keys - used for stable storage where keys were previously validated.
// This assumes the stored data is valid. For legacy ledgers that may have stored invalid keys,
// this will still deserialize successfully but the key may not actually be valid.
impl<'de> Deserialize<'de> for MetadataKey<Checked> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(s, PhantomData))
    }
}

// CandidType implementation - uses the same wire format for both
impl<V: ValidationState> CandidType for MetadataKey<V> {
    fn _ty() -> candid::types::Type {
        String::_ty()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        self.0.idl_serialize(serializer)
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
    fn test_metadata_key_debug() {
        let checked = MetadataKey::parse("icrc1:name").unwrap();
        assert_eq!(format!("{:?}", checked), "icrc1:name");

        let unchecked = MetadataKey::from_str_unchecked("icrc1:name");
        assert_eq!(
            format!("{:?}", unchecked),
            "MetadataKey<Unchecked>(icrc1:name)"
        );
    }

    #[test]
    fn test_metadata_key_into_string() {
        let key = MetadataKey::new("icrc1", "decimals").unwrap();
        let s: String = key.into();
        assert_eq!(s, "icrc1:decimals");
    }

    #[test]
    fn test_metadata_key_deserialize_valid() {
        let json = "\"icrc1:name\"";
        let key: MetadataKey<Unchecked> = serde_json::from_str(json).unwrap();
        assert!(key.is_valid());

        let checked = key.require_valid().unwrap();
        assert_eq!(checked.namespace(), "icrc1");
        assert_eq!(checked.key(), "name");
    }

    #[test]
    fn test_metadata_key_deserialize_invalid() {
        let json = "\"invalidkey\"";
        let key: MetadataKey<Unchecked> = serde_json::from_str(json).unwrap();
        assert!(!key.is_valid());
        assert_eq!(key.as_str(), "invalidkey");

        // require_valid should fail
        assert!(key.require_valid().is_err());
    }

    #[test]
    fn test_metadata_key_assume_checked() {
        let unchecked = MetadataKey::from_str_unchecked("icrc1:name");
        let checked = unchecked.assume_checked();
        assert_eq!(checked.namespace(), "icrc1");
        assert_eq!(checked.key(), "name");
    }

    #[test]
    fn test_metadata_key_into_unchecked() {
        let checked = MetadataKey::parse("icrc1:name").unwrap();
        let unchecked = checked.into_unchecked();
        assert_eq!(unchecked.as_str(), "icrc1:name");
    }

    #[test]
    fn test_metadata_key_is_valid() {
        assert!(MetadataKey::new("icrc1", "name").unwrap().is_valid());
        assert!(MetadataKey::parse("app:key").unwrap().is_valid());

        let invalid = MetadataKey::from_str_unchecked("nocolon");
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_metadata_key_serialize() {
        let checked = MetadataKey::parse("icrc1:name").unwrap();
        let json = serde_json::to_string(&checked).unwrap();
        assert_eq!(json, "\"icrc1:name\"");

        let unchecked = MetadataKey::from_str_unchecked("icrc1:name");
        let json = serde_json::to_string(&unchecked).unwrap();
        assert_eq!(json, "\"icrc1:name\"");
    }
}
