//! Metadata key types for ICRC-1 ledger metadata.

use candid::{CandidType, Deserialize};
use serde::Serialize;
use std::borrow::Borrow;
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
/// let key = MetadataKey::parse("myapp:version").unwrap();
/// assert_eq!(key.namespace(), "myapp");
/// assert_eq!(key.key(), "version");
/// ```
#[derive(
    CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct MetadataKey(String);

impl MetadataKey {
    /// The reserved namespace for ICRC-1 standard keys.
    pub const ICRC1_NAMESPACE: &'static str = "icrc1";

    // ==================== ICRC-1 Standard Keys ====================

    /// The human-readable name of the token (e.g., "Internet Computer Protocol").
    pub const ICRC1_NAME: &'static str = "icrc1:name";

    /// The ticker symbol of the token (e.g., "ICP").
    pub const ICRC1_SYMBOL: &'static str = "icrc1:symbol";

    /// The number of decimals the token uses.
    pub const ICRC1_DECIMALS: &'static str = "icrc1:decimals";

    /// The default transfer fee.
    pub const ICRC1_FEE: &'static str = "icrc1:fee";

    /// A logo for the token (typically a data URI with an image).
    pub const ICRC1_LOGO: &'static str = "icrc1:logo";

    /// The maximum length of a memo in bytes.
    pub const ICRC1_MAX_MEMO_LENGTH: &'static str = "icrc1:max_memo_length";

    // ==================== ICRC-103 Keys ====================

    /// Whether public allowances are enabled.
    pub const ICRC103_PUBLIC_ALLOWANCES: &'static str = "icrc103:public_allowances";

    /// The maximum value for the take operation.
    pub const ICRC103_MAX_TAKE_VALUE: &'static str = "icrc103:max_take_value";

    // ==================== ICRC-106 Keys ====================

    /// The principal of the index canister associated with this ledger.
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
        // Namespace is already validated by taking everything before the first colon
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

    /// Returns whether this key uses the reserved `icrc1` namespace.
    pub fn is_icrc1(&self) -> bool {
        self.namespace() == Self::ICRC1_NAMESPACE
    }

    /// Consumes the key and returns the inner string.
    pub fn into_string(self) -> String {
        self.0
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

impl Borrow<str> for MetadataKey {
    fn borrow(&self) -> &str {
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
        assert!(key.is_icrc1());
    }

    #[test]
    fn test_metadata_key_parse() {
        let key = MetadataKey::parse("myapp:version").unwrap();
        assert_eq!(key.namespace(), "myapp");
        assert_eq!(key.key(), "version");
        assert!(!key.is_icrc1());
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
