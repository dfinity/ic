/// Sensitive data held as a Vec of `u8`s.
use core::fmt::{self, Debug};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Sensitive data held as a Vec of `u8`s.
///
/// This type is very similar to the SecretVec type, also in this
/// crate, with the main difference being that its serialization and
/// deserialization are as compact as (and identical to) just encoding
/// a bytestring directly.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    secret: Vec<u8>,
}

impl SecretBytes {
    /// Constructs a `SecretBytes` from the provided `secret`
    pub fn new(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    /// Constructs a `SecretBytes` from the provided (non-owned) `secret`.
    ///
    /// Note: It is the responsibility of the caller to clear the memory
    /// used by `secret`.
    pub fn new_from_unowned(secret: &[u8]) -> Self {
        Self::new(secret.to_vec())
    }

    /// Provides read-only access to the secret vec.
    pub fn expose_secret(&self) -> &[u8] {
        &self.secret
    }
}

impl Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED SecretBytes of length {}", self.secret.len())
    }
}

impl serde::Serialize for SecretBytes {
    fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.secret)
    }
}

impl<'a> serde::Deserialize<'a> for SecretBytes {
    fn deserialize<D: serde::de::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = SecretBytes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "a bytestring")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(SecretBytes::new_from_unowned(v))
            }
        }

        deserializer.deserialize_bytes(Visitor)
    }
}
