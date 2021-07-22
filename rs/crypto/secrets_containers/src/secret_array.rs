/// Sensitive data held as an array of `u8`s.
///
/// To keep the sensitive data from not getting cleaned due to unintended
/// copies, the array is allocated on the heap as a `Box<u8>`.
use core::fmt::{self, Debug};
use serde::de::Error;
use zeroize::Zeroize;

/// Sensitive data held as an array of `u8`s.
#[derive(Clone, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct SecretArray<const N: usize> {
    inner_secret: Box<[u8; N]>,
}

impl<const N: usize> SecretArray<N> {
    /// Constructs a `SecretArray` from the provided `secret`, and clears the
    /// memory used by `secret`.
    pub fn new_and_zeroize_argument(secret: &mut [u8; N]) -> Self {
        let mut ret = Self {
            inner_secret: Box::new([0_u8; N]),
        };
        ret.inner_secret.copy_from_slice(&secret[..]);
        secret.zeroize();
        ret
    }

    /// Constructs a `SecretArray` from the provided (non-owned) `secret`.
    ///
    /// Note: It is the responsibility of the caller to clear the memory
    /// used by `secret`.
    pub fn new_and_dont_zeroize_argument(secret: &[u8; N]) -> Self {
        let mut ret = Self {
            inner_secret: Box::new([0_u8; N]),
        };
        ret.inner_secret.copy_from_slice(&secret[..]);
        ret
    }

    /// Provides read-only access to the secret array.
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.inner_secret
    }
}

impl<const N: usize> Debug for SecretArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED SecretArray<{}>", N)
    }
}

impl<const N: usize> serde::Serialize for SecretArray<N> {
    fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.expose_secret())
    }
}

struct SecretArrayVisitor<const N: usize>;

impl<'de, const N: usize> serde::de::Visitor<'de> for SecretArrayVisitor<N> {
    type Value = SecretArray<N>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "a byte array of length {}", N)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if v.len() == N {
            let mut ret = SecretArray {
                inner_secret: Box::new([0_u8; N]),
            };
            ret.inner_secret.copy_from_slice(v);
            Ok(ret)
        } else {
            Err(Error::invalid_length(v.len(), &self))
        }
    }
}

impl<'a, const N: usize> serde::Deserialize<'a> for SecretArray<N> {
    fn deserialize<D: serde::de::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(SecretArrayVisitor)
    }
}
