/// Sensitive data held as a Vec of `u8`s.
use core::fmt::{self, Debug};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Sensitive data held as a Vec of `u8`s.
///
/// SecretVec implement Serialize/Deserialize traits from serde. However
/// due to an oversight when the type was first written, it uses a significantly
/// less efficient encoding than would be preferable. It is not possible to
/// update this now without breaking existing encoded structures.
///
/// For new code, consider instead using SecretBytes, also from this
/// crate, which implements a compact encoding which is equivalent to
/// just the bytestring itself.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec {
    inner_secret: Vec<u8>,
}

impl SecretVec {
    /// Constructs a `SecretVec` from the provided `secret`, and clears the
    /// memory used by `secret`.
    pub fn new_and_zeroize_argument(secret: &mut Vec<u8>) -> Self {
        let ret = Self::new_and_dont_zeroize_argument(secret);
        secret.zeroize();
        ret
    }

    /// Constructs a `SecretVec` from the provided (non-owned) `secret`.
    ///
    /// Note: It is the responsibility of the caller to clear the memory
    /// used by `secret`.
    pub fn new_and_dont_zeroize_argument(secret: &[u8]) -> Self {
        Self {
            inner_secret: secret.to_vec(),
        }
    }

    /// Provides read-only access to the secret vec.
    pub fn expose_secret(&self) -> &[u8] {
        &self.inner_secret
    }
}

impl Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "REDACTED SecretVec of length {}",
            self.inner_secret.len()
        )
    }
}
