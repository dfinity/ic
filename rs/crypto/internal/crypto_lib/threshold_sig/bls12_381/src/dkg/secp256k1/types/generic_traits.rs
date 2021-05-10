//! These are boilerplate implementations of standard traits that cannot be
//! auto-generated in the normal way because Rust doesn't have const generics
//! yet. This code is in a separate file to avoid cluttering the types file with
//! implementation details.

use super::*;
use secp256k1::curve::Affine;
use std::fmt;

#[cfg(test)]
mod tests;

// Note: This is needed because Rust doesn't support const generics yet.
impl fmt::Debug for EphemeralPopBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0[..])
    }
}
impl PartialEq for EphemeralPopBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for EphemeralPopBytes {}

// Note: This is needed because public keys can have multiple representations
impl PartialEq for EphemeralPublicKey {
    fn eq(&self, other: &Self) -> bool {
        Affine::from_gej(&self.0) == Affine::from_gej(&other.0)
    }
}
impl Eq for EphemeralPublicKey {}

impl Zeroize for EphemeralSecretKey {
    fn zeroize(&mut self) {
        self.0.clear()
    }
}

/* TODO(CRP-103): Zeroize all secret keys properly; Zeroize does not work as originally thought.
impl Drop for EphemeralSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
*/
impl fmt::Debug for EphemeralSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}

impl fmt::Debug for EphemeralSecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}

impl Zeroize for EphemeralKeySetBytes {
    fn zeroize(&mut self) {
        self.secret_key_bytes.zeroize();
    }
}

impl fmt::Debug for EncryptedShareBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}
