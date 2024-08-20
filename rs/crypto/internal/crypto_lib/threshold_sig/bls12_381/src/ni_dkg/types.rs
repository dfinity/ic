//! Types used by all implementations of NiDKG methods.

#![allow(clippy::unit_arg)] // Arbitrary is a unit arg in: derive(proptest_derive::Arbitrary)

#[cfg(test)]
mod tests;

use super::groth20_bls12_381::types as groth20_bls12_381;
use serde::{Deserialize, Serialize};
use std::fmt;
use strum_macros::IntoStaticStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(test)]
use proptest_derive::Arbitrary;

/// Forward secure encryption secret key.
#[derive(Clone, Eq, PartialEq, IntoStaticStr, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[allow(non_camel_case_types)]
pub enum CspFsEncryptionSecretKey {
    Groth20_Bls12_381(groth20_bls12_381::FsEncryptionSecretKey),
}

impl fmt::Debug for CspFsEncryptionSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // this prints no secret key parts since Debug for BTENodeBytes is redacted:
            CspFsEncryptionSecretKey::Groth20_Bls12_381(sk) => {
                write!(f, "CspFsEncryptionSecretKey::Groth20_Bls12_381 - {:?}", sk)
            }
        }
    }
}

/// Forward secure encryption keys (secret and public keys, and
/// proof-of-possession)
#[derive(
    Clone, Debug, Eq, PartialEq, IntoStaticStr, Serialize, Deserialize, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(test, derive(Arbitrary))]
#[allow(non_camel_case_types)]
pub enum CspFsEncryptionKeySet {
    Groth20WithPop_Bls12_381(groth20_bls12_381::FsEncryptionKeySetWithPop),
}
