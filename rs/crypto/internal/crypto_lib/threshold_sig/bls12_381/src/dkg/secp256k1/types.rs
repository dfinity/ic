//! (deprecated) Interactive Distributed Key Generation (DKG) Types
//!
//! The types in this file correspond to the types used in the spec, including
//! ephemeral (secp256k1) keys, dealings, complaints and transcripts.  Please
//! see the specification for more details.

pub use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::secp256k1::EphemeralPublicKeyBytes;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

#[derive(Copy, Clone, Eq, PartialEq, Zeroize)]
pub struct EphemeralSecretKeyBytes(pub [u8; EphemeralSecretKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(EphemeralSecretKeyBytes, EphemeralSecretKeyBytes::SIZE);
impl EphemeralSecretKeyBytes {
    pub const SIZE: usize = 32;
}

impl fmt::Debug for EphemeralSecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EphemeralPopBytes(pub [u8; EphemeralPopBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(EphemeralPopBytes, EphemeralPopBytes::SIZE);
impl EphemeralPopBytes {
    pub const SIZE: usize = EphemeralPublicKeyBytes::SIZE + 2 * EphemeralSecretKeyBytes::SIZE;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct EphemeralKeySetBytes {
    pub secret_key_bytes: EphemeralSecretKeyBytes,
    pub public_key_bytes: EphemeralPublicKeyBytes,
    pub pop_bytes: EphemeralPopBytes,
}

impl Zeroize for EphemeralKeySetBytes {
    fn zeroize(&mut self) {
        self.secret_key_bytes.zeroize();
    }
}
