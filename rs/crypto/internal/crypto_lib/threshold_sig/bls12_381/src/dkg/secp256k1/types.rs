//! (deprecated) Interactive Distributed Key Generation (DKG) Types
//!
//! The types in this file correspond to the types used in the spec, including
//! ephemeral (secp256k1) keys, dealings, complaints and transcripts.  Please
//! see the specification for more details.

mod advanced_ops;
#[cfg(test)]
mod arbitrary;
mod conversions;
mod generic_traits;
mod ops;

use crate::types as threshold;
use crate::types::{PublicCoefficients, SecretKeyBytes};
pub use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::secp256k1::EphemeralPublicKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_types::NodeIndex;
use pairing::bls12_381::Fr;
use serde::{Deserialize, Serialize};
use std::collections::btree_map::BTreeMap;
use zeroize::Zeroize;

#[derive(Clone, Eq, PartialEq)]
pub struct EphemeralSecretKey(secp256k1::curve::Scalar);

#[derive(Copy, Clone, Eq, PartialEq, Zeroize)]
pub struct EphemeralSecretKeyBytes(pub [u8; EphemeralSecretKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(EphemeralSecretKeyBytes, EphemeralSecretKeyBytes::SIZE);
impl EphemeralSecretKeyBytes {
    pub const SIZE: usize = 32;
}

#[allow(unused)]
pub const SECP256K1_SECRET_KEY_ONE: EphemeralSecretKeyBytes = EphemeralSecretKeyBytes([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

#[derive(Clone, Debug)]
pub struct EphemeralPublicKey(secp256k1::curve::Jacobian);

pub const SECP256K1_PUBLIC_KEY_ONE: EphemeralPublicKeyBytes = EphemeralPublicKeyBytes([
    2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219,
    45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
]);

#[derive(Copy, Clone)]
pub struct EphemeralPopBytes(pub [u8; EphemeralPopBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(EphemeralPopBytes, EphemeralPopBytes::SIZE);
impl EphemeralPopBytes {
    pub const SIZE: usize = EphemeralPublicKeyBytes::SIZE + 2 * EphemeralSecretKeyBytes::SIZE;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralPop {
    pub spec_ext: EphemeralPublicKey,
    pub spec_c: EphemeralSecretKey,
    pub spec_s: EphemeralSecretKey,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct EphemeralKeySetBytes {
    pub secret_key_bytes: EphemeralSecretKeyBytes,
    pub public_key_bytes: EphemeralPublicKeyBytes,
    pub pop_bytes: EphemeralPopBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CLibDealing {
    pub public_coefficients: PublicCoefficients,
    pub receiver_data: Vec<Option<EncryptedShare>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CLibDealingBytes {
    pub public_coefficients: PublicCoefficientsBytes,
    pub receiver_data: Vec<Option<EncryptedShareBytes>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CLibVerifiedDealing {
    pub dealer_public_key: EphemeralPublicKey,
    pub public_coefficients: PublicCoefficients,
    pub receiver_data: Vec<Option<EncryptedShare>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CLibVerifiedDealingBytes {
    pub dealer_public_key: EphemeralPublicKeyBytes,
    pub public_coefficients: PublicCoefficientsBytes,
    pub receiver_data: Vec<Option<EncryptedShareBytes>>,
}

pub type EncryptedShare = threshold::SecretKey;
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct EncryptedShareBytes(pub [u8; EncryptedShareBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(EncryptedShareBytes, EncryptedShareBytes::SIZE);
impl EncryptedShareBytes {
    pub const SIZE: usize = SecretKeyBytes::SIZE;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CLibComplaint {
    pub diffie_hellman: EphemeralPublicKey,
    pub pok_challenge: EphemeralSecretKey,
    pub pok_response: EphemeralSecretKey,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CLibComplaintBytes {
    pub diffie_hellman: EphemeralPublicKeyBytes,
    pub pok_challenge: EphemeralSecretKeyBytes,
    pub pok_response: EphemeralSecretKeyBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CLibResponseBytes {
    pub complaints: BTreeMap<EphemeralPublicKeyBytes, Option<CLibComplaintBytes>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CLibVerifiedResponseBytes {
    pub receiver_public_key: EphemeralPublicKeyBytes,
    pub complaints: BTreeMap<EphemeralPublicKeyBytes, Option<CLibComplaintBytes>>,
}

/// This is the long term public record of a DKG.
///
/// Signatories (receivers) can compute their secret threshold signing key from
/// the transcript and their private ephemeral key.  the private ephemeral key
/// is then discarded so this can be done only once.
///
/// Any node can use the public values in the transcript to verify individual or
/// combined threshold signatures.
///
/// # Fields
/// * `dealer_public_keys` are ephemeral public keys; these used by signatories
///   (receivers) in conjunction with their private ephemeral key to decrypt
///   their private threshold key.
/// * `dealer_reshare_indices` are used only for resharing DKGs.  Resharing
///   dealers were receivers in a preceding DKG.  Receivers are always
///   associated with indices.  Those indices are required, together with the
///   `dealer_public_keys`, to decrypt private threshold keys.
/// * `public_coefficients` are a vector of public keys.  These include the
///   threshold public key, used to verify combined threshold signatures, and
///   can be used to compute the public key of any signatory (receiver).
/// * `receiver_data` is the encrypted secret threshold keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CLibTranscriptBytes {
    pub dealer_public_keys: Vec<EphemeralPublicKeyBytes>,
    pub dealer_reshare_indices: Option<Vec<NodeIndex>>,
    pub public_coefficients: PublicCoefficientsBytes,
    pub receiver_data: Vec<Option<(EphemeralPublicKeyBytes, EncryptedShareBytes)>>,
}

pub mod serialisation {
    pub const TAG_PUBKEY_INFINITE: u8 = 0x00;
    pub const TAG_PUBKEY_EVEN: u8 = 0x02;
    pub const TAG_PUBKEY_ODD: u8 = 0x03;
}
