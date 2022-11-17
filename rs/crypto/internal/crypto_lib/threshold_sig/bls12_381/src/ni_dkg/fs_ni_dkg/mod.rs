//! Non-interactive distributed key generation
//!
//! Based on "Non-interactive distributed key generation and key resharing",
//! Jens Groth <https://eprint.iacr.org/2021/339>

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

// We follow the notation of the paper to the extent possible.
//   * We replace uppercase single-character variables with two copies of its
//     lowercase version, e.g. `A` -> `aa`.
//   * Greek letters are replaced by their names in English, e.g. `tau`.
//
// We build on top of the BLS12-381 library in `bls12_381/type`.
//
//   Gt        The field where pairing outputs live.
//   Scalar    Holds integers modulo the group order
//   G1Affine  The group G_1.
//   G2Affine  The group G_2.

pub use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;

pub mod chunking;
pub mod dlog_recovery;
pub mod encryption_key_pop;
pub mod forward_secure;
pub mod nizk_chunking;
pub mod nizk_sharing;
pub mod random_oracles;
