//! Non-interactive distributed key generation
//!
//! Based on "Non-interactive distributed key generation and key resharing",
//! Jens Groth <https://eprint.iacr.org/2021/339>

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

// We follow the notation of the paper to the extent possible.
//   * As Clippy warns about single-character variable names, we prefix some of
//     them with `spec_`.
//   * We replace uppercase single-character variables with two copies of its
//     lowercase version, e.g. `A` -> `aa`.
//   * Greek letters are replaced by their names in English, e.g. `tau`.
//
// We build on top of MIRACL's `bls12381`.
//
//   rom::CURVE_ORDER  What the paper calls `p`.
//   rom::MODULUS      The order of FP, the field where the elliptic curve
// lives.
//
//   FP    The field Z_MODULUS (not Z_p).
//   FP12  The field where pairing outputs live.
//   BIG   Holds integers modulo `p`; also integers modulo MODULUS.
//   ECP   The group G_1.
//   ECP2  The group G_2.

pub mod encryption_key_pop;
pub mod forward_secure;
pub mod nizk_chunking;
pub mod nizk_sharing;
pub mod random_oracles;
pub mod utils;
