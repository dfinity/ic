//! Conversion between MIRACL representations of BLS12-381 values and the
//! standard representation.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

#[cfg(test)]
mod tests;

pub use ic_crypto_internal_types::curves::bls12_381::{
    Fr as FrBytes, G1 as G1Bytes, G2 as G2Bytes,
};

use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, Scalar};
use miracl_core_bls12381::bls12381::{big::BIG, ecp::ECP, ecp2::ECP2};

/// Serializes a MIRACL `Fr` (i.e. `BIG`) to a standard, library-independent
/// form.
///
/// Note: MIRACL represents `Fr` as a `BIG`, which is a larger data type than
/// `FrBytes`.
///
/// # References
/// * The `G1Bytes` documentation includes a description of the format.
///
/// # Panics
/// * If the leading bytes of `big` are *not* `0`
pub fn miracl_fr_to_bytes(big: &BIG) -> FrBytes {
    FrBytes(Scalar::from_miracl(big).serialize())
}

// TODO(IDX-1866)
#[allow(clippy::result_unit_err)]
/// Parses an `Fr` in a standard, library-independent form to a MIRACL `BIG`.
///
/// # Errors
/// * `Err(())` if `bytes` encodes a `BIG` that's greater than the BLS12_381
///   curve order.
pub fn miracl_fr_from_bytes(bytes: &[u8; FrBytes::SIZE]) -> Result<BIG, ()> {
    Scalar::deserialize(bytes)
        .map(|s| s.to_miracl())
        .map_err(|_| ())
}

/// Serializes a MIRACL `G1` (i.e. `ECP`) to a standard, library-independent
/// form.
///
/// # References
/// * The `G1Bytes` documentation includes a description of the format.
pub fn miracl_g1_to_bytes(ecp: &ECP) -> G1Bytes {
    G1Bytes(G1Affine::from_miracl(ecp).serialize())
}

// TODO(IDX-1866)
#[allow(clippy::result_unit_err)]
/// Parses a `G1` in a standard, library-independent form to a MIRACL `ECP`.
///
/// Note: This does NOT verify that the parsed value is actually in `G1`.
///
/// Errors:
/// * `Err(())` if
///   - The point is encoded in UNCOMPRESSED form
///   - The point's x-coordinate is non-canonical (i.e. greater than the field
///     modulus)
///   - The point's x-coordinate is infinity, but the INFINITY flag is *not* set
///   - The INFINITY flag is set, but the encoded x-coordinate is *not*
///     all-zeroes
pub fn miracl_g1_from_bytes_unchecked(bytes: &[u8; G1Bytes::SIZE]) -> Result<ECP, ()> {
    G1Affine::deserialize_unchecked(bytes)
        .map(|p| p.to_miracl())
        .map_err(|_| ())
}

// TODO(IDX-1866)
#[allow(clippy::result_unit_err)]
/// Parses a `G1` in a standard, library-independent form to a MIRACL `ECP`.
///
/// Also verifies that the point is in the correct prime order subgroup.
///
/// # Errors
/// * `Err(())` if
///   - The point is *not* in the correct prime order subgroup.
///   - The point is encoded in UNCOMPRESSED form
///   - The point's x-coordinate is non-canonical (i.e. greater than the field
///     modulus)
///   - The point's x-coordinate is infinity, but the INFINITY flag is *not* set
///   - The INFINITY flag is set, but the encoded x-coordinate is *not*
///     all-zeroes
pub fn miracl_g1_from_bytes(bytes: &[u8; G1Bytes::SIZE]) -> Result<ECP, ()> {
    G1Affine::deserialize(bytes)
        .map(|p| p.to_miracl())
        .map_err(|_| ())
}

/// Serializes a MIRACL `G2` (i.e. `ECP2`) to a standard, library-independent
/// form.
///
/// # References
/// * The `G2Bytes` documentation includes a description of the format.
pub fn miracl_g2_to_bytes(ecp2: &ECP2) -> G2Bytes {
    G2Bytes(G2Affine::from_miracl(ecp2).serialize())
}

// TODO(IDX-1866)
#[allow(clippy::result_unit_err)]
/// Parses a `G2` in a standard, library-independent form to a MIRACL `ECP2`.
///
/// Note: This does NOT verify that the parsed value is actually in `G2`.
///
/// Errors:
/// * `Err(())` if
///   - The point is encoded in UNCOMPRESSED form
///   - Either sub-component of the point's x-coordinate is non-canonical (i.e.
///     greater than the field modulus)
///   - The point's x-coordinate is infinity, but the INFINITY flag is *not* set
///   - The INFINITY flag is set, but the encoded x-coordinate is *not*
///     all-zeroes
pub fn miracl_g2_from_bytes_unchecked(bytes: &[u8; G2Bytes::SIZE]) -> Result<ECP2, ()> {
    G2Affine::deserialize_unchecked(bytes)
        .map(|p| p.to_miracl())
        .map_err(|_| ())
}

// TODO(IDX-1866)
#[allow(clippy::result_unit_err)]
/// Parses a `G2` in a standard, library-independent form to a MIRACL `ECP2`.
///
/// Also verifies that the point is in the correct prime order subgroup.
///
/// Errors:
/// * `Err(())` if
///   - The point is *not* in the correct prime order subgroup.
///   - The point is encoded in UNCOMPRESSED form
///   - Either sub-component of the point's x-coordinate is non-canonical (i.e.
///     greater than the field modulus)
///   - The point's x-coordinate is infinity, but the INFINITY flag is *not* set
///   - The INFINITY flag is set, but the encoded x-coordinate is *not*
///     all-zeroes
pub fn miracl_g2_from_bytes(bytes: &[u8; G2Bytes::SIZE]) -> Result<ECP2, ()> {
    G2Affine::deserialize(bytes)
        .map(|p| p.to_miracl())
        .map_err(|_| ())
}
