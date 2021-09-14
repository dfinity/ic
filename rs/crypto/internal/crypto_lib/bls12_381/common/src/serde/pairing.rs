//! Serialisation and deserialisation of the pairing library BLS12-381 types.

use ff::PrimeFieldRepr;
use group::{CurveAffine, CurveProjective, EncodedPoint, GroupDecodingError};
use pairing::bls12_381::{FrRepr, G1Affine, G2Affine, G1, G2};

pub const FR_SIZE: usize = 32;
pub const G1_SIZE: usize = 48;
pub const G2_SIZE: usize = 96;

#[cfg(test)]
mod test_vectors_g1;
#[cfg(test)]
mod test_vectors_g2;
#[cfg(test)]
mod tests;

/// Decode BLS12-381 G1 point from bytes
///
/// # Arguments
/// * `bytes`: a compressed instance of G1 point
/// # Errors
/// * `GroupDecodingError` if the input is invalid
/// # Returns
/// The decoded point
pub fn g1_from_bytes(bytes: &[u8; G1_SIZE]) -> Result<G1, GroupDecodingError> {
    let mut compressed: <G1Affine as CurveAffine>::Compressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(bytes);
    compressed
        .into_affine()
        .map(|affine| affine.into_projective())
}

/// Encode BLS12-381 G1 point to bytes
///
/// # Arguments
/// * `g1` a point
/// # Returns
/// The encoded point in compressed form
pub fn g1_to_bytes(g1: &G1) -> [u8; G1_SIZE] {
    let mut bytes = [0u8; G1_SIZE];
    bytes.copy_from_slice(g1.into_affine().into_compressed().as_ref());
    bytes
}

/// Decode BLS12-381 G2 point from bytes
///
/// # Arguments
/// * `bytes`: a compressed instance of G2 point
/// # Errors
/// * `GroupDecodingError` if the input is invalid
/// # Returns
/// The decoded point
pub fn g2_from_bytes(bytes: &[u8; G2_SIZE]) -> Result<G2, GroupDecodingError> {
    let mut compressed: <G2Affine as CurveAffine>::Compressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(bytes);
    compressed
        .into_affine()
        .map(|affine| affine.into_projective())
}

/// Decode BLS12-381 G2 point from bytes, without guaranteeing that the encoding
/// represents an element in the large prime order subgroup.
///
/// # Security Notice
///
/// This should only be used if the `bytes` are from a trusted source.
///
/// # Arguments
/// * `bytes`: a compressed instance of G2 point
/// # Errors
/// * `GroupDecodingError` if the input is invalid
/// # Returns
/// The decoded point
pub fn g2_from_bytes_unchecked(bytes: &[u8; G2_SIZE]) -> Result<G2, GroupDecodingError> {
    let mut compressed: <G2Affine as CurveAffine>::Compressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(bytes);
    compressed
        .into_affine_unchecked()
        .map(|affine| affine.into_projective())
}

/// Encode BLS12-381 G2 point to bytes
///
/// # Arguments
/// * `g2` a point
/// # Returns
/// The encoded point in compressed form
pub fn g2_to_bytes(g2: &G2) -> [u8; G2_SIZE] {
    let mut bytes = [0u8; G2_SIZE];
    bytes.copy_from_slice(g2.into_affine().into_compressed().as_ref());
    bytes
}

/// Encode BLS12-381 field element to bytes
///
/// # Arguments
/// * `fr` a field element
/// # Returns
/// The encoded element
pub fn fr_to_bytes(fr: &FrRepr) -> [u8; FR_SIZE] {
    let mut ans = [0u8; FR_SIZE];
    fr.write_be(&mut ans[0..])
        .expect("Insufficient output space");
    ans
}

/// Decode BLS12-381 field element from bytes
///
/// # Arguments
/// * `bytes`: encoding of a field element
/// # Returns
/// The decoded field element
pub fn fr_from_bytes(bytes: &[u8; FR_SIZE]) -> FrRepr {
    let mut ans = FrRepr([0; 4]);
    let mut reader = &bytes[..];
    ans.read_be(&mut reader)
        .expect("Insufficient input material");
    ans
}
