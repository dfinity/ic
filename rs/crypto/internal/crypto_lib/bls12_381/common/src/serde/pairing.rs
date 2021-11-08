//! Serialisation and deserialisation of the pairing library BLS12-381 types.

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

pub const FR_SIZE: usize = 32;
pub const G1_SIZE: usize = 48;
pub const G2_SIZE: usize = 96;

#[cfg(test)]
mod test_vectors_g1;
#[cfg(test)]
mod test_vectors_g2;
#[cfg(test)]
mod tests;

#[derive(Copy, Clone, Debug)]
pub enum GroupDecodingError {
    InvalidPoint,
}

#[derive(Copy, Clone, Debug)]
pub enum ScalarDecodingError {
    InvalidScalar,
}

/// Decode BLS12-381 G1 point from bytes
///
/// # Arguments
/// * `bytes`: a compressed instance of G1 point
/// # Errors
/// * `GroupDecodingError` if the input is invalid
/// # Returns
/// The decoded point

pub fn g1_from_bytes(bytes: &[u8; G1_SIZE]) -> Result<G1Projective, GroupDecodingError> {
    let g1a = G1Affine::from_compressed(bytes);

    if bool::from(g1a.is_some()) {
        Ok(G1Projective::from(g1a.unwrap()))
    } else {
        Err(GroupDecodingError::InvalidPoint)
    }
}

/// Encode BLS12-381 G1 point to bytes
///
/// # Arguments
/// * `g1` a point
/// # Returns
/// The encoded point in compressed form
pub fn g1_to_bytes(g1: &G1Projective) -> [u8; G1_SIZE] {
    let g1a = G1Affine::from(g1);
    g1a.to_compressed()
}

/// Decode BLS12-381 G2 point from bytes
///
/// # Arguments
/// * `bytes`: a compressed instance of G2 point
/// # Errors
/// * `GroupDecodingError` if the input is invalid
/// # Returns
/// The decoded point
pub fn g2_from_bytes(bytes: &[u8; G2_SIZE]) -> Result<G2Projective, GroupDecodingError> {
    let g2a = G2Affine::from_compressed(bytes);
    if bool::from(g2a.is_some()) {
        Ok(G2Projective::from(g2a.unwrap()))
    } else {
        Err(GroupDecodingError::InvalidPoint)
    }
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

pub fn g2_from_bytes_unchecked(bytes: &[u8; G2_SIZE]) -> Result<G2Projective, GroupDecodingError> {
    let g2a = G2Affine::from_compressed_unchecked(bytes);
    if bool::from(g2a.is_some()) {
        Ok(G2Projective::from(g2a.unwrap()))
    } else {
        Err(GroupDecodingError::InvalidPoint)
    }
}

/// Encode BLS12-381 G2 point to bytes
///
/// # Arguments
/// * `g2` a point
/// # Returns
/// The encoded point in compressed form
pub fn g2_to_bytes(g2: &G2Projective) -> [u8; G2_SIZE] {
    let g2a = G2Affine::from(g2);
    g2a.to_compressed()
}

/// Encode BLS12-381 field element to bytes
///
/// # Arguments
/// * `fr` a field element
/// # Returns
/// The encoded element
pub fn fr_to_bytes(fr: &Scalar) -> [u8; FR_SIZE] {
    let bytes = fr.to_bytes();
    let mut rev_bytes = [0u8; FR_SIZE];
    for i in 0..FR_SIZE {
        rev_bytes[i] = bytes[FR_SIZE - i - 1];
    }
    rev_bytes
}

/// Decode BLS12-381 field element from bytes
///
/// # Arguments
/// * `bytes`: encoding of a field element
/// # Errors
/// * `ScalarDecodingError` if the input is invalid (out of range)
/// # Returns
/// The decoded field element
pub fn fr_from_bytes(bytes: &[u8; FR_SIZE]) -> Result<Scalar, ScalarDecodingError> {
    let mut le_bytes = [0u8; 32];

    for i in 0..FR_SIZE {
        le_bytes[i] = bytes[FR_SIZE - i - 1];
    }
    let s = Scalar::from_bytes(&le_bytes);

    if bool::from(s.is_none()) {
        return Err(ScalarDecodingError::InvalidScalar);
    }

    Ok(s.unwrap())
}

/// Decode BLS12-381 field element from bytes (accepting out of range elements)
///
/// # Arguments
/// * `bytes`: encoding of a field element
/// # Returns
/// The decoded field element
pub fn fr_from_bytes_unchecked(bytes: &[u8; FR_SIZE]) -> Scalar {
    let mut le_bytes = [0u8; 64];

    for i in 0..FR_SIZE {
        le_bytes[i] = bytes[FR_SIZE - i - 1];
    }
    // le_bytes[32..64] left as zero
    Scalar::from_bytes_wide(&le_bytes)
}
