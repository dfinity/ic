//! Variable to fixed size byte array conversions.
//!
//! When const_generics are in stable rust, all of these become just
//! `.try_into()`.  `#![feature(const_generics)]` is available in the rust
//! nightly release.

use crate::curves::bls12_381::{FrBytes, G1Bytes, G2Bytes};
use std::convert::TryInto;

/// Converts a vec into the correct number of bytes for a Fr
pub fn fr_bytes_from_vec(bytes: &[u8]) -> &[u8; FrBytes::SIZE] {
    bytes.try_into().expect("Incorrect number of bytes for Fr")
}

/// Converts a vec into the correct number of bytes for a G1
pub fn g1_bytes_from_vec(bytes: &[u8]) -> [u8; G1Bytes::SIZE] {
    if bytes.len() != G1Bytes::SIZE {
        panic!(
            "Wrong size for G1: Expected {} got {}",
            G1Bytes::SIZE,
            bytes.len()
        );
    }
    let mut ans = [0u8; G1Bytes::SIZE];
    ans.copy_from_slice(bytes);
    ans
}

/// Converts a vec into the correct number of bytes for a G2
pub fn g2_bytes_from_vec(bytes: &[u8]) -> [u8; G2Bytes::SIZE] {
    if bytes.len() != G2Bytes::SIZE {
        panic!("Wrong size for G2");
    }
    let mut ans = [0u8; G2Bytes::SIZE];
    ans.copy_from_slice(bytes);
    ans
}
