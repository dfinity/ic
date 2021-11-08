#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Common methods for working with BLS12-381 primitives

pub mod serde;
pub use self::serde::pairing::{
    fr_from_bytes, fr_from_bytes_unchecked, fr_to_bytes, g1_from_bytes, g1_to_bytes, g2_from_bytes,
    g2_from_bytes_unchecked, g2_to_bytes, FR_SIZE, G1_SIZE, G2_SIZE,
};

mod arithmetic;
pub use arithmetic::{sum_g1, sum_g2};

mod hash;
pub use hash::{hash_to_fr, hash_to_g1, hash_to_miracl_g1, random_bls12_381_scalar, MiraclG1};

pub mod test_utils;

#[cfg(target_arch = "wasm32")]
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(always_fail);
