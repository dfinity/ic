#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Common methods for working with BLS12-381 primitives

pub mod serde;
pub use self::serde::pairing::{
    fr_from_bytes, fr_to_bytes, g1_from_bytes, g1_to_bytes, g2_from_bytes, g2_to_bytes, FR_SIZE,
    G1_SIZE, G2_SIZE,
};

mod arithmetic;
pub use arithmetic::{scalar_multiply, sum};

mod hash;
pub use hash::{hash_to_fr, hash_to_g1, hash_to_miracl_g1, MiraclG1};

pub mod test_utils;
