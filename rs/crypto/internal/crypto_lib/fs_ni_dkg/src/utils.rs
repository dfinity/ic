//! Utility functions for the NI-DKG code

use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::rom::CURVE_ORDER;
use miracl_core::rand::RAND;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[cfg(test)]
mod tests;

/// Order of the prime order subgroup of curve BLS12_381.
pub(crate) fn curve_order() -> BIG {
    BIG::new_ints(&CURVE_ORDER)
}

/// Point at infinity on G1 of curve BLS12_381.
pub(crate) fn ecp_inf() -> ECP {
    let mut new = ECP::new();
    new.inf();
    new
}

/// Point at infinity on G2 of curve BLS12_381.
pub(crate) fn ecp2_inf() -> ECP2 {
    let mut new = ECP2::new();
    new.inf();
    new
}

/// Zero element in the scalar field of curve BLS12_381.
pub(crate) fn big_zero() -> BIG {
    BIG::new_int(0)
}

/// Identity element in the scalar field of curve BLS12_381.
pub(crate) fn big_one() -> BIG {
    BIG::new_int(1)
}

/// Addition of two field elements modulo the prime order of the group.
pub(crate) fn field_add(left: &BIG, right: &BIG) -> BIG {
    BIG::modadd(left, right, &curve_order())
}

/// Multiplication of two field elements modulo the prime order of the group.
pub(crate) fn field_mul(left: &BIG, right: &BIG) -> BIG {
    BIG::modmul(left, right, &curve_order())
}

/// A random number generator based on the ChaCha20 stream cipher
#[allow(non_camel_case_types)]
pub struct RAND_ChaCha20 {
    chacha20: ChaCha20Rng,
}

impl RAND_ChaCha20 {
    pub fn new(seed: [u8; 32]) -> Self {
        RAND_ChaCha20 {
            chacha20: ChaCha20Rng::from_seed(seed),
        }
    }
}

impl RAND for RAND_ChaCha20 {
    fn seed(&mut self, _rawlen: usize, raw: &[u8]) {
        // Copy first 32 bytes from raw to raw32
        let mut raw32 = [0u8; 32];
        let copying = std::cmp::min(raw.len(), raw32.len());
        raw32[0..copying].copy_from_slice(&raw[0..copying]);
        self.chacha20 = ChaCha20Rng::from_seed(raw32);
    }

    fn getbyte(&mut self) -> u8 {
        let mut random_byte: [u8; 1] = [0; 1];
        // `fill_bytes()` with 1-byte buffer consumes 4 bytes of the random stream.
        self.chacha20.fill_bytes(&mut random_byte);
        random_byte[0]
    }
}
