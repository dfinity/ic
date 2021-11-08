//! Utility functions for the NI-DKG code

use ic_crypto_internal_bls12381_serde_miracl::{
    miracl_fr_to_bytes, miracl_g1_to_bytes, miracl_g2_to_bytes,
};
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::fp::FP;
use miracl_core::bls12381::{ecp, rom};
use miracl_core::hmac;
use miracl_core::rand::RAND;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[cfg(test)]
mod tests;

/// Order of the prime order subgroup of curve BLS12_381.
pub fn curve_order() -> BIG {
    BIG::new_ints(&rom::CURVE_ORDER)
}

/// Point at infinity on G1 of curve BLS12_381.
pub fn ecp_inf() -> ECP {
    let mut new = ECP::new();
    new.inf();
    new
}

/// Point at infinity on G2 of curve BLS12_381.
pub fn ecp2_inf() -> ECP2 {
    let mut new = ECP2::new();
    new.inf();
    new
}

/// Zero element in the scalar field of curve BLS12_381.
pub fn big_zero() -> BIG {
    BIG::new_int(0)
}

/// Identity element in the scalar field of curve BLS12_381.
pub fn big_one() -> BIG {
    BIG::new_int(1)
}

/// Addition of two field elements modulo the prime order of the group.
pub fn field_add(left: &BIG, right: &BIG) -> BIG {
    BIG::modadd(left, right, &curve_order())
}

/// Multiplication of two field elements modulo the prime order of the group.
pub fn field_mul(left: &BIG, right: &BIG) -> BIG {
    BIG::modmul(left, right, &curve_order())
}

// Helpers to compute SHA256 hashes of elements of  Z_p/G_1/G_2.

/// Feeds an element of Z_p BIG to a hash.
///
/// Note: The least significant 32 bytes of a BIG are sufficient to contain an
/// element of Z_p.  We reduce the BIG representation to guarantee that the
/// element is in canonical form, in those 32 bytes.
pub fn process_fr(h: &mut miracl_core::hash256::HASH256, big: &BIG) {
    let mut big = *big;
    big.rmod(&BIG::new_ints(&rom::CURVE_ORDER));
    h.process_array(&miracl_fr_to_bytes(&big).0)
}

/// Feeds the standard serialisation of an element of G1==ECP to a hash.
pub fn process_ecp(h: &mut miracl_core::hash256::HASH256, point: &ECP) {
    h.process_array(&miracl_g1_to_bytes(point).0)
}

/// Feeds the standard serialisation of an element of G2==ECP2 to a hash.
pub fn process_ecp2(h: &mut miracl_core::hash256::HASH256, point: &ECP2) {
    h.process_array(&miracl_g2_to_bytes(point).0)
}

fn ceil(a: usize, b: usize) -> usize {
    (a - 1) / b + 1
}

/// Hash a message to a random integer modulo the BLS12-381 order
///
/// # Arguments
/// * `dst` a domain seperator
/// * `msg` the message to hash
/// * `spec_p` the order of BLS12-381
/// # Returns
/// An integer between 0 and spec_p
pub fn oracle_p(dst: &[u8], msg: &[u8], spec_p: &BIG) -> BIG {
    // We use `hash_to_field_bls12381` to hash to Z_p, even though it returns an
    // element of Z_MODULUS. However, MODULUS is 381-bit, while p is about 256 bits,
    // so the output is practically uniform modulo `p`.
    let mut x = hash_to_field_bls12381(hmac::MC_SHA2, ecp::HASH_TYPE, dst, msg, 1)[0].redc();
    x.rmod(spec_p);
    x
}

// Hash-to-field and hash-to-point, according to the draft spec.
// Copied from MIRACL's TestHTP.rs.
fn hash_to_field_bls12381(
    hash: usize,
    hlen: usize,
    dst: &[u8],
    msg: &[u8],
    ctr: usize,
) -> [miracl_core::bls12381::fp::FP; 2] {
    use miracl_core::bls12381::dbig::DBIG;
    let mut spec_u: [FP; 2] = [FP::new(), FP::new()];

    let q = BIG::new_ints(&rom::MODULUS);
    let k = q.nbits();
    let spec_r = BIG::new_ints(&rom::CURVE_ORDER);
    let m = spec_r.nbits();
    let ll = ceil(k + ceil(m, 2), 8);
    let mut okm: [u8; 512] = [0; 512];
    hmac::xmd_expand(hash, hlen, &mut okm, ll * ctr, dst, msg);
    let mut fd: [u8; 256] = [0; 256];
    for i in 0..ctr {
        for j in 0..ll {
            fd[j] = okm[i * ll + j];
        }
        let mut dx = DBIG::frombytes(&fd[0..ll]);
        let w = FP::new_big(&dx.dmod(&q));
        spec_u[i].copy(&w);
    }
    spec_u
}

fn hash_to_field2_bls12381(
    hash: usize,
    hlen: usize,
    dst: &[u8],
    msg: &[u8],
    ctr: usize,
) -> [miracl_core::bls12381::fp2::FP2; 2] {
    use miracl_core::bls12381::dbig::DBIG;
    use miracl_core::bls12381::fp2::FP2;

    let mut spec_u: [FP2; 2] = [FP2::new(), FP2::new()];

    let q = BIG::new_ints(&rom::MODULUS);
    let k = q.nbits();
    let spec_r = BIG::new_ints(&rom::CURVE_ORDER);
    let m = spec_r.nbits();
    let ll = ceil(k + ceil(m, 2), 8);
    let mut okm: [u8; 512] = [0; 512];
    hmac::xmd_expand(hash, hlen, &mut okm, 2 * ll * ctr, dst, msg);
    let mut fd: [u8; 256] = [0; 256];
    for i in 0..ctr {
        for j in 0..ll {
            fd[j] = okm[2 * i * ll + j];
        }
        let mut dx = DBIG::frombytes(&fd[0..ll]);
        let w1 = FP::new_big(&dx.dmod(&q));

        for j in 0..ll {
            fd[j] = okm[(2 * i + 1) * ll + j];
        }
        dx = DBIG::frombytes(&fd[0..ll]);
        let w2 = FP::new_big(&dx.dmod(&q));
        spec_u[i].copy(&FP2::new_fps(&w1, &w2));
    }
    spec_u
}

/// Hash a message onto the BLS12-381 G2 curve
///
/// Uses <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>
///
/// # Arguments
/// * `dst` a domain seperator (see the internet draft for guidance on
///   formatting)
/// * `mess` is a message that will be hashed onto G2
/// # Returns
/// An element of BLS12-381 G2
pub fn htp2_bls12381(dst: &[u8], mess: &str) -> ECP2 {
    let m = mess.as_bytes();
    let spec_u = hash_to_field2_bls12381(hmac::MC_SHA2, ecp::HASH_TYPE, dst, m, 2);
    let mut x = ECP2::map2point(&spec_u[0]);
    let x1 = ECP2::map2point(&spec_u[1]);
    x.add(&x1);
    x.cfp();
    x.affine();
    x
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
