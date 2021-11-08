//! Hashing to BLS12-381 primitives

use crate::serde::pairing::g1_from_bytes;
use bls12_381::{G1Projective, Scalar};
use ic_crypto_internal_bls12381_serde_miracl::miracl_g1_to_bytes;
use ic_crypto_sha::Sha256;
use miracl_core::bls12381::ecp::ECP;
use rand_chacha::ChaChaRng;
use rand_core::RngCore;
use rand_core::SeedableRng;

#[cfg(test)]
mod tests;

/// Hash onto BLS12-381 G1 (random oracle variant) returning zkgroup/pairing
/// object
///
/// This follows the internet draft <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>
///
/// # Arguments
/// * `dst` is a domain separation tag (see draft-irtf-cfrg-hash-to-curve for
///   guidance on formatting of this tag)
/// * `msg` is the message to be hashed to an elliptic curve point on BLS12_381.
/// # Returns
/// The G1 point as a zkgroup/pairing object
pub fn hash_to_g1(domain: &[u8], msg: &[u8]) -> G1Projective {
    let hash = hash_to_miracl_g1(domain, msg);
    g1_from_bytes(&miracl_g1_to_bytes(&hash).0)
        .expect("unreachable: conversion error from Miracl G1 to pairing::G1")
}

// Based on MIRACL's TestHTP.rs.
fn hash_to_field_bls12381(
    hash: usize,
    hlen: usize,
    dst: &[u8],
    msg: &[u8],
    ctr: usize,
) -> [miracl_core::bls12381::fp::FP; 2] {
    use miracl_core::bls12381::big::BIG;
    use miracl_core::bls12381::dbig::DBIG;
    use miracl_core::bls12381::fp::FP;
    use miracl_core::bls12381::rom;
    use miracl_core::hmac;

    let mut uu: [FP; 2] = [FP::new(), FP::new()];

    let qq = BIG::new_ints(&rom::MODULUS);
    let kk = qq.nbits();
    let rr = BIG::new_ints(&rom::CURVE_ORDER);
    let mm = rr.nbits();
    let ll = ceil(kk + ceil(mm, 2), 8);
    let mut okm: [u8; 512] = [0; 512];
    hmac::xmd_expand(hash, hlen, &mut okm, ll * ctr, &dst, &msg);
    let mut fd: [u8; 256] = [0; 256];
    for i in 0..ctr {
        for j in 0..ll {
            fd[j] = okm[i * ll + j];
        }
        let mut dx = DBIG::frombytes(&fd[0..ll]);
        let w = FP::new_big(&dx.dmod(&qq));
        uu[i].copy(&w);
    }
    uu
}

// Returns ceil(a/b). Assumes a>0.
fn ceil(a: usize, b: usize) -> usize {
    (a - 1) / b + 1
}

/// Type alias for a Miracl BLS12-381 G1 elliptic curve point.
pub type MiraclG1 = ECP;

/// Hash onto BLS12-381 G1 (random oracle variant) returning MIRACL object
///
/// This follows the internet draft <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>
///
/// # Arguments
/// * `dst` is a domain separation tag (see draft-irtf-cfrg-hash-to-curve for
///   guidance on formatting of this tag)
/// * `msg` is the message to be hashed to an elliptic curve point on BLS12_381.
/// # Returns
/// The G1 point as a MIRACL object
pub fn hash_to_miracl_g1(dst: &[u8], msg: &[u8]) -> MiraclG1 {
    use miracl_core::bls12381::ecp;
    use miracl_core::hmac;
    let u = hash_to_field_bls12381(hmac::MC_SHA2, ecp::HASH_TYPE, dst, msg, 2);

    // Note: `map2point` implements the function `map_to_curve` specified in the
    // internet draft, according to the BLS12_381 ciphersuite for G1.
    let mut p = MiraclG1::map2point(&u[0]);
    let p1 = MiraclG1::map2point(&u[1]);
    p.add(&p1);
    p.cfp();
    p.affine();

    p
}

pub fn random_bls12_381_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    loop {
        let mut repr = [0u64; 4];
        for r in repr.iter_mut() {
            *r = rng.next_u64();
        }

        /*
        Since the modulus is 255 bits, we clear out the most significant bit to
        reduce number of repetitions for the rejection sampling.

        (This also matches the logic used in the old version of zcrypto/pairing,
        which we are attempting to maintain bit-for-bit compatability with)
        */
        repr[3] &= 0xffffffffffffffff >> 1;

        let mut repr8 = [0u8; 32];
        repr8[..8].copy_from_slice(&repr[0].to_le_bytes());
        repr8[8..16].copy_from_slice(&repr[1].to_le_bytes());
        repr8[16..24].copy_from_slice(&repr[2].to_le_bytes());
        repr8[24..].copy_from_slice(&repr[3].to_le_bytes());

        let scalar = Scalar::from_bytes(&repr8);

        if bool::from(scalar.is_none()) {
            continue; // out of range
        }

        let mut scalar = scalar.unwrap();

        /*
        The purpose of this function is to maintain bit-compatability with old
        versions of zkcrypto/pairing's Fr::random. That function generates random
        values by generating a random integer, then treating it as if it was already
        in Montgomery format; that is, x is stored as xR where R == 2**256, and so
        the value that Fr::random produces is really z*R^-1 where z is the RNG
        output.

        To produce this value using the public API we have to first generate the
        value, then multiply by R^-1 mod p, which is the constant below using
        little-endian convention, ie the value is really 0x1bbe869...5c040.
        Here R == 2**256 and p is the order of the BLS12-381 subgroup.
        */
        let montgomery_fixup = [
            0x13f75b69fe75c040,
            0xab6fca8f09dc705f,
            0x7204078a4f77266a,
            0x1bbe869330009d57,
        ];

        let montgomery_fixup = Scalar::from_raw(montgomery_fixup);
        scalar *= montgomery_fixup;

        return scalar;
    }
}

/// Deterministically create a BLS12-381 field element from a hash
///
/// # Arguments
/// * `hash` a Sha256 hash which is finalized and consumed.
/// # Returns
/// A field element
pub fn hash_to_fr(hash: Sha256) -> Scalar {
    let hash = hash.finish();
    let mut rng = ChaChaRng::from_seed(hash);
    random_bls12_381_scalar(&mut rng)
}
