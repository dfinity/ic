#![allow(clippy::unwrap_used)]
//! Tests for bls operations
use super::super::{fr_to_bytes, g1_to_bytes};
use super::*;
use ic_crypto_internal_bls12381_serde_miracl::miracl_g1_to_bytes;
use pairing::bls12_381::FrRepr;
use std::collections::HashSet;

/// Verifies that different messages yield different points on G1 when hashed,
/// with high probability
#[test]
fn test_distinct_messages_yield_distinct_curve_points() {
    let dst = b"DFX01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let number_of_messages = 100;
    let points: HashSet<_> = (0..number_of_messages as u32)
        .map(|number| {
            let g1 = hash_to_g1(dst, &number.to_be_bytes()[..]);
            let bytes = g1_to_bytes(&g1);
            // It suffices to prove that the first 32 bytes are distinct.  More requires a
            // custom hash implementation.
            let mut hashable = [0u8; 32];
            hashable.copy_from_slice(&bytes[0..32]);
            hashable
        })
        .collect();
    assert_eq!(number_of_messages, points.len(), "Collisions found");
}

/// Verifies that different messages yield different points on G1 when hashed,
/// with high probability: MIRACL edition.
#[test]
fn test_distinct_messages_yield_distinct_curve_points_miracl() {
    let dst = b"DFX01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let number_of_messages = 100;
    let points: HashSet<_> = (0..number_of_messages as u32)
        .map(|number| {
            let miracl_g1 = hash_to_miracl_g1(dst, &number.to_be_bytes()[..]);
            let bytes = miracl_g1_to_bytes(&miracl_g1).0;
            // It suffices to prove that the first 32 bytes are distinct.  More requires a
            // custom hash implementation.
            let mut hashable = [0u8; 32];
            hashable.copy_from_slice(&bytes[0..32]);
            hashable
        })
        .collect();
    assert_eq!(number_of_messages, points.len(), "Collisions found");
}

#[test]
fn test_empty_hash_matches_draft_spec_09() {
    let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let miracl_g1 = hash_to_miracl_g1(dst, b"");
    let got = miracl_g1_to_bytes(&miracl_g1).0;
    // The spec says P.x starts with "05", which we replace with "85" because the
    // `pairing` crate sets the MSB to indicate point compression. (Another bit
    // indicates the "sign" of the y-coordinate, which happens to be 0 for this
    // case.)
    let want : &[u8] = &hex::decode("852926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1").unwrap();
    assert_eq!(want, &got[..]);
}

/// Verifies that different hashes yield different points on Fr.
#[test]
fn test_distinct_hashes_yield_distinct_fr() {
    let number_of_scalars = 100;
    let scalars: HashSet<_> = (0..number_of_scalars as u32)
        .map(|number| {
            let mut hash = Sha256::new();
            hash.write(&number.to_be_bytes()[..]);
            fr_to_bytes(&FrRepr::from(hash_to_fr(hash)))
        })
        .collect();
    assert_eq!(number_of_scalars, scalars.len(), "Collisions found");
}

/// Verifies that hash_to_fr produces the expected output
///
/// hash_to_fr must forever produce the same output for the same input.
/// This test checks this invariant. See CRP-1063 for background.
#[test]
fn test_hash_to_fr_produces_same_output_for_same_input() {
    let mut hash = Sha256::new();
    hash.write(b"A test input");
    let fr_bytes = fr_to_bytes(&FrRepr::from(hash_to_fr(hash)));
    assert_eq!(
        hex::encode(fr_bytes),
        "630fcb163218d5cd34f3ee5dc68bdbeda20975a54e08b130f3457afc6728d1d5"
    );

    let mut hash = Sha256::new();
    hash.write(b"A second unrelated test input");
    let fr_bytes = fr_to_bytes(&FrRepr::from(hash_to_fr(hash)));
    assert_eq!(
        hex::encode(fr_bytes),
        "699ed6764b14e1ae3ff73686399084f4fbbd51b972f85c49e4ef0954b36921af"
    );
}
