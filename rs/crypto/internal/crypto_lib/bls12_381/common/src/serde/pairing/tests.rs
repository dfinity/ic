//! Tests for bls operations
use super::*;
use crate::random_bls12_381_scalar;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

/// Verifies that G1 points are unchanged by serialisation followed by
/// deserialisation
#[test]
fn test_g1_serde() {
    let mut rng = ChaChaRng::from_seed([9u8; 32]);
    for fr in (0..100).map(|_| random_bls12_381_scalar(&mut rng)) {
        let g1 = G1Projective::generator() * fr;
        let serialized = g1_to_bytes(&g1);
        let deserialized = g1_from_bytes(&serialized).expect("Failed to deserialize");
        assert_eq!(
            g1, deserialized,
            "G1 serde did not return original curve point"
        );
    }
}

/// Verifies that G2 points are unchanged by serialisation followed by
/// deserialisation
#[test]
fn test_g2_serde() {
    let mut rng = ChaChaRng::from_seed([9u8; 32]);
    for fr in (0..100).map(|_| random_bls12_381_scalar(&mut rng)) {
        let g2 = G2Projective::generator() * fr;
        let serialized = g2_to_bytes(&g2);
        let deserialized = g2_from_bytes(&serialized).expect("Failed to deserialize");
        assert_eq!(
            g2, deserialized,
            "G2 serde did not return original curve point"
        );
    }
}

/// Verifies that field elements are unchanged by serialisation followed by
/// deserialisation
#[test]
fn test_fr_serde() {
    let mut rng = ChaChaRng::from_seed([9u8; 32]);
    for fr in (0..100).map(|_| random_bls12_381_scalar(&mut rng)) {
        let serialized = fr_to_bytes(&fr);
        let deserialized = fr_from_bytes(&serialized).expect("Serialized element out of range");
        assert_eq!(
            fr, deserialized,
            "Fr serde did not return original field element"
        );

        let deserialized = fr_from_bytes_unchecked(&serialized);
        assert_eq!(
            fr, deserialized,
            "Fr serde did not return original field element"
        );
    }
}
