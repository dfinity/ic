//! Integration tests for the multisig lib public API

use assert_matches::assert_matches;
use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine};
use ic_crypto_internal_multi_sig_bls12381 as multi_sig;
use ic_crypto_internal_multi_sig_bls12381::types::{
    CombinedSignatureBytes, IndividualSignatureBytes, PopBytes, PublicKeyBytes, SecretKeyBytes,
};
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_types::curves::bls12_381::G2Bytes;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use proptest::prelude::*;
use rand::{CryptoRng, Rng};

/// Generate a G1 point that is not in the prime-order subgroup (has torsion).
/// Used to test that malformed inputs are properly rejected.
fn non_torsion_g1<R: Rng + CryptoRng>(rng: &mut R) -> G1Affine {
    let mut buf = [0u8; G1Affine::BYTES];

    loop {
        rng.fill_bytes(&mut buf);
        buf[0] |= 0x80; // set compressed bit
        buf[0] &= 0xBF; // clear infinity bit

        match G1Affine::deserialize_unchecked(&buf) {
            Ok(pt) if !pt.is_torsion_free() => {
                return pt;
            }
            _ => {}
        };
    }
}

/// Generate a G2 point that is not in the prime-order subgroup (has torsion).
/// Used to test that malformed inputs are properly rejected.
fn non_torsion_g2<R: Rng + CryptoRng>(rng: &mut R) -> G2Affine {
    let mut buf = [0u8; G2Affine::BYTES];

    loop {
        rng.fill_bytes(&mut buf);
        buf[0] |= 0x80; // set compressed bit
        buf[0] &= 0xBF; // clear infinity bit

        match G2Affine::deserialize_unchecked(&buf) {
            Ok(pt) if !pt.is_torsion_free() => {
                return pt;
            }
            _ => {}
        };
    }
}

/// Proptest strategy for generating key pairs using the public API
fn key_pair_bytes() -> impl Strategy<Value = (SecretKeyBytes, PublicKeyBytes)> {
    any::<[u8; 32]>().prop_map(|seed| {
        let seed = Seed::from_bytes(&seed);
        multi_sig::keypair_from_seed(seed)
    })
}

/// Proptest strategy for generating individual signatures using the public API
fn individual_signature_bytes() -> impl Strategy<Value = IndividualSignatureBytes> {
    (any::<[u8; 32]>(), any::<[u8; 8]>()).prop_map(|(seed, message)| {
        let seed = Seed::from_bytes(&seed);
        let (secret_key, _public_key) = multi_sig::keypair_from_seed(seed);
        multi_sig::sign(&message, &secret_key)
    })
}

/// Proptest strategy for generating PoPs using the public API
fn pop_bytes() -> impl Strategy<Value = PopBytes> {
    any::<[u8; 32]>().prop_map(|seed| {
        let seed = Seed::from_bytes(&seed);
        let (secret_key, public_key) = multi_sig::keypair_from_seed(seed);
        multi_sig::create_pop(&public_key, &secret_key).expect("Failed to create PoP")
    })
}

/// Proptest strategy for generating combined signatures using the public API
fn combined_signature_bytes() -> impl Strategy<Value = CombinedSignatureBytes> {
    individual_signature_bytes().prop_map(|signature| {
        multi_sig::combine(&[signature]).expect("Failed to combine signatures")
    })
}

fn test_happy_path(
    keys: &[(SecretKeyBytes, PublicKeyBytes)],
    message: &[u8],
) -> (
    Vec<IndividualSignatureBytes>,
    CombinedSignatureBytes,
    Vec<PublicKeyBytes>,
) {
    let pops: CryptoResult<Vec<PopBytes>> = keys
        .iter()
        .map(|(secret_key, public_key)| multi_sig::create_pop(public_key, secret_key))
        .collect();
    let signatures: Vec<IndividualSignatureBytes> = keys
        .iter()
        .map(|(secret_key, _)| multi_sig::sign(message, secret_key))
        .collect();
    let pops = pops.expect("PoP generation failed");
    let signature = multi_sig::combine(&signatures);
    let signature = signature.expect("Signature combination failed");
    let public_keys: Vec<PublicKeyBytes> = keys
        .iter()
        .map(|(_, public_key)| public_key)
        .copied()
        .collect();
    let pop_verification: CryptoResult<()> = public_keys
        .iter()
        .zip(pops)
        .try_for_each(|(public_key, pop)| multi_sig::verify_pop(&pop, public_key));
    let individual_verification: CryptoResult<()> = public_keys
        .iter()
        .zip(signatures.clone())
        .try_for_each(|(public_key, signature)| {
            multi_sig::verify_individual(message, &signature, public_key)
        });
    assert!(pop_verification.is_ok(), "PoP verification failed");
    assert!(
        individual_verification.is_ok(),
        "Individual signature verification failed"
    );
    assert!(
        multi_sig::verify_combined(message, &signature, &public_keys).is_ok(),
        "Signature verification failed"
    );
    (signatures, signature, public_keys)
}

// Slow tests
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 5,
        .. ProptestConfig::default()
    })]

    #[test]
    fn multisig_verification_succeeds(
      keys in proptest::collection::vec(key_pair_bytes(), 1..10),
      message in proptest::collection::vec(any::<u8>(), 0..100),
    ) {
        test_happy_path(&keys, &message);
    }

    #[test]
    fn incorrect_individual_signature_fails(
      keys in key_pair_bytes(),
      message in proptest::collection::vec(any::<u8>(), 0..100),
      evil_signature in individual_signature_bytes()
    ) {
        let (secret_key, public_key) = keys;
        let signature = multi_sig::sign(&message, &secret_key);
        prop_assume!(evil_signature != signature);
        assert_matches!(
            multi_sig::verify_individual(&message, &evil_signature, &public_key),
            Err(CryptoError::SignatureVerification {
                algorithm: AlgorithmId::MultiBls12_381,
                ..
            })
        );
    }

    #[test]
    fn incorrect_pop_fails(
      keys in key_pair_bytes(),
      evil_pop in pop_bytes()
    ) {
        let (secret_key, public_key) = keys;
        let pop = multi_sig::create_pop(&public_key, &secret_key).expect("Failed to create PoP");
        prop_assume!(evil_pop != pop);
        assert_matches!(
            multi_sig::verify_pop(&evil_pop, &public_key),
            Err(CryptoError::PopVerification {
                algorithm: AlgorithmId::MultiBls12_381,
                ..
            })
        );
    }

    #[test]
    fn incorrect_combined_signature_fails(
      keys in proptest::collection::vec(key_pair_bytes(), 1..10),
      message in proptest::collection::vec(any::<u8>(), 0..100),
      evil_signature in combined_signature_bytes()
    ) {
        let (_signatures, signature, public_keys) = test_happy_path(&keys, &message);
        prop_assume!(evil_signature != signature);
        assert_matches!(
            multi_sig::verify_combined(&message, &evil_signature, &public_keys),
            Err(CryptoError::SignatureVerification {
                algorithm: AlgorithmId::MultiBls12_381,
                ..
            })
        );
    }
}

#[test]
fn verify_individual_accepts_a_valid_signature() {
    let rng = &mut reproducible_rng();
    let (secret_key, public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let message = b"test message";
    let signature = multi_sig::sign(message, &secret_key);
    assert!(multi_sig::verify_individual(message, &signature, &public_key).is_ok());
}

#[test]
fn verify_pop_accepts_a_valid_pop() {
    let rng = &mut reproducible_rng();
    let (secret_key, public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let pop = multi_sig::create_pop(&public_key, &secret_key).expect("Failed to create PoP");
    assert!(multi_sig::verify_pop(&pop, &public_key).is_ok());
}

#[test]
fn verify_pop_fails_on_public_key_bytes_with_unset_compressed_flag() {
    let rng = &mut reproducible_rng();
    let (secret_key, public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let pop = multi_sig::create_pop(&public_key, &secret_key).expect("Failed to create PoP");
    let mut public_key_bytes = public_key;
    public_key_bytes.0[G2Bytes::FLAG_BYTE_OFFSET] &= !G2Bytes::COMPRESSED_FLAG;
    match multi_sig::verify_pop(&pop, &public_key_bytes) {
        Err(e) => assert!(e.to_string().contains("Point decoding failed")),
        Ok(_) => panic!("error should have been thrown"),
    }
}

#[test]
fn verify_pop_fails_on_public_key_bytes_not_on_curve() {
    let rng = &mut reproducible_rng();
    let (secret_key, public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let pop = multi_sig::create_pop(&public_key, &secret_key).expect("Failed to create PoP");
    let mut public_key_bytes = public_key;
    // Zero out the bytes, set the compression flag.
    // This represents x = 0, which happens to have no solution on the G2 curve.
    for i in 0..G2Bytes::SIZE {
        public_key_bytes.0[i] = 0;
    }
    public_key_bytes.0[G2Bytes::FLAG_BYTE_OFFSET] |= G2Bytes::COMPRESSED_FLAG;
    match multi_sig::verify_pop(&pop, &public_key_bytes) {
        Err(e) => assert!(e.to_string().contains("Point decoding failed")),
        Ok(_) => panic!("error should have been thrown"),
    }
}

#[test]
fn verify_pop_fails_on_public_key_bytes_not_in_subgroup() {
    let rng = &mut reproducible_rng();
    let (secret_key, public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let pop = multi_sig::create_pop(&public_key, &secret_key).expect("Failed to create PoP");
    let mut public_key_bytes = public_key;
    // By manual rejection sampling, we found an x-coordinate with a
    // solution, which is unlikely to have order r.
    for i in 0..G2Bytes::SIZE {
        public_key_bytes.0[i] = 0;
    }
    public_key_bytes.0[G2Bytes::FLAG_BYTE_OFFSET] |= G2Bytes::COMPRESSED_FLAG;
    public_key_bytes.0[5] = 3;
    match multi_sig::verify_pop(&pop, &public_key_bytes) {
        Err(e) => assert!(e.to_string().contains("Point decoding failed")),
        Ok(_) => panic!("error should have been thrown"),
    }
}

#[test]
fn verify_individual_signature_fails_with_wrong_message() {
    let rng = &mut reproducible_rng();
    let (secret_key, public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let message = b"correct message";
    let wrong_message = b"wrong message";

    let signature = multi_sig::sign(message, &secret_key);

    assert_matches!(
        multi_sig::verify_individual(wrong_message, &signature, &public_key),
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            ..
        })
    );
}

#[test]
fn verify_individual_signature_fails_with_wrong_public_key() {
    let rng = &mut reproducible_rng();
    let (secret_key, _public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let (_other_secret_key, other_public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let message = b"test message";

    let signature = multi_sig::sign(message, &secret_key);

    assert_matches!(
        multi_sig::verify_individual(message, &signature, &other_public_key),
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            ..
        })
    );
}

#[test]
fn verify_combined_signature_fails_with_wrong_message() {
    let rng = &mut reproducible_rng();
    let keys: Vec<_> = (0..3)
        .map(|_| multi_sig::keypair_from_seed(Seed::from_rng(rng)))
        .collect();
    let message = b"correct message";
    let wrong_message = b"wrong message";

    let signatures: Vec<_> = keys
        .iter()
        .map(|(sk, _)| multi_sig::sign(message, sk))
        .collect();
    let combined_sig = multi_sig::combine(&signatures).expect("Failed to combine");
    let public_keys: Vec<_> = keys.iter().map(|(_, pk)| *pk).collect();

    assert_matches!(
        multi_sig::verify_combined(wrong_message, &combined_sig, &public_keys),
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            ..
        })
    );
}

#[test]
fn verify_combined_signature_fails_with_missing_public_key() {
    let rng = &mut reproducible_rng();
    let keys: Vec<_> = (0..3)
        .map(|_| multi_sig::keypair_from_seed(Seed::from_rng(rng)))
        .collect();
    let message = b"test message";

    let signatures: Vec<_> = keys
        .iter()
        .map(|(sk, _)| multi_sig::sign(message, sk))
        .collect();
    let combined_sig = multi_sig::combine(&signatures).expect("Failed to combine");
    // Only include first two public keys, missing the third
    let public_keys: Vec<_> = keys.iter().take(2).map(|(_, pk)| *pk).collect();

    assert_matches!(
        multi_sig::verify_combined(message, &combined_sig, &public_keys),
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            ..
        })
    );
}

#[test]
fn verify_combined_signature_fails_with_extra_public_key() {
    let rng = &mut reproducible_rng();
    let keys: Vec<_> = (0..3)
        .map(|_| multi_sig::keypair_from_seed(Seed::from_rng(rng)))
        .collect();
    let (_, extra_public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let message = b"test message";

    let signatures: Vec<_> = keys
        .iter()
        .map(|(sk, _)| multi_sig::sign(message, sk))
        .collect();
    let combined_sig = multi_sig::combine(&signatures).expect("Failed to combine");
    let mut public_keys: Vec<_> = keys.iter().map(|(_, pk)| *pk).collect();
    public_keys.push(extra_public_key);

    assert_matches!(
        multi_sig::verify_combined(message, &combined_sig, &public_keys),
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            ..
        })
    );
}

#[test]
fn verify_combined_signature_accepts_with_reordered_public_keys() {
    let rng = &mut reproducible_rng();
    let keys: Vec<_> = (0..3)
        .map(|_| multi_sig::keypair_from_seed(Seed::from_rng(rng)))
        .collect();
    let message = b"test message";

    let signatures: Vec<_> = keys
        .iter()
        .map(|(sk, _)| multi_sig::sign(message, sk))
        .collect();
    let combined_sig = multi_sig::combine(&signatures).expect("Failed to combine");
    // Reverse the order of public keys
    let public_keys: Vec<_> = keys.iter().rev().map(|(_, pk)| *pk).collect();

    // BLS signature aggregation is just summation so it works even if
    // the public keys are reordered, as long as they are all included
    assert!(
        multi_sig::verify_combined(message, &combined_sig, &public_keys).is_ok(),
        "Combined signature should verify regardless of public key order (commutative aggregation)"
    );
}

#[test]
fn verify_pop_fails_with_wrong_public_key() {
    let rng = &mut reproducible_rng();
    let (secret_key, public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let (_, other_public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));

    let pop = multi_sig::create_pop(&public_key, &secret_key).expect("Failed to create PoP");

    assert_matches!(
        multi_sig::verify_pop(&pop, &other_public_key),
        Err(CryptoError::PopVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            ..
        })
    );
}

#[test]
fn verify_individual_fails_with_malformed_signature_bytes() {
    let rng = &mut reproducible_rng();
    let (_, public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let message = b"test message";

    // Create malformed signature bytes (point not in subgroup)
    let malformed_sig = non_torsion_g1(rng);
    let malformed_sig_bytes = IndividualSignatureBytes(malformed_sig.serialize());

    match multi_sig::verify_individual(message, &malformed_sig_bytes, &public_key) {
        Ok(_) => panic!("Unexpectedly accepted malformed signature"),
        Err(e) => assert!(e.to_string().contains("Point decoding failed")),
    }
}

#[test]
fn verify_individual_fails_with_malformed_public_key_bytes() {
    let rng = &mut reproducible_rng();
    let (secret_key, _public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let message = b"test message";

    let signature = multi_sig::sign(message, &secret_key);

    // Create malformed public key bytes (point not in subgroup)
    let malformed_pk = non_torsion_g2(rng);
    let malformed_pk_bytes = PublicKeyBytes(malformed_pk.serialize());

    match multi_sig::verify_individual(message, &signature, &malformed_pk_bytes) {
        Ok(_) => panic!("Unexpectedly accepted malformed public key"),
        Err(e) => assert!(e.to_string().contains("Point decoding failed")),
    }
}

#[test]
fn verify_combined_fails_with_malformed_signature_bytes() {
    let rng = &mut reproducible_rng();
    let keys: Vec<_> = (0..2)
        .map(|_| multi_sig::keypair_from_seed(Seed::from_rng(rng)))
        .collect();
    let public_key_bytes: Vec<_> = keys.iter().map(|(_, pk)| *pk).collect();
    let message = b"test message";

    // Create malformed combined signature bytes (point not in subgroup)
    let malformed_sig = non_torsion_g1(rng);
    let malformed_sig_bytes = CombinedSignatureBytes(malformed_sig.serialize());

    match multi_sig::verify_combined(message, &malformed_sig_bytes, &public_key_bytes) {
        Ok(_) => panic!("Unexpectedly accepted malformed combined signature"),
        Err(e) => assert!(e.to_string().contains("Point decoding failed")),
    }
}

#[test]
fn verify_combined_fails_with_malformed_public_key_bytes() {
    let rng = &mut reproducible_rng();
    let keys: Vec<_> = (0..2)
        .map(|_| multi_sig::keypair_from_seed(Seed::from_rng(rng)))
        .collect();
    let message = b"test message";

    let signatures: Vec<_> = keys
        .iter()
        .map(|(sk, _)| multi_sig::sign(message, sk))
        .collect();
    let combined_sig = multi_sig::combine(&signatures).expect("Failed to combine");

    // Create public key list with one malformed key
    let malformed_pk = non_torsion_g2(rng);
    let public_key_bytes = vec![
        keys[0].1,
        PublicKeyBytes(malformed_pk.serialize()), // malformed
    ];

    match multi_sig::verify_combined(message, &combined_sig, &public_key_bytes) {
        Ok(_) => panic!("Unexpectedly accepted malformed public key"),
        Err(e) => assert!(e.to_string().contains("Point decoding failed")),
    }
}

#[test]
fn combine_signature_fails_with_malformed_individual_signature_bytes() {
    let rng = &mut reproducible_rng();
    let (secret_key, _) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let message = b"test message";

    let valid_sig = multi_sig::sign(message, &secret_key);

    // Create malformed signature bytes (point not in subgroup)
    let malformed_sig = non_torsion_g1(rng);
    let malformed_sig_bytes = IndividualSignatureBytes(malformed_sig.serialize());

    let signatures = vec![valid_sig, malformed_sig_bytes];

    match multi_sig::combine(&signatures) {
        Ok(_) => panic!("Unexpectedly accepted malformed signature in combine"),
        Err(e) => assert!(e.to_string().contains("Point decoding failed")),
    }
}

#[test]
fn verify_pop_fails_with_malformed_pop_bytes() {
    let rng = &mut reproducible_rng();
    let (_, public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));

    // Create malformed PoP bytes (point not in subgroup)
    let malformed_pop = non_torsion_g1(rng);
    let malformed_pop_bytes = PopBytes(malformed_pop.serialize());

    match multi_sig::verify_pop(&malformed_pop_bytes, &public_key) {
        Ok(_) => panic!("Unexpectedly accepted malformed PoP"),
        Err(e) => assert!(e.to_string().contains("Point decoding failed")),
    }
}

#[test]
fn verify_combined_with_empty_public_keys_verifies_identity() {
    let message = b"test message";

    // Combined signature with no signers is the identity
    let combined_sig = multi_sig::combine(&[]).expect("Failed to combine empty");
    let empty_public_keys: Vec<PublicKeyBytes> = vec![];

    // Verifying identity signature with empty public keys list
    // This is a degenerate case - documenting the behavior
    let result = multi_sig::verify_combined(message, &combined_sig, &empty_public_keys);

    // The identity signature with empty public keys should verify
    // because: e(identity, g2) = e(H(m), identity) = 1
    assert!(
        result.is_ok(),
        "Empty signature with empty public keys should verify (identity case)"
    );
}

#[test]
fn verify_combined_identity_signature_fails_with_nonempty_public_keys() {
    let rng = &mut reproducible_rng();
    let (_, public_key) = multi_sig::keypair_from_seed(Seed::from_rng(rng));
    let message = b"test message";

    // Identity signature (no signers)
    let combined_sig = multi_sig::combine(&[]).expect("Failed to combine empty");
    let public_keys = vec![public_key];

    assert_matches!(
        multi_sig::verify_combined(message, &combined_sig, &public_keys),
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            ..
        })
    );
}
