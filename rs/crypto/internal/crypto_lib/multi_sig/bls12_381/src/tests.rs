//! Tests for multisignatures

use crate::{
    api, crypto as multi_crypto, types as multi_types, types::CombinedSignature,
    types::IndividualSignature, types::PublicKey, types::SecretKey, types::SecretKeyBytes,
    types::arbitrary,
};
use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng};

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

fn check_multi_signature_verifies(keys: &[(SecretKey, PublicKey)], message: &[u8]) {
    let signatures: Vec<IndividualSignature> = keys
        .iter()
        .map(|(secret_key, _)| multi_crypto::sign_message(message, secret_key))
        .collect();
    let signature: CombinedSignature = multi_crypto::combine_signatures(&signatures);
    let public_keys: Vec<PublicKey> = keys
        .iter()
        .map(|(_, public_key)| public_key)
        .cloned()
        .collect();
    assert!(multi_crypto::verify_combined_message_signature(
        message,
        &signature,
        &public_keys
    ));
}

/// This checks that the output of operations is stable.
mod stability {
    use super::*;
    use crate::types::PublicKeyBytes;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn message_to_g1() {
        assert_eq!(
            hex::encode(
                multi_crypto::hash_message_to_g1(b"abc")
                    .to_affine()
                    .serialize()
            ),
            "a13964470939e806ca5ca96b348ab13af3f06a7d9dc4e8a0cf20d8a81a6d8f5a692c67424228d45d749e7832d27cea79"
        );
    }
    #[test]
    fn public_key_to_g1() {
        let mut csprng = ChaCha20Rng::seed_from_u64(42);
        let (_secret_key, public_key) = multi_crypto::keypair_from_rng(&mut csprng);
        let public_key_bytes = PublicKeyBytes::from(&public_key);
        assert_eq!(
            hex::encode(
                multi_crypto::hash_public_key_to_g1(&public_key_bytes.0[..])
                    .to_affine()
                    .serialize()
            ),
            "b02fd0d54faab7498924d7e230f84b00519ea7f3846cd30f82b149c1f172ad79ee68adb2ea2fc8a2d40ffdf3fd5df02a"
        );
    }

    #[test]
    fn secret_key_from_fixed_rng() {
        let mut csprng = ChaCha20Rng::seed_from_u64(9000);
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(&mut csprng);
        let secret_key_bytes = SecretKeyBytes::from(&secret_key);

        assert_eq!(
            hex::encode(serde_cbor::to_vec(&secret_key_bytes).unwrap()),
            "582020bfd7f85be7ce1f54ea1b0d750ae3324ab7897fde3235e189ec697f0fade983"
        );

        let public_key_bytes = PublicKeyBytes::from(&public_key);

        assert_eq!(
            hex::encode(serde_cbor::to_vec(&public_key_bytes).unwrap()),
            "5860805197d0cf9a60da1acc5750be523048f14622dadef70e7c2648b674181555881092e20e26440f6ad277380b33ea84f412f99c5fe4c993198e5c5233e39d1dd55656add17bdbf65d889fec7cc05befb0466bc9ad1b55bb57539c4f9d74c43c5a"
        )
    }
}

mod basic_functionality {
    use super::*;
    use crate::types::PublicKeyBytes;
    use proptest::prelude::*;
    use proptest::std_facade::HashSet;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Slow tests
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4,
            .. ProptestConfig::default()
        })]

        #[test]
        fn keypair_from_seed_works(seed: [u64; 4]) {
            multi_crypto::keypair_from_seed(seed);
        }

        #[test]
        fn keypair_from_rng_works(seed: [u8; 32]) {
            let rng = &mut ChaCha20Rng::from_seed(seed);
            multi_crypto::keypair_from_rng(rng);
        }
    }

    /// Verifies that different messages yield different points on G1 when
    /// hashed, with high probability
    #[test]
    fn test_distinct_messages_yield_distinct_hashes() {
        let number_of_messages = 100;
        let points: HashSet<_> = (0..number_of_messages as u32)
            .map(|number| {
                let bytes = multi_crypto::hash_message_to_g1(&number.to_be_bytes()[..])
                    .to_affine()
                    .serialize();
                // It suffices to prove that the first 32 bytes are distinct.  More requires a
                // custom hash implementation.
                let mut hashable = [0u8; 32];
                hashable.copy_from_slice(&bytes[0..32]);
                hashable
            })
            .collect();
        assert_eq!(number_of_messages, points.len(), "Collisions found");
    }
    /// Verifies that different public keys yield different points on G1 when
    /// hashed, with high probability
    #[test]
    fn test_distinct_public_keys_yield_distinct_hashes() {
        let number_of_public_keys = 100;
        let rng = &mut reproducible_rng();
        let points: HashSet<_> = (0..number_of_public_keys as u64)
            .map(|_| {
                let (_secret_key, public_key) = multi_crypto::keypair_from_rng(rng);
                let public_key_bytes = PublicKeyBytes::from(&public_key);
                let g1 = multi_crypto::hash_public_key_to_g1(&public_key_bytes.0[..]).to_affine();
                let bytes = g1.serialize();
                // It suffices to prove that the first 32 bytes are distinct.  More requires a
                // custom hash implementation.
                let mut hashable = [0u8; 32];
                hashable.copy_from_slice(&bytes[0..32]);
                hashable
            })
            .collect();
        assert_eq!(number_of_public_keys, points.len(), "Collisions found");
    }
}

mod advanced_functionality {
    use super::*;
    use crate::types::{PopBytes, PublicKeyBytes};
    use ic_crypto_internal_types::curves::bls12_381::G2Bytes;
    use proptest::prelude::*;

    #[test]
    fn zero_signatures_yields_signature_zero() {
        assert_eq!(
            multi_crypto::combine_signatures(&[]),
            multi_types::CombinedSignature::identity()
        );
    }

    #[test]
    fn single_point_signature_verifies() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let point = multi_crypto::hash_message_to_g1(b"abba");
        let signature = multi_crypto::sign_point(&point, &secret_key);
        assert!(multi_crypto::verify_point(
            &point.to_affine(),
            &signature,
            &public_key
        ));
    }

    #[test]
    fn individual_multi_signature_contribution_verifies() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let message = b"bjork";
        let signature = multi_crypto::sign_message(message, &secret_key);
        assert!(multi_crypto::verify_individual_message_signature(
            message,
            &signature,
            &public_key
        ));
    }

    #[test]
    fn pop_verifies() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let pop = multi_crypto::create_pop(&public_key, &secret_key);
        assert!(multi_crypto::verify_pop(&pop, &public_key));
    }

    #[test]
    fn verify_pop_throws_error_on_public_key_bytes_with_unset_compressed_flag() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let pop = multi_crypto::create_pop(&public_key, &secret_key);
        let pop_bytes = PopBytes::from(&pop);
        let mut public_key_bytes = PublicKeyBytes::from(&public_key);
        public_key_bytes.0[G2Bytes::FLAG_BYTE_OFFSET] &= !G2Bytes::COMPRESSED_FLAG;
        match api::verify_pop(&pop_bytes, &public_key_bytes) {
            Err(e) => assert!(e.to_string().contains("Point decoding failed")),
            Ok(_) => panic!("error should have been thrown"),
        }
    }

    #[test]
    fn verify_pop_throws_error_on_public_key_bytes_not_on_curve() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let pop = multi_crypto::create_pop(&public_key, &secret_key);
        let pop_bytes = PopBytes::from(&pop);
        let mut public_key_bytes = PublicKeyBytes::from(&public_key);
        // Zero out the bytes, set the compression flag.
        // This represents x = 0, which happens to have no solution
        // on the G2 curve.
        for i in 0..G2Bytes::SIZE {
            public_key_bytes.0[i] = 0;
        }
        public_key_bytes.0[G2Bytes::FLAG_BYTE_OFFSET] |= G2Bytes::COMPRESSED_FLAG;
        match api::verify_pop(&pop_bytes, &public_key_bytes) {
            Err(e) => assert!(e.to_string().contains("Point decoding failed")),
            Ok(_) => panic!("error should have been thrown"),
        }
    }

    #[test]
    fn verify_pop_throws_error_on_public_key_bytes_not_in_subgroup() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let pop = multi_crypto::create_pop(&public_key, &secret_key);
        let pop_bytes = PopBytes::from(&pop);
        let mut public_key_bytes = PublicKeyBytes::from(&public_key);
        // By manual rejection sampling, we found an x-coordinate with a
        // solution, which is unlikely to have order r.
        for i in 0..G2Bytes::SIZE {
            public_key_bytes.0[i] = 0;
        }
        public_key_bytes.0[G2Bytes::FLAG_BYTE_OFFSET] |= G2Bytes::COMPRESSED_FLAG;
        public_key_bytes.0[5] = 3;
        match api::verify_pop(&pop_bytes, &public_key_bytes) {
            Err(e) => assert!(e.to_string().contains("Point decoding failed")),
            Ok(_) => panic!("error should have been thrown"),
        }
    }

    #[test]
    fn double_signature_verifies() {
        let keys = [
            multi_crypto::keypair_from_seed([1, 2, 3, 4]),
            multi_crypto::keypair_from_seed([5, 6, 7, 8]),
        ];
        check_multi_signature_verifies(&keys, b"abba");
    }

    // Slow tests
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 2,
            .. ProptestConfig::default()
        })]
        #[test]
        fn multisig_verification_succeeds(
          keys in proptest::collection::vec(arbitrary::key_pair(), 1..10),
          message in proptest::collection::vec(any::<u8>(), 0..100),
        ) {
            check_multi_signature_verifies(&keys, &message);
        }
    }
}

mod verification_tests {
    use super::*;
    use crate::types::{
        CombinedSignatureBytes, IndividualSignatureBytes, PopBytes, PublicKeyBytes,
    };

    #[test]
    fn individual_signature_fails_with_wrong_message() {
        let rng = &mut reproducible_rng();
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(rng);
        let message = b"correct message";
        let wrong_message = b"wrong message";

        let signature = multi_crypto::sign_message(message, &secret_key);

        assert!(
            !multi_crypto::verify_individual_message_signature(
                wrong_message,
                &signature,
                &public_key
            ),
            "Signature should not verify with wrong message"
        );
    }

    #[test]
    fn individual_signature_fails_with_wrong_public_key() {
        let rng = &mut reproducible_rng();
        let (secret_key, _public_key) = multi_crypto::keypair_from_rng(rng);
        let (_other_secret_key, other_public_key) = multi_crypto::keypair_from_rng(rng);
        let message = b"test message";

        let signature = multi_crypto::sign_message(message, &secret_key);

        assert!(
            !multi_crypto::verify_individual_message_signature(
                message,
                &signature,
                &other_public_key
            ),
            "Signature should not verify with wrong public key"
        );
    }

    #[test]
    fn combined_signature_fails_with_wrong_message() {
        let rng = &mut reproducible_rng();
        let keys: Vec<_> = (0..3)
            .map(|_| multi_crypto::keypair_from_rng(rng))
            .collect();
        let message = b"correct message";
        let wrong_message = b"wrong message";

        let signatures: Vec<_> = keys
            .iter()
            .map(|(sk, _)| multi_crypto::sign_message(message, sk))
            .collect();
        let combined_sig = multi_crypto::combine_signatures(&signatures);
        let public_keys: Vec<_> = keys.iter().map(|(_, pk)| pk.clone()).collect();

        assert!(
            !multi_crypto::verify_combined_message_signature(
                wrong_message,
                &combined_sig,
                &public_keys
            ),
            "Combined signature should not verify with wrong message"
        );
    }

    #[test]
    fn combined_signature_fails_with_missing_public_key() {
        let rng = &mut reproducible_rng();
        let keys: Vec<_> = (0..3)
            .map(|_| multi_crypto::keypair_from_rng(rng))
            .collect();
        let message = b"test message";

        let signatures: Vec<_> = keys
            .iter()
            .map(|(sk, _)| multi_crypto::sign_message(message, sk))
            .collect();
        let combined_sig = multi_crypto::combine_signatures(&signatures);
        // Only include first two public keys, missing the third
        let public_keys: Vec<_> = keys.iter().take(2).map(|(_, pk)| pk.clone()).collect();

        assert!(
            !multi_crypto::verify_combined_message_signature(message, &combined_sig, &public_keys),
            "Combined signature should not verify with missing public key"
        );
    }

    #[test]
    fn combined_signature_fails_with_extra_public_key() {
        let rng = &mut reproducible_rng();
        let keys: Vec<_> = (0..3)
            .map(|_| multi_crypto::keypair_from_rng(rng))
            .collect();
        let (_, extra_public_key) = multi_crypto::keypair_from_rng(rng);
        let message = b"test message";

        let signatures: Vec<_> = keys
            .iter()
            .map(|(sk, _)| multi_crypto::sign_message(message, sk))
            .collect();
        let combined_sig = multi_crypto::combine_signatures(&signatures);
        let mut public_keys: Vec<_> = keys.iter().map(|(_, pk)| pk.clone()).collect();
        public_keys.push(extra_public_key);

        assert!(
            !multi_crypto::verify_combined_message_signature(message, &combined_sig, &public_keys),
            "Combined signature should not verify with extra public key"
        );
    }

    #[test]
    fn combined_signature_verifies_with_reordered_public_keys() {
        let rng = &mut reproducible_rng();
        let keys: Vec<_> = (0..3)
            .map(|_| multi_crypto::keypair_from_rng(rng))
            .collect();
        let message = b"test message";

        let signatures: Vec<_> = keys
            .iter()
            .map(|(sk, _)| multi_crypto::sign_message(message, sk))
            .collect();
        let combined_sig = multi_crypto::combine_signatures(&signatures);
        // Reverse the order of public keys
        let public_keys: Vec<_> = keys.iter().rev().map(|(_, pk)| pk.clone()).collect();

        // BLS signature aggregation is just summation so it works even if
        // the public keys are reordered, as long as they are all included

        assert!(
            multi_crypto::verify_combined_message_signature(message, &combined_sig, &public_keys),
            "Combined signature should verify regardless of public key order (commutative aggregation)"
        );
    }

    #[test]
    fn pop_fails_with_wrong_public_key() {
        let rng = &mut reproducible_rng();
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(rng);
        let (_, other_public_key) = multi_crypto::keypair_from_rng(rng);

        let pop = multi_crypto::create_pop(&public_key, &secret_key);

        assert!(
            !multi_crypto::verify_pop(&pop, &other_public_key),
            "PoP should not verify with wrong public key"
        );
    }

    #[test]
    fn verify_individual_fails_with_malformed_signature_bytes() {
        let rng = &mut reproducible_rng();
        let (_, public_key) = multi_crypto::keypair_from_rng(rng);
        let public_key_bytes = PublicKeyBytes::from(&public_key);
        let message = b"test message";

        // Create malformed signature bytes (point not in subgroup)
        let malformed_sig = non_torsion_g1(rng);
        let malformed_sig_bytes = IndividualSignatureBytes(malformed_sig.serialize());

        match api::verify_individual(message, &malformed_sig_bytes, &public_key_bytes) {
            Ok(_) => panic!("Unexpectedly accepted malformed signature"),
            Err(e) => assert!(e.to_string().contains("Point decoding failed")),
        }
    }

    #[test]
    fn verify_individual_fails_with_malformed_public_key_bytes() {
        let rng = &mut reproducible_rng();
        let (secret_key, _public_key) = multi_crypto::keypair_from_rng(rng);
        let message = b"test message";

        let signature = multi_crypto::sign_message(message, &secret_key);
        let signature_bytes = IndividualSignatureBytes::from(&signature);

        // Create malformed public key bytes (point not in subgroup)
        let malformed_pk = non_torsion_g2(rng);
        let malformed_pk_bytes = PublicKeyBytes(malformed_pk.serialize());

        match api::verify_individual(message, &signature_bytes, &malformed_pk_bytes) {
            Ok(_) => panic!("Unexpectedly accepted malformed public key"),
            Err(e) => assert!(e.to_string().contains("Point decoding failed")),
        }
    }

    #[test]
    fn verify_combined_fails_with_malformed_signature_bytes() {
        let rng = &mut reproducible_rng();
        let keys: Vec<_> = (0..2)
            .map(|_| multi_crypto::keypair_from_rng(rng))
            .collect();
        let public_key_bytes: Vec<_> = keys
            .iter()
            .map(|(_, pk)| PublicKeyBytes::from(pk))
            .collect();
        let message = b"test message";

        // Create malformed combined signature bytes (point not in subgroup)
        let malformed_sig = non_torsion_g1(rng);
        let malformed_sig_bytes = CombinedSignatureBytes(malformed_sig.serialize());

        match api::verify_combined(message, &malformed_sig_bytes, &public_key_bytes) {
            Ok(_) => panic!("Unexpectedly accepted malformed combined signature"),
            Err(e) => assert!(e.to_string().contains("Point decoding failed")),
        }
    }

    #[test]
    fn verify_combined_fails_with_malformed_public_key_bytes() {
        let rng = &mut reproducible_rng();
        let keys: Vec<_> = (0..2)
            .map(|_| multi_crypto::keypair_from_rng(rng))
            .collect();
        let message = b"test message";

        let signatures: Vec<_> = keys
            .iter()
            .map(|(sk, _)| multi_crypto::sign_message(message, sk))
            .collect();
        let combined_sig = multi_crypto::combine_signatures(&signatures);
        let combined_sig_bytes = CombinedSignatureBytes::from(&combined_sig);

        // Create public key list with one malformed key
        let malformed_pk = non_torsion_g2(rng);
        let public_key_bytes = vec![
            PublicKeyBytes::from(&keys[0].1),
            PublicKeyBytes(malformed_pk.serialize()), // malformed
        ];

        match api::verify_combined(message, &combined_sig_bytes, &public_key_bytes) {
            Ok(_) => panic!("Unexpectedly accepted malformed public key"),
            Err(e) => assert!(e.to_string().contains("Point decoding failed")),
        }
    }

    #[test]
    fn combine_fails_with_malformed_individual_signature_bytes() {
        let rng = &mut reproducible_rng();
        let (secret_key, _) = multi_crypto::keypair_from_rng(rng);
        let message = b"test message";

        let valid_sig = multi_crypto::sign_message(message, &secret_key);
        let valid_sig_bytes = IndividualSignatureBytes::from(&valid_sig);

        // Create malformed signature bytes (point not in subgroup)
        let malformed_sig = non_torsion_g1(rng);
        let malformed_sig_bytes = IndividualSignatureBytes(malformed_sig.serialize());

        let signatures = vec![valid_sig_bytes, malformed_sig_bytes];

        match api::combine(&signatures) {
            Ok(_) => panic!("Unexpectedly accepted malformed signature in combine"),
            Err(e) => assert!(e.to_string().contains("Point decoding failed")),
        }
    }

    #[test]
    fn verify_pop_fails_with_malformed_pop_bytes() {
        let rng = &mut reproducible_rng();
        let (_, public_key) = multi_crypto::keypair_from_rng(rng);
        let public_key_bytes = PublicKeyBytes::from(&public_key);

        // Create malformed PoP bytes (point not in subgroup)
        let malformed_pop = non_torsion_g1(rng);
        let malformed_pop_bytes = PopBytes(malformed_pop.serialize());

        match api::verify_pop(&malformed_pop_bytes, &public_key_bytes) {
            Ok(_) => panic!("Unexpectedly accepted malformed PoP"),
            Err(e) => assert!(e.to_string().contains("Point decoding failed")),
        }
    }

    #[test]
    fn verify_combined_with_empty_public_keys_verifies_identity() {
        let message = b"test message";

        // Combined signature with no signers is the identity
        let combined_sig = multi_crypto::combine_signatures(&[]);
        let combined_sig_bytes = CombinedSignatureBytes::from(&combined_sig);
        let empty_public_keys: Vec<PublicKeyBytes> = vec![];

        // Verifying identity signature with empty public keys list
        // This is a degenerate case - documenting the behavior
        let result = api::verify_combined(message, &combined_sig_bytes, &empty_public_keys);

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
        let (_, public_key) = multi_crypto::keypair_from_rng(rng);
        let message = b"test message";

        // Identity signature (no signers)
        let combined_sig = multi_crypto::combine_signatures(&[]);
        let combined_sig_bytes = CombinedSignatureBytes::from(&combined_sig);
        let public_keys = vec![PublicKeyBytes::from(&public_key)];

        let result = api::verify_combined(message, &combined_sig_bytes, &public_keys);
        assert!(
            result.is_err(),
            "Identity signature should not verify with non-empty public keys"
        );
    }
}
