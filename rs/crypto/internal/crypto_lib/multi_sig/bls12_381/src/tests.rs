//! Unit tests for multisignature internals.
//!
//! These tests specifically exercise internal (non-public) APIs of this crate.
//! Tests for the public API are in tests/api_tests.rs.

use crate::{crypto as multi_crypto, types as multi_types, types::SecretKeyBytes, types::arbitrary};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

/// Tests for stability of internal cryptographic operations.
///
/// These tests verify that the output of internal hash functions and key
/// derivation remains stable across versions. They must remain unit tests
/// because they test internal functions not exposed in the public API.
mod stability {
    use super::*;
    use crate::types::PublicKeyBytes;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// This test checks that key generation is stable.
    ///
    /// Unit test because: accesses SecretKeyBytes.0 which is pub(crate).
    #[test]
    fn bls12_key_generation_is_stable() {
        let mut csprng = ChaCha20Rng::seed_from_u64(42);
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(&mut csprng);
        let secret_key_bytes = SecretKeyBytes::from(&secret_key);
        let public_key_bytes = PublicKeyBytes::from(&public_key);

        assert_eq!(
            hex::encode(secret_key_bytes.0.expose_secret()),
            "55f292a9a75dc429aa86f5fb84756558c5210a2de4a8d4d3b4207beb0d419072"
        );
        assert_eq!(
            hex::encode(public_key_bytes.0),
            "b5077d187db1ff824d246bc7c311f909047e20375dc836087da1d7e5c3add0e8fc838af6aaa7373b41824c9bd080f47c0a50e3cdf06bf1cb4061a6cc6ab1802acce096906cece92e7487a29e89a187b618e6af1292515202640795f3359161c2"
        );
    }

    /// Unit test because: tests internal hash_message_to_g1 function not in public API.
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

    /// Unit test because: tests internal hash_public_key_to_g1 function not in public API.
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

    /// Unit test because: accesses SecretKeyBytes.0 which is pub(crate).
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

/// Tests for basic internal functionality.
///
/// These tests verify internal key generation and hashing functions that are
/// not part of the public API.
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

        /// Unit test because: tests internal keypair_from_seed which is #[cfg(test)] only.
        #[test]
        fn keypair_from_seed_works(seed: [u64; 4]) {
            multi_crypto::keypair_from_seed(seed);
        }

        /// Unit test because: tests internal keypair_from_rng that returns internal
        /// types (SecretKey, PublicKey) rather than public types (SecretKeyBytes, PublicKeyBytes).
        #[test]
        fn keypair_from_rng_works(seed: [u8; 32]) {
            let rng = &mut ChaCha20Rng::from_seed(seed);
            multi_crypto::keypair_from_rng(rng);
        }
    }

    /// Unit test because: tests internal hash_message_to_g1 function not in public API.
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

    /// Unit test because: tests internal hash_public_key_to_g1 function not in public API.
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

/// Tests for advanced internal functionality.
///
/// These tests verify internal cryptographic operations like point signing
/// and signature combination that use internal types.
mod advanced_functionality {
    use super::*;
    use crate::types::{CombinedSignature, IndividualSignature, PublicKey, SecretKey};
    use proptest::prelude::*;

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

    /// Unit test because: tests internal combine_signatures and CombinedSignature::identity()
    /// which are not in the public API (public API returns CombinedSignatureBytes).
    #[test]
    fn zero_signatures_yields_signature_zero() {
        assert_eq!(
            multi_crypto::combine_signatures(&[]),
            multi_types::CombinedSignature::identity()
        );
    }

    /// Unit test because: tests internal sign_point and verify_point functions
    /// that operate on G1Projective points, not exposed in the public API.
    #[test]
    fn single_point_signature_verifies() {
        let rng = &mut reproducible_rng();
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(rng);
        let point = multi_crypto::hash_message_to_g1(b"abba");
        let signature = multi_crypto::sign_point(&point, &secret_key);
        assert!(multi_crypto::verify_point(
            &point.to_affine(),
            &signature,
            &public_key
        ));
    }

    /// Unit test because: tests internal sign_message/verify_individual_message_signature
    /// that operate on internal types (SecretKey, PublicKey, IndividualSignature).
    #[test]
    fn individual_multi_signature_contribution_verifies() {
        let rng = &mut reproducible_rng();
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(rng);
        let message = b"bjork";
        let signature = multi_crypto::sign_message(message, &secret_key);
        assert!(multi_crypto::verify_individual_message_signature(
            message,
            &signature,
            &public_key
        ));
    }

    /// Unit test because: tests internal create_pop/verify_pop that operate on
    /// internal types (Pop, PublicKey).
    #[test]
    fn pop_verifies() {
        let rng = &mut reproducible_rng();
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(rng);
        let pop = multi_crypto::create_pop(&public_key, &secret_key);
        assert!(multi_crypto::verify_pop(&pop, &public_key));
    }

    /// Unit test because: tests internal verify_combined_message_signature with
    /// internal types (SecretKey, PublicKey).
    #[test]
    fn double_signature_verifies() {
        let rng = &mut reproducible_rng();
        let keys = [
            multi_crypto::keypair_from_rng(rng),
            multi_crypto::keypair_from_rng(rng),
        ];
        check_multi_signature_verifies(&keys, b"abba");
    }

    // Slow tests
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 2,
            .. ProptestConfig::default()
        })]

        /// Unit test because: uses arbitrary::key_pair() which returns internal types
        /// (SecretKey, PublicKey) rather than public types.
        #[test]
        fn multisig_verification_succeeds(
          keys in proptest::collection::vec(arbitrary::key_pair(), 1..10),
          message in proptest::collection::vec(any::<u8>(), 0..100),
        ) {
            check_multi_signature_verifies(&keys, &message);
        }
    }
}
