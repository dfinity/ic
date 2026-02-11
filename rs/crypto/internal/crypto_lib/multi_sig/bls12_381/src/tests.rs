//! Unit tests for multisignature internals.
//!
//! These tests specifically exercise internal (non-public) APIs of this crate.
//! Tests for the public API are in tests/api_tests.rs.

use crate::{crypto as multi_crypto, types as multi_types, types::SecretKeyBytes};
use ic_crypto_internal_seed::Seed;
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
        let seed = Seed::from_bytes(&[42u8]);
        let (_secret_key, public_key) = multi_crypto::keypair_from_rng(&mut seed.into_rng());
        let public_key_bytes = PublicKeyBytes::from(&public_key);
        assert_eq!(
            hex::encode(
                multi_crypto::hash_public_key_to_g1(&public_key_bytes.0[..])
                    .to_affine()
                    .serialize()
            ),
            "a09ed55a4473ee51bc413640f84e701aa3707a5d78b5b08d35112503fa986ac7a8a4b4eebe0d3a8947a477924249a237"
        );
    }

    /// Unit test because: accesses SecretKeyBytes.0 which is pub(crate).
    #[test]
    fn secret_key_from_fixed_seed() {
        let seed = Seed::from_bytes(&[42u8]);
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(&mut seed.into_rng());
        let secret_key_bytes = SecretKeyBytes::from(&secret_key);

        assert_eq!(
            hex::encode(serde_cbor::to_vec(&secret_key_bytes).unwrap()),
            "582073481d06d01187a77fe0752b5d8ddffda57f1bbda3bd455b25a661290beafa49"
        );

        let public_key_bytes = PublicKeyBytes::from(&public_key);

        assert_eq!(
            hex::encode(serde_cbor::to_vec(&public_key_bytes).unwrap()),
            "5860a0006d9c7a98d3267552f132cf2ddc9ebd13ff5913dbb02d756275edb9bdedb474ac511e911f544d5a892ede57db614f035c72f5c11f95ca1417be429ad2a5d7c4e4cd3a03fffb106d4e8fcc847955f11913a46cc65a9a8e012f61df9aa8b9bd"
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
}
