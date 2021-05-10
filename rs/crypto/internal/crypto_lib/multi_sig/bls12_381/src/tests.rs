//! Tests for multisignatures

use crate::{
    api, crypto as multi_crypto, test_utils as multi_test_utils, types as multi_types,
    types::arbitrary,
};
use group::CurveProjective;
use ic_crypto_internal_bls12381_common as bls;
use ic_crypto_internal_test_vectors::unhex::hex_to_48_bytes;

/// This checks that the output of operations is stable.
mod stability {
    use super::*;
    use crate::types::PublicKeyBytes;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn message_to_g1() {
        assert_eq!(
            bls::g1_to_bytes(&multi_crypto::hash_message_to_g1(b"abc"))[..],
            hex_to_48_bytes(
                "a13964470939e806ca5ca96b348ab13af3f06a7d9dc4e8a0cf20d8a81a6d8f5a692c67424228d45d749e7832d27cea79"
            )[..]
        );
    }
    #[test]
    fn public_key_to_g1() {
        let mut csprng = ChaCha20Rng::seed_from_u64(42);
        let (_secret_key, public_key) = multi_crypto::keypair_from_rng(&mut csprng);
        let public_key_bytes = PublicKeyBytes::from(public_key);
        assert_eq!(
            bls::g1_to_bytes(&multi_crypto::hash_public_key_to_g1(&public_key_bytes.0[..]))[..],
            hex_to_48_bytes(
                "8b6db127df1bdc6e0a78c7b1e9539d9c7720cf10f07c5f408d06ad8000538f556f546949c94329a0164fbdc5d8eb1d33"
            )[..]
        );
    }
}

mod basic_functionality {
    use super::*;
    use crate::types::PublicKeyBytes;
    use ic_crypto_internal_bls12381_common::g1_to_bytes;
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
            let mut rng = ChaCha20Rng::from_seed(seed);
            multi_crypto::keypair_from_rng(&mut rng);
        }
    }

    /// Verifies that different messages yield different points on G1 when
    /// hashed, with high probability
    #[test]
    fn test_distinct_messages_yield_distinct_hashes() {
        let number_of_messages = 100;
        let points: HashSet<_> = (0..number_of_messages as u32)
            .map(|number| {
                let g1 = multi_crypto::hash_message_to_g1(&number.to_be_bytes()[..]);
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
    /// Verifies that different public keys yield different points on G1 when
    /// hashed, with high probability
    #[test]
    fn test_distinct_public_keys_yield_distinct_hashes() {
        let number_of_public_keys = 100;
        let mut csprng = ChaCha20Rng::seed_from_u64(42);
        let points: HashSet<_> = (0..number_of_public_keys as u64)
            .map(|_| {
                let (_secret_key, public_key) = multi_crypto::keypair_from_rng(&mut csprng);
                let public_key_bytes = PublicKeyBytes::from(public_key);
                let g1 = multi_crypto::hash_public_key_to_g1(&public_key_bytes.0[..]);
                let bytes = g1_to_bytes(&g1);
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
    use ic_crypto_internal_types::curves::bls12_381::G2;
    use proptest::prelude::*;

    #[test]
    fn zero_signatures_yields_signature_zero() {
        assert_eq!(
            multi_crypto::combine_signatures(&[]),
            multi_types::CombinedSignature::zero()
        );
    }

    #[test]
    fn single_point_signature_verifies() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let point = multi_crypto::hash_message_to_g1(b"abba");
        multi_test_utils::single_point_signature_verifies(secret_key, public_key, point);
    }

    #[test]
    fn individual_multi_signature_contribution_verifies() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        multi_test_utils::individual_multi_signature_contribution_verifies(
            secret_key, public_key, b"abba",
        );
    }
    #[test]
    fn pop_verifies() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let pop = multi_crypto::create_pop(public_key, secret_key);
        assert!(multi_crypto::verify_pop(pop, public_key));
    }

    #[test]
    fn verify_pop_throws_error_on_public_key_bytes_with_unset_compressed_flag() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let pop = multi_crypto::create_pop(public_key, secret_key);
        let pop_bytes = PopBytes::from(pop);
        let mut public_key_bytes = PublicKeyBytes::from(public_key);
        public_key_bytes.0[G2::FLAG_BYTE_OFFSET] &= !G2::COMPRESSED_FLAG;
        match api::verify_pop(pop_bytes, public_key_bytes) {
            Err(e) => assert!(e
                .to_string()
                .contains("encoding has unexpected compression mode")),
            Ok(_) => panic!("error should have been thrown"),
        }
    }

    #[test]
    fn verify_pop_throws_error_on_public_key_bytes_not_on_curve() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let pop = multi_crypto::create_pop(public_key, secret_key);
        let pop_bytes = PopBytes::from(pop);
        let mut public_key_bytes = PublicKeyBytes::from(public_key);
        // Zero out the bytes, set the compression flag.
        // This represents x = 0, which happens to have no solution
        // on the G2 curve.
        for i in 0..G2::SIZE {
            public_key_bytes.0[i] = 0;
        }
        public_key_bytes.0[G2::FLAG_BYTE_OFFSET] |= G2::COMPRESSED_FLAG;
        match api::verify_pop(pop_bytes, public_key_bytes) {
            Err(e) => assert!(e
                .to_string()
                .contains("coordinate(s) do not lie on the curve")),
            Ok(_) => panic!("error should have been thrown"),
        }
    }

    #[test]
    fn verify_pop_throws_error_on_public_key_bytes_not_in_subgroup() {
        let (secret_key, public_key) = multi_crypto::keypair_from_seed([1, 2, 3, 4]);
        let pop = multi_crypto::create_pop(public_key, secret_key);
        let pop_bytes = PopBytes::from(pop);
        let mut public_key_bytes = PublicKeyBytes::from(public_key);
        // By manual rejection sampling, we found an x-coordinate with a
        // solution, which is unlikely to have order r.
        for i in 0..G2::SIZE {
            public_key_bytes.0[i] = 0;
        }
        public_key_bytes.0[G2::FLAG_BYTE_OFFSET] |= G2::COMPRESSED_FLAG;
        public_key_bytes.0[5] = 3;
        match api::verify_pop(pop_bytes, public_key_bytes) {
            Err(e) => assert!(e.to_string().contains("not part of an r-order subgroup")),
            Ok(_) => panic!("error should have been thrown"),
        }
    }

    #[test]
    fn double_signature_verifies() {
        let keys = [
            multi_crypto::keypair_from_seed([1, 2, 3, 4]),
            multi_crypto::keypair_from_seed([5, 6, 7, 8]),
        ];
        multi_test_utils::multi_signature_verifies(&keys, b"abba");
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
            multi_test_utils::multi_signature_verifies(&keys, &message);
        }
    }
}
