//! Tests for multisignatures

use crate::{
    api, crypto as multi_crypto, types as multi_types, types::CombinedSignature,
    types::IndividualSignature, types::PublicKey, types::SecretKey, types::SecretKeyBytes,
    types::arbitrary,
};
use ic_crypto_internal_seed::Seed;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

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
        fn keypair_from_seed_works(seed: [u8; 32]) {
            let seed = Seed::from_bytes(&seed);
            api::keypair_from_seed(seed);
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
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(&mut reproducible_rng());
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
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(&mut reproducible_rng());
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
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(&mut reproducible_rng());
        let pop = multi_crypto::create_pop(&public_key, &secret_key);
        assert!(multi_crypto::verify_pop(&pop, &public_key));
    }

    #[test]
    fn verify_pop_throws_error_on_public_key_bytes_with_unset_compressed_flag() {
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(&mut reproducible_rng());
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
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(&mut reproducible_rng());
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
        let (secret_key, public_key) = multi_crypto::keypair_from_rng(&mut reproducible_rng());
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
        #[test]
        fn multisig_verification_succeeds(
          keys in proptest::collection::vec(arbitrary::key_pair(), 1..10),
          message in proptest::collection::vec(any::<u8>(), 0..100),
        ) {
            check_multi_signature_verifies(&keys, &message);
        }
    }
}
