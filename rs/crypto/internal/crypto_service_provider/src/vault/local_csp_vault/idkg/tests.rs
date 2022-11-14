use crate::vault::api::IDkgProtocolCspVault;
use crate::vault::local_csp_vault::test_utils::temp_local_csp_server::TempLocalCspVault;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

mod idkg_gen_mega_key_pair {
    use super::*;
    use crate::keygen::utils::idkg_dealing_encryption_pk_to_proto;
    use crate::vault::api::PublicKeyStoreCspVault;
    use crate::vault::api::SecretKeyStoreCspVault;
    use crate::KeyId;
    use ic_crypto_internal_seed::Seed;
    use ic_crypto_internal_threshold_sig_ecdsa::EccCurveType;
    use ic_types::crypto::AlgorithmId;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::proptest;
    use std::collections::HashSet;

    proptest! {
        #[test]
        fn should_generate_mega_key_pair_and_store_it_in_the_vault(seed: [u8;32]) {
            let temp_vault =  TempLocalCspVault::new_with_rng(Seed::from_bytes(&seed).into_rng());

            let generated_public_key = temp_vault
                .vault
                .idkg_gen_mega_key_pair(AlgorithmId::ThresholdEcdsaSecp256k1)
                .expect("error generating I-DKG dealing encryption key pair");
            let stored_public_key = temp_vault
                .vault
                .current_node_public_keys()
                .expect("error retrieving public keys")
                .idkg_dealing_encryption_public_key
                .expect("missing I-DKG public key");
            let key_id = KeyId::try_from(&generated_public_key)
            .expect("valid key ID");

            prop_assert_eq!(generated_public_key.curve_type(), EccCurveType::K256);
            prop_assert_eq!(idkg_dealing_encryption_pk_to_proto(generated_public_key), stored_public_key);
            prop_assert!(temp_vault.vault.sks_contains(&key_id).expect("error reading SKS"));
        }
    }

    #[test]
    fn should_generate_distinct_mega_public_keys_with_high_probability() {
        let rng = reproducible_rng();
        let temp_vault = TempLocalCspVault::new_with_rng(rng);
        let mut generated_keys = HashSet::new();
        let expected_number_of_keys = 100;
        for _ in 1..=expected_number_of_keys {
            let public_key = temp_vault
                .vault
                .idkg_gen_mega_key_pair(AlgorithmId::ThresholdEcdsaSecp256k1)
                .expect("error generating I-DKG dealing encryption key pair");
            // MEGaPublicKey does not implement Hash so we use the serialized form
            let is_inserted = generated_keys.insert(public_key.serialize());
            if !is_inserted {
                panic!("MEGaPublicKey {:?} was already inserted!", public_key);
            }
        }
        assert_eq!(generated_keys.len(), expected_number_of_keys);
    }
}
