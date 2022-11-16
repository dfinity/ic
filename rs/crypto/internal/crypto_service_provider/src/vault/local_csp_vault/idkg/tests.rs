use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::vault::api::IDkgProtocolCspVault;
use crate::vault::local_csp_vault::test_utils::temp_local_csp_server::TempLocalCspVault;
use crate::vault::test_utils;
use crate::CspVault;
use crate::LocalCspVault;
use crate::PublicKeyStore;
use crate::SecretKeyStore;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::AlgorithmId;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

mod idkg_gen_dealing_encryption_key_pair {
    use super::*;
    use crate::keygen::utils::idkg_dealing_encryption_pk_to_proto;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::secret_key_store::test_utils::MockSecretKeyStore;
    use crate::vault::api::PublicKeyStoreCspVault;
    use crate::vault::api::SecretKeyStoreCspVault;
    use crate::vault::test_utils::local_csp_vault::new_local_csp_vault;
    use crate::KeyId;
    use ic_crypto_internal_seed::Seed;
    use ic_crypto_internal_threshold_sig_ecdsa::EccCurveType;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use mockall::Sequence;
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
                .idkg_gen_dealing_encryption_key_pair()
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
                .idkg_gen_dealing_encryption_key_pair()
                .expect("error generating I-DKG dealing encryption key pair");
            // MEGaPublicKey does not implement Hash so we use the serialized form
            let is_inserted = generated_keys.insert(public_key.serialize());
            if !is_inserted {
                panic!("MEGaPublicKey {:?} was already inserted!", public_key);
            }
        }
        assert_eq!(generated_keys.len(), expected_number_of_keys);
    }

    #[test]
    fn should_generate_and_store_dealing_encryption_key_pair_multiple_times() {
        test_utils::idkg::should_generate_and_store_dealing_encryption_key_pair_multiple_times(
            new_local_csp_vault(),
        );
    }

    #[test]
    fn should_store_idkg_secret_key_before_public_key() {
        let mut seq = Sequence::new();

        let mut sks = MockSecretKeyStore::new();
        sks.expect_insert()
            .times(1)
            .returning(|_key, _key_id, _scope| Ok(()))
            .in_sequence(&mut seq);

        let mut pks = MockPublicKeyStore::new();
        let empty_idkg_public_keys = Vec::new();
        pks.expect_idkg_dealing_encryption_pubkeys()
            .times(1)
            .return_const(empty_idkg_public_keys)
            .in_sequence(&mut seq);
        pks.expect_set_idkg_dealing_encryption_pubkeys()
            .times(1)
            .returning(|_keys| Ok(()))
            .in_sequence(&mut seq);

        let vault = vault_with_node_secret_key_store_and_public_key_store(sks, pks);

        assert!(vault.idkg_gen_dealing_encryption_key_pair().is_ok());
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_storing_idkg_public_key_fails() {
        let mut pks_returning_io_error = MockPublicKeyStore::new();
        let empty_idkg_public_keys = Vec::new();
        pks_returning_io_error
            .expect_idkg_dealing_encryption_pubkeys()
            .times(1)
            .return_const(empty_idkg_public_keys);
        let io_error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!");
        pks_returning_io_error
            .expect_set_idkg_dealing_encryption_pubkeys()
            .return_once(|_keys| Err(io_error));

        let vault = vault_with_public_key_store(pks_returning_io_error);

        test_utils::idkg::should_fail_with_transient_internal_error_if_storing_idkg_public_key_fails(
            vault,
        );
    }

    #[test]
    fn should_add_new_idkg_dealing_encryption_public_key_last() {
        let mut pks = MockPublicKeyStore::new();
        let idkg_public_key_1 = idkg_node_public_key_with_value([1; 32].to_vec());
        let idkg_public_key_2 = idkg_node_public_key_with_value([0; 32].to_vec());
        let existing_keys = vec![idkg_public_key_1.clone(), idkg_public_key_2.clone()];
        pks.expect_idkg_dealing_encryption_pubkeys()
            .times(1)
            .return_const(existing_keys);
        pks.expect_set_idkg_dealing_encryption_pubkeys()
            .times(1)
            .withf(move |keys: &Vec<PublicKey>| {
                keys.len() == 3 && keys[0] == idkg_public_key_1 && keys[1] == idkg_public_key_2
            })
            .returning(|_keys| Ok(()));

        let vault = vault_with_public_key_store(pks);

        assert!(vault.idkg_gen_dealing_encryption_key_pair().is_ok());
    }
}

fn idkg_node_public_key_with_value(key_value: Vec<u8>) -> PublicKey {
    PublicKey {
        version: 0,
        algorithm: AlgorithmId::MegaSecp256k1 as i32,
        proof_data: None,
        key_value,
        timestamp: None,
    }
}

fn vault_with_public_key_store<P: PublicKeyStore + 'static>(
    public_key_store: P,
) -> Arc<dyn CspVault> {
    let dummy_rng = ChaCha20Rng::seed_from_u64(42);
    let temp_sks = TempSecretKeyStore::new();
    let vault = LocalCspVault::new_for_test(dummy_rng, temp_sks, public_key_store);
    Arc::new(vault)
}

fn vault_with_node_secret_key_store_and_public_key_store<
    S: SecretKeyStore + 'static,
    P: PublicKeyStore + 'static,
>(
    node_secret_key_store: S,
    public_key_store: P,
) -> Arc<dyn CspVault> {
    let dummy_rng = ChaCha20Rng::seed_from_u64(42);
    let vault = LocalCspVault::new_for_test(dummy_rng, node_secret_key_store, public_key_store);
    Arc::new(vault)
}
