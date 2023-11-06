use crate::api::CspCreateMEGaKeyError;
use crate::secret_key_store::SecretKeyStoreInsertionError;
use crate::vault::api::IDkgProtocolCspVault;
use crate::vault::local_csp_vault::PublicKeyStore;
use crate::vault::test_utils;
use crate::LocalCspVault;
use assert_matches::assert_matches;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

mod idkg_gen_dealing_encryption_key_pair {
    use super::*;
    use crate::canister_threshold::IDKG_MEGA_SCOPE;
    use crate::keygen::utils::idkg_dealing_encryption_pk_to_proto;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::PublicKeyAddError;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::vault::api::PublicKeyStoreCspVault;
    use crate::vault::api::SecretKeyStoreCspVault;
    use crate::KeyId;
    use hex::FromHex;
    use ic_crypto_internal_seed::Seed;
    use ic_crypto_internal_threshold_sig_ecdsa::EccCurveType;
    use ic_test_utilities::FastForwardTimeSource;
    use ic_types::time::GENESIS;
    use mockall::Sequence;
    use proptest::prelude::*;
    use std::collections::HashSet;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn should_generate_mega_key_pair_and_store_it_in_the_vault(seed: [u8;32]) {
            let vault =  LocalCspVault::builder_for_test().with_rng(Seed::from_bytes(&seed).into_rng()).build();

            let generated_public_key = vault
                .idkg_gen_dealing_encryption_key_pair()
                .expect("error generating I-DKG dealing encryption key pair");
            let stored_public_key = vault
                .current_node_public_keys()
                .expect("error retrieving public keys")
                .idkg_dealing_encryption_public_key
                .expect("missing I-DKG public key");
            let key_id = KeyId::try_from(&generated_public_key)
            .expect("valid key ID");

            prop_assert_eq!(generated_public_key.curve_type(), EccCurveType::K256);
            prop_assert_eq!(idkg_dealing_encryption_pk_to_proto(generated_public_key), stored_public_key);
            prop_assert!(vault.sks_contains(&key_id).expect("error reading SKS"));
        }
    }

    #[test]
    fn should_generate_distinct_mega_public_keys_with_high_probability() {
        let vault = LocalCspVault::builder_for_test().build();
        let mut generated_keys = HashSet::new();
        for _ in 1..=100 {
            let public_key = vault
                .idkg_gen_dealing_encryption_key_pair()
                .expect("error generating I-DKG dealing encryption key pair");
            // MEGaPublicKey does not implement Hash so we use the serialized form
            assert!(
                generated_keys.insert(public_key.serialize()),
                "MEGaPublicKey {:?} was already inserted!",
                public_key
            );
        }
    }

    #[test]
    fn should_generate_and_store_dealing_encryption_key_pair_multiple_times() {
        test_utils::idkg::should_generate_and_store_dealing_encryption_key_pair_multiple_times(
            LocalCspVault::builder_for_test().build_into_arc(),
        );
    }

    #[test]
    fn should_correctly_extend_public_key_vector() {
        let vault = LocalCspVault::builder_for_test().build();
        let mut generated_keys = Vec::new();
        for _ in 1..=5 {
            let public_key = vault
                .idkg_gen_dealing_encryption_key_pair()
                .expect("failed to create keys");
            let public_key_proto = idkg_dealing_encryption_pk_to_proto(public_key.clone());
            generated_keys.push(public_key_proto);
        }
        assert_eq!(
            vault
                .public_key_store
                .read()
                .idkg_dealing_encryption_pubkeys(),
            generated_keys
        );
    }

    #[test]
    fn should_eventually_detect_race_condition_when_extending_public_key_vector() {
        const NUM_ITERATIONS: usize = 200;
        let vault = LocalCspVault::builder_for_test().build_into_arc();
        let mut thread_handles = Vec::new();
        for _ in 1..=NUM_ITERATIONS {
            let vault = Arc::clone(&vault);
            thread_handles.push(std::thread::spawn(move || {
                vault
                    .idkg_gen_dealing_encryption_key_pair()
                    .expect("failed to create keys")
            }));
        }
        let mut generated_keys = Vec::new();
        let mut duplicate_key_detector = HashSet::new();
        for thread_handle in thread_handles {
            let public_key = thread_handle.join().expect("failed to join");
            assert!(duplicate_key_detector.insert(public_key.serialize()));
            generated_keys.push(public_key);
        }
        let public_key_store_read_lock = vault.public_key_store.read();
        for generated_key in generated_keys {
            assert!(public_key_store_read_lock
                .idkg_dealing_encryption_pubkeys()
                .contains(&idkg_dealing_encryption_pk_to_proto(generated_key)));
        }
        assert_eq!(
            public_key_store_read_lock
                .idkg_dealing_encryption_pubkeys()
                .len(),
            NUM_ITERATIONS
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
        pks.expect_add_idkg_dealing_encryption_pubkey()
            .times(1)
            .return_once(|_key| Ok(()))
            .in_sequence(&mut seq);

        let vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(sks)
            .with_public_key_store(pks)
            .build_into_arc();

        assert!(vault.idkg_gen_dealing_encryption_key_pair().is_ok());
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_storing_idkg_public_key_fails() {
        let io_error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!");
        let mut pks_returning_io_error = MockPublicKeyStore::new();
        pks_returning_io_error
            .expect_add_idkg_dealing_encryption_pubkey()
            .return_once(|_| Err(PublicKeyAddError::Io(io_error)));

        let vault = LocalCspVault::builder_for_test()
            .with_public_key_store(pks_returning_io_error)
            .build_into_arc();

        test_utils::idkg::should_fail_with_transient_internal_error_if_storing_idkg_public_key_fails(
            vault,
        );
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_idkg_secret_key_persistence_fails_due_to_io_error(
    ) {
        let mut sks_returning_io_error = MockSecretKeyStore::new();
        let expected_io_error = "cannot write to file".to_string();
        sks_returning_io_error
            .expect_insert()
            .times(1)
            .return_const(Err(SecretKeyStoreInsertionError::TransientError(
                expected_io_error.clone(),
            )));
        let vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(sks_returning_io_error)
            .build();

        let result = vault.idkg_gen_dealing_encryption_key_pair();

        assert_matches!(
            result,
            Err(CspCreateMEGaKeyError::TransientInternalError { internal_error })
            if internal_error.contains(&expected_io_error)
        );
    }

    #[test]
    fn should_fail_with_internal_error_if_idkg_secret_key_persistence_fails_due_to_serialization_error(
    ) {
        let mut sks_returning_serialization_error = MockSecretKeyStore::new();
        let expected_serialization_error = "cannot serialize keys".to_string();
        sks_returning_serialization_error
            .expect_insert()
            .times(1)
            .return_const(Err(SecretKeyStoreInsertionError::SerializationError(
                expected_serialization_error.clone(),
            )));
        let vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(sks_returning_serialization_error)
            .build();

        let result = vault.idkg_gen_dealing_encryption_key_pair();

        assert_matches!(
            result,
            Err(CspCreateMEGaKeyError::InternalError { internal_error })
            if internal_error.contains(&expected_serialization_error)
        );
    }

    #[test]
    fn should_add_new_idkg_dealing_encryption_public_key_last() {
        let vault = LocalCspVault::builder_for_test().build();
        assert!(vault
            .public_key_store_read_lock()
            .idkg_dealing_encryption_pubkeys()
            .is_empty());

        assert!(vault.idkg_gen_dealing_encryption_key_pair().is_ok());
        let generated_keys = vault
            .public_key_store_read_lock()
            .idkg_dealing_encryption_pubkeys();
        assert_eq!(generated_keys.len(), 1);
        let first_public_key = &generated_keys[0];

        assert!(vault.idkg_gen_dealing_encryption_key_pair().is_ok());
        let generated_keys = vault
            .public_key_store_read_lock()
            .idkg_dealing_encryption_pubkeys();
        assert_eq!(generated_keys.len(), 2);
        assert_eq!(&generated_keys[0], first_public_key);
        let second_public_key = &generated_keys[1];

        assert!(vault.idkg_gen_dealing_encryption_key_pair().is_ok());
        let generated_keys = vault
            .public_key_store_read_lock()
            .idkg_dealing_encryption_pubkeys();
        assert_eq!(generated_keys.len(), 3);
        assert_eq!(&generated_keys[0], first_public_key);
        assert_eq!(&generated_keys[1], second_public_key);
    }

    #[test]
    fn should_store_generated_secret_key_with_correct_key_id_and_scope() {
        let mut sks = MockSecretKeyStore::new();
        let expected_key_id =
            KeyId::from_hex("20087da760d4dcc7488ab32c611ed83f0ca9e58778ba6c441cca2d46609ea90b")
                .expect("invalid key id");
        sks.expect_insert()
            .times(1)
            .withf(move |key_id, _key, scope| {
                *key_id == expected_key_id && *scope == Some(IDKG_MEGA_SCOPE)
            })
            .return_const(Ok(()));
        let vault = LocalCspVault::builder_for_test()
            .with_rng(ChaCha20Rng::seed_from_u64(42))
            .with_node_secret_key_store(sks)
            .build_into_arc();

        assert!(vault.idkg_gen_dealing_encryption_key_pair().is_ok());
    }

    #[test]
    fn should_generate_idkg_dealing_encryption_public_key_with_timestamp() {
        let time_source = FastForwardTimeSource::new();
        time_source.set_time(GENESIS).expect("wrong time");
        let vault = LocalCspVault::builder_for_test()
            .with_time_source(time_source)
            .build();

        let _ = vault
            .idkg_gen_dealing_encryption_key_pair()
            .expect("failed to create keys");

        assert_eq!(
            vault
                .current_node_public_keys_with_timestamps()
                .expect("Failed to retrieve current public keys")
                .idkg_dealing_encryption_public_key
                .expect("missing IDKG public key")
                .timestamp
                .expect("missing IDKG key generation timestamp"),
            GENESIS.as_millis_since_unix_epoch()
        );
    }
}

mod idkg_retain_active_keys {
    use crate::key_id::KeyId;
    use crate::keygen::utils::mega_public_key_from_proto;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::PublicKeyStore;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::vault::api::{IDkgProtocolCspVault, PublicKeyStoreCspVault, SecretKeyStoreCspVault};
    use crate::vault::local_csp_vault::idkg::idkg_dealing_encryption_pk_to_proto;
    use crate::LocalCspVault;
    use crate::SecretKeyStore;
    use assert_matches::assert_matches;
    use ic_crypto_internal_threshold_sig_ecdsa::MEGaPublicKey;
    use ic_crypto_internal_types::scope::{ConstScope, Scope};
    use ic_crypto_test_utils_keys::public_keys::valid_idkg_dealing_encryption_public_key;
    use ic_types::crypto::canister_threshold_sig::error::IDkgRetainKeysError;
    use mockall::predicate::eq;
    use mockall::Sequence;
    use rand::CryptoRng;
    use rand::Rng;
    use std::collections::BTreeSet;

    #[test]
    fn should_fail_when_idkg_oldest_public_key_not_found() {
        let vault = LocalCspVault::builder_for_test().build();
        let idkg_dealing_encryption_public_key_proto = valid_idkg_dealing_encryption_public_key();
        let idkg_dealing_encryption_public_key =
            mega_public_key_from_proto(&idkg_dealing_encryption_public_key_proto)
                .expect("should convert to MEGaPublicKey");

        let result =
            vault.idkg_retain_active_keys(BTreeSet::new(), idkg_dealing_encryption_public_key);

        assert_matches!(result, Err(IDkgRetainKeysError::InternalError {internal_error})
            if internal_error.contains("Could not find oldest IDKG public key")
        );
    }

    #[test]
    fn should_not_delete_only_key_pair() {
        let vault = LocalCspVault::builder_for_test().build();
        let public_key = vault
            .idkg_gen_dealing_encryption_key_pair()
            .expect("error generating IDKG key pair");

        let result = vault.idkg_retain_active_keys(BTreeSet::new(), public_key.clone());

        assert!(result.is_ok());
        assert_eq!(
            vault
                .current_node_public_keys()
                .expect("missing node public keys")
                .idkg_dealing_encryption_public_key,
            Some(idkg_dealing_encryption_pk_to_proto(public_key.clone()))
        );
        assert!(vault
            .sks_contains(&KeyId::try_from(&public_key).expect("invalid key ID"))
            .expect("error reading SKS"));
    }

    #[test]
    fn should_retain_only_active_public_keys() {
        let vault = LocalCspVault::builder_for_test().build();
        let number_of_keys = 5;
        let oldest_public_key_index = 2;
        let mut rotated_public_keys =
            generate_idkg_dealing_encryption_key_pairs(&vault, number_of_keys);

        vault
            .idkg_retain_active_keys(
                BTreeSet::new(),
                rotated_public_keys[oldest_public_key_index].clone(),
            )
            .expect("error retaining active IDKG keys");

        let guard = vault.public_key_store_read_lock();
        let retained_public_keys = guard.idkg_dealing_encryption_pubkeys();
        assert_eq!(
            retained_public_keys.len(),
            number_of_keys - oldest_public_key_index
        );
        rotated_public_keys.drain(0..oldest_public_key_index);
        assert_eq!(rotated_public_keys.len(), retained_public_keys.len());
        for (index, rotated_public_key) in rotated_public_keys.into_iter().enumerate() {
            let rotated_public_key_proto =
                idkg_dealing_encryption_pk_to_proto(rotated_public_key.clone());
            assert!(rotated_public_key_proto.equal_ignoring_timestamp(&retained_public_keys[index]));
        }
    }

    #[test]
    fn should_retain_only_active_secret_keys() {
        let vault = LocalCspVault::builder_for_test().build();
        let number_of_keys = 5;
        let oldest_public_key_index = 2;
        let rotated_public_keys =
            generate_idkg_dealing_encryption_key_pairs(&vault, number_of_keys);

        vault
            .idkg_retain_active_keys(
                BTreeSet::new(),
                rotated_public_keys[oldest_public_key_index].clone(),
            )
            .expect("error retaining active IDKG keys");

        for (i, public_key) in rotated_public_keys.iter().enumerate() {
            let key_id = KeyId::try_from(public_key).expect("invalid key id");
            if i < oldest_public_key_index {
                assert!(!vault.sks_contains(&key_id).expect("error reading SKS"));
            } else {
                assert!(vault.sks_contains(&key_id).expect("error reading SKS"));
            }
        }
    }

    #[test]
    fn should_retain_public_keys_before_secret_keys_before_shares() {
        let mut pks = MockPublicKeyStore::new();
        let mut node_sks = MockSecretKeyStore::new();
        let mut canister_sks = MockSecretKeyStore::new();
        let mut seq = Sequence::new();

        let oldest_public_key_proto = valid_idkg_dealing_encryption_public_key();
        let oldest_public_key = mega_public_key_from_proto(&oldest_public_key_proto)
            .expect("should convert to MEGaPublicKey");
        pks.expect_idkg_dealing_encryption_pubkeys().never();
        pks.expect_would_retain_idkg_public_keys_modify_pubkey_store()
            .times(1)
            .in_sequence(&mut seq)
            .with(eq(oldest_public_key_proto.clone()))
            .return_once(|_| Ok(true));
        pks.expect_retain_idkg_public_keys_since()
            .times(1)
            .in_sequence(&mut seq)
            .with(eq(oldest_public_key_proto.clone()))
            .return_once(|_| Ok(true));
        pks.expect_idkg_dealing_encryption_pubkeys()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(vec![oldest_public_key_proto]);
        node_sks
            .expect_retain()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|_filter, scope| *scope == Scope::Const(ConstScope::IDkgMEGaEncryptionKeys))
            .return_const(Ok(()));
        canister_sks
            .expect_retain_would_modify_keystore()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|_filter, scope| *scope == Scope::Const(ConstScope::IDkgThresholdKeys))
            .return_const(true);
        canister_sks
            .expect_retain()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|_filter, scope| *scope == Scope::Const(ConstScope::IDkgThresholdKeys))
            .return_const(Ok(()));

        let vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(node_sks)
            .with_canister_secret_key_store(canister_sks)
            .with_public_key_store(pks)
            .build();

        assert!(vault
            .idkg_retain_active_keys(BTreeSet::new(), oldest_public_key)
            .is_ok());
    }

    #[test]
    fn should_not_use_secret_key_store_if_public_key_store_was_not_modified() {
        let mut pks = MockPublicKeyStore::new();
        let node_sks = MockSecretKeyStore::new();
        let mut canister_sks = MockSecretKeyStore::new();
        let mut seq = Sequence::new();

        let oldest_public_key_proto = valid_idkg_dealing_encryption_public_key();
        let oldest_public_key = mega_public_key_from_proto(&oldest_public_key_proto)
            .expect("should convert to MEGaPublicKey");
        pks.expect_idkg_dealing_encryption_pubkeys().never();
        pks.expect_retain_idkg_public_keys_since().never();
        pks.expect_would_retain_idkg_public_keys_modify_pubkey_store()
            .times(1)
            .in_sequence(&mut seq)
            .with(eq(oldest_public_key_proto))
            .return_once(|_| Ok(false));
        canister_sks
            .expect_retain_would_modify_keystore()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|_filter, scope| *scope == Scope::Const(ConstScope::IDkgThresholdKeys))
            .return_const(false);
        canister_sks.expect_retain().never();

        let vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(node_sks)
            .with_canister_secret_key_store(canister_sks)
            .with_public_key_store(pks)
            .build();

        assert!(vault
            .idkg_retain_active_keys(BTreeSet::new(), oldest_public_key)
            .is_ok());
    }

    fn generate_idkg_dealing_encryption_key_pairs<
        R: Rng + CryptoRng,
        S: SecretKeyStore,
        C: SecretKeyStore,
        P: PublicKeyStore,
    >(
        vault: &LocalCspVault<R, S, C, P>,
        number_of_key_pairs_to_generate: usize,
    ) -> Vec<MEGaPublicKey> {
        let mut rotated_public_keys = Vec::new();
        for _ in 0..number_of_key_pairs_to_generate {
            rotated_public_keys.push(
                vault
                    .idkg_gen_dealing_encryption_key_pair()
                    .expect("error generating IDKG key pair"),
            );
        }
        assert_eq!(rotated_public_keys.len(), number_of_key_pairs_to_generate);
        rotated_public_keys
    }
}
