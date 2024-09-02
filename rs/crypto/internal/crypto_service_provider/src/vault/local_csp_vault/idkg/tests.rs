use crate::api::CspCreateMEGaKeyError;
use crate::keygen::utils::idkg_dealing_encryption_pk_to_proto;
use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreInsertionError};
use crate::vault::api::IDkgProtocolCspVault;
use crate::vault::local_csp_vault::idkg::SecretKeyStoreWriteError;
use crate::vault::local_csp_vault::PublicKeyStore;
use crate::vault::test_utils;
use crate::KeyId;
use crate::LocalCspVault;
use assert_matches::assert_matches;
use ic_crypto_internal_types::NodeIndex;
use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_transcript_id_for_tests;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgDealing, SignedIDkgDealing,
};
use ic_types::crypto::{BasicSig, BasicSigOf};
use ic_types::signature::{BasicSignature, BasicSignatureBatch};
use ic_types::{NodeId, PrincipalId};
use mockall::Sequence;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;
use std::sync::Arc;

type LocalCspVaultForTest =
    LocalCspVault<ReproducibleRng, TempSecretKeyStore, TempSecretKeyStore, TempPublicKeyStore>;
type CustomVaultFn = Box<dyn FnOnce(LocalCspVaultForTest) -> Box<dyn IDkgProtocolCspVault>>;

mod idkg_gen_dealing_encryption_key_pair {
    use super::*;
    use crate::canister_threshold::IDKG_MEGA_SCOPE;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::PublicKeyAddError;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::vault::api::PublicKeyStoreCspVault;
    use crate::vault::api::SecretKeyStoreCspVault;
    use crate::KeyId;
    use hex::FromHex;
    use ic_crypto_internal_seed::Seed;
    use ic_crypto_internal_threshold_sig_ecdsa::EccCurveType;
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_types::time::GENESIS;
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
            prop_assert!(vault.sks_contains(key_id).expect("error reading SKS"));
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
    use super::*;
    use crate::canister_threshold::{IDKG_MEGA_SCOPE, IDKG_THRESHOLD_KEYS_SCOPE};
    use crate::key_id::KeyId;
    use crate::keygen::utils::mega_public_key_from_proto;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::{PublicKeyRetainError, PublicKeyStore};
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::secret_key_store::SecretKeyStoreWriteError;
    use crate::vault::api::{IDkgProtocolCspVault, PublicKeyStoreCspVault, SecretKeyStoreCspVault};
    use crate::vault::local_csp_vault::idkg::PublicKeyRetainCheckError;
    use crate::LocalCspVault;
    use crate::SecretKeyStore;
    use assert_matches::assert_matches;
    use ic_crypto_internal_threshold_sig_ecdsa::MEGaPublicKey;
    use ic_crypto_internal_types::scope::{ConstScope, Scope};
    use ic_crypto_test_utils_keys::public_keys::valid_idkg_dealing_encryption_public_key;
    use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
    use ic_protobuf::registry::crypto::v1::PublicKey;
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
            .sks_contains(KeyId::try_from(&public_key).expect("invalid key ID"))
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
                assert!(!vault.sks_contains(key_id).expect("error reading SKS"));
            } else {
                assert!(vault.sks_contains(key_id).expect("error reading SKS"));
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

    #[test]
    fn should_fail_if_oldest_pk_not_found_during_would_retain_modify_pks() {
        let mut pks = MockPublicKeyStore::new();

        let oldest_public_key_proto = valid_idkg_dealing_encryption_public_key();
        let oldest_public_key = mega_public_key_from_proto(&oldest_public_key_proto)
            .expect("should convert to MEGaPublicKey");
        pks.expect_would_retain_idkg_public_keys_modify_pubkey_store()
            .times(1)
            .return_once(|_| Err(PublicKeyRetainCheckError::OldestPublicKeyNotFound));
        let vault = LocalCspVault::builder_for_test()
            .with_public_key_store(pks)
            .build();

        assert_matches!(
            vault.idkg_retain_active_keys(BTreeSet::new(), oldest_public_key),
            Err(IDkgRetainKeysError::InternalError{ internal_error })
            if internal_error.contains("Could not find oldest IDKG public key")
        );
    }

    #[test]
    fn should_fail_on_serialization_error_from_pks_during_retention() {
        let mut pks = MockPublicKeyStore::new();
        let mut seq = Sequence::new();

        let oldest_public_key_proto = valid_idkg_dealing_encryption_public_key();
        let oldest_public_key = mega_public_key_from_proto(&oldest_public_key_proto)
            .expect("should convert to MEGaPublicKey");
        let err =
            PublicKeyRetainError::Io(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"));
        pks.expect_would_retain_idkg_public_keys_modify_pubkey_store()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_| Ok(true));
        pks.expect_retain_idkg_public_keys_since()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_| Err(err));

        let vault = LocalCspVault::builder_for_test()
            .with_public_key_store(pks)
            .build();

        assert_matches!(
            vault.idkg_retain_active_keys(BTreeSet::new(), oldest_public_key),
            Err(IDkgRetainKeysError::TransientInternalError{ internal_error })
            if internal_error.contains("oh no!")
        );
    }

    #[test]
    fn should_fail_if_oldest_pk_not_found_during_retention() {
        let mut pks = MockPublicKeyStore::new();
        let mut seq = Sequence::new();

        let oldest_public_key_proto = valid_idkg_dealing_encryption_public_key();
        let oldest_public_key = mega_public_key_from_proto(&oldest_public_key_proto)
            .expect("should convert to MEGaPublicKey");
        let err = PublicKeyRetainError::OldestPublicKeyNotFound;
        pks.expect_would_retain_idkg_public_keys_modify_pubkey_store()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_| Ok(true));
        pks.expect_retain_idkg_public_keys_since()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_| Err(err));

        let vault = LocalCspVault::builder_for_test()
            .with_public_key_store(pks)
            .build();

        assert_matches!(
            vault.idkg_retain_active_keys(BTreeSet::new(), oldest_public_key),
            Err(IDkgRetainKeysError::InternalError{ internal_error })
            if internal_error.contains("Could not find oldest IDKG public key")
        );
    }

    #[test]
    fn should_fail_if_pk_proto_algorithm_id_unsupported() {
        let mut pks = MockPublicKeyStore::new();
        let mut seq = Sequence::new();

        let invalid_alg_id_pk = PublicKey {
            version: 1,
            algorithm: AlgorithmIdProto::EcdsaP256 as i32,
            key_value: vec![0xFF; 100],
            proof_data: None,
            timestamp: None,
        };

        let oldest_public_key_proto = valid_idkg_dealing_encryption_public_key();
        let oldest_public_key = mega_public_key_from_proto(&oldest_public_key_proto)
            .expect("should convert to MEGaPublicKey");
        pks.expect_would_retain_idkg_public_keys_modify_pubkey_store()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_| Ok(true));
        pks.expect_retain_idkg_public_keys_since()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_| Ok(true));
        pks.expect_idkg_dealing_encryption_pubkeys()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|| vec![invalid_alg_id_pk]);

        let vault = LocalCspVault::builder_for_test()
            .with_public_key_store(pks)
            .build();

        assert_matches!(
            vault.idkg_retain_active_keys(BTreeSet::new(), oldest_public_key),
            Err(IDkgRetainKeysError::InternalError{ internal_error })
            if internal_error.contains("Unsupported algorithm")
        );
    }

    #[test]
    fn should_fail_if_failed_deserialize_pk_proto() {
        let mut pks = MockPublicKeyStore::new();
        let mut seq = Sequence::new();

        let invalid_alg_id_pk = PublicKey {
            version: 1,
            algorithm: AlgorithmIdProto::MegaSecp256k1 as i32,
            key_value: vec![0xFF; 100],
            proof_data: None,
            timestamp: None,
        };

        let oldest_public_key_proto = valid_idkg_dealing_encryption_public_key();
        let oldest_public_key = mega_public_key_from_proto(&oldest_public_key_proto)
            .expect("should convert to MEGaPublicKey");
        pks.expect_would_retain_idkg_public_keys_modify_pubkey_store()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_| Ok(true));
        pks.expect_retain_idkg_public_keys_since()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_| Ok(true));
        pks.expect_idkg_dealing_encryption_pubkeys()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|| vec![invalid_alg_id_pk]);

        let vault = LocalCspVault::builder_for_test()
            .with_public_key_store(pks)
            .build();

        assert_matches!(
            vault.idkg_retain_active_keys(BTreeSet::new(), oldest_public_key),
            Err(IDkgRetainKeysError::InternalError{ internal_error })
            if internal_error.contains("Error deserializing IDKG public key")
        );
    }

    #[test]
    fn should_fail_if_sks_retain_fails() {
        let errors_outputs = vec![
            (
                SecretKeyStoreWriteError::SerializationError("oh no!".to_string()),
                IDkgRetainKeysError::SerializationError {
                    internal_error: "Serialization error while retaining active IDKG dealing encryption secret keys: \"oh no!\"".to_string()
                },
            ),
            (
                SecretKeyStoreWriteError::TransientError("oh no!".to_string()),
                IDkgRetainKeysError::TransientInternalError {
                    internal_error: "IO error while retaining active IDKG dealing encryption secret keys: \"oh no!\"".to_string()
                },
            ),
        ];

        for (input_error, expected_output_error) in errors_outputs {
            let mut pks = MockPublicKeyStore::new();
            let mut sks = MockSecretKeyStore::new();
            let mut seq = Sequence::new();

            let oldest_public_key_proto = valid_idkg_dealing_encryption_public_key();
            let oldest_public_key = mega_public_key_from_proto(&oldest_public_key_proto)
                .expect("should convert to MEGaPublicKey");

            pks.expect_would_retain_idkg_public_keys_modify_pubkey_store()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_| Ok(true));
            pks.expect_retain_idkg_public_keys_since()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_| Ok(true));
            pks.expect_idkg_dealing_encryption_pubkeys()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|| vec![oldest_public_key_proto]);

            sks.expect_retain()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_, _| Err(input_error));

            let vault = LocalCspVault::builder_for_test()
                .with_public_key_store(pks)
                .with_node_secret_key_store(sks)
                .build();

            assert_eq!(
                vault.idkg_retain_active_keys(BTreeSet::new(), oldest_public_key),
                Err(expected_output_error)
            );
        }
    }

    #[test]
    fn should_fail_if_csks_retain_fails() {
        let errors_outputs = vec![
            (
                SecretKeyStoreWriteError::TransientError("oh no!".to_string()),
                IDkgRetainKeysError::TransientInternalError {
                    internal_error: "IO error while retaining active IDKG canister secret shares: \"oh no!\"".to_string()
                },
            ),
            (
                SecretKeyStoreWriteError::SerializationError("oh no!".to_string()),
                IDkgRetainKeysError::SerializationError {
                    internal_error: "Serialization error while retaining active IDKG canister secret shares: \"oh no!\"".to_string()
                },
            ),
        ];

        for (input_error, expected_output_error) in errors_outputs {
            let mut pks = MockPublicKeyStore::new();
            let mut csks = MockSecretKeyStore::new();
            let mut seq = Sequence::new();

            let oldest_public_key_proto = valid_idkg_dealing_encryption_public_key();
            let oldest_public_key = mega_public_key_from_proto(&oldest_public_key_proto)
                .expect("should convert to MEGaPublicKey");

            pks.expect_would_retain_idkg_public_keys_modify_pubkey_store()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_| Ok(false));

            csks.expect_retain_would_modify_keystore()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_, _| true);
            csks.expect_retain()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_, _| Err(input_error));

            let vault = LocalCspVault::builder_for_test()
                .with_public_key_store(pks)
                .with_canister_secret_key_store(csks)
                .build();

            assert_eq!(
                vault.idkg_retain_active_keys(BTreeSet::new(), oldest_public_key),
                Err(expected_output_error)
            );
        }
    }

    #[test]
    fn should_use_correct_key_scope() {
        let pks = TempPublicKeyStore::new();

        let mut mnsks = MockSecretKeyStore::new();
        let mut mcsks = MockSecretKeyStore::new();

        let mut seq = Sequence::new();

        const NUMBER_OF_KEYS: usize = 5;
        mnsks
            .expect_insert()
            .times(NUMBER_OF_KEYS)
            .withf(|_, _, scope| scope == &Some(IDKG_MEGA_SCOPE))
            .in_sequence(&mut seq)
            .return_const(Ok(()));

        mnsks
            .expect_retain()
            .times(1)
            .withf(|_, scope| scope == &IDKG_MEGA_SCOPE)
            .in_sequence(&mut seq)
            .return_const(Ok(()));

        mcsks
            .expect_retain_would_modify_keystore()
            .times(1)
            .withf(|_, scope| scope == &IDKG_THRESHOLD_KEYS_SCOPE)
            .in_sequence(&mut seq)
            .return_const(true);

        mcsks
            .expect_retain()
            .times(1)
            .withf(|_, scope| scope == &IDKG_THRESHOLD_KEYS_SCOPE)
            .in_sequence(&mut seq)
            .return_const(Ok(()));

        let vault = LocalCspVault::builder_for_test()
            .with_public_key_store(pks)
            .with_canister_secret_key_store(mcsks)
            .with_node_secret_key_store(mnsks)
            .build();

        let oldest_public_key_index = 2;
        let rotated_public_keys =
            generate_idkg_dealing_encryption_key_pairs(&vault, NUMBER_OF_KEYS);

        vault
            .idkg_retain_active_keys(
                BTreeSet::new(),
                rotated_public_keys[oldest_public_key_index].clone(),
            )
            .expect("error retaining active IDKG keys");
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

mod idkg_create_dealing {
    use super::*;
    use crate::vault::api::{IDkgCreateDealingVaultError, IDkgDealingInternalBytes};
    use assert_matches::assert_matches;
    use ic_crypto_internal_threshold_sig_ecdsa::{
        CombinedCommitment, EccCurveType, IDkgTranscriptInternal, PolynomialCommitmentType,
    };
    use ic_crypto_internal_threshold_sig_ecdsa_test_utils::random_polynomial_commitment;
    use ic_crypto_internal_types::NodeIndex;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_transcript_id_for_tests;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_types::{
        crypto::{
            canister_threshold_sig::idkg::{
                IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptOperation,
                IDkgTranscriptType,
            },
            AlgorithmId,
        },
        NumberOfNodes, RegistryVersion,
    };
    use ic_types_test_utils::ids::node_test_id;
    use rand::{CryptoRng, Rng};

    #[test]
    fn should_work() {
        assert_matches!(IDkgCreateDealingTest::new_with_valid_params().run(), Ok(_));
    }

    #[test]
    fn should_fail_on_malformed_mega_pubkey() {
        let mut test = IDkgCreateDealingTest::new_with_valid_params();
        let invalid_key_serialization = vec![0xFF, 100];
        {
            let invalid_key_serialization = invalid_key_serialization.clone();
            test.receiver_key_modifier_fn =
                Box::new(|algorithm_id, _key_value| (algorithm_id, invalid_key_serialization));
        }
        assert_matches!(
            test.run(),
            Err(IDkgCreateDealingVaultError::MalformedPublicKey {
                receiver_index,
                key_bytes
            })
            if receiver_index == 0 && key_bytes == invalid_key_serialization
        );
    }

    #[test]
    fn should_fail_on_invalid_algorithm_id_in_pubkey() {
        let mut test = IDkgCreateDealingTest::new_with_valid_params();
        let invalid_algorithm_id = AlgorithmId::MultiBls12_381;
        test.receiver_key_modifier_fn =
            Box::new(move |_algorithm_id, key_value| (invalid_algorithm_id, key_value));
        assert_matches!(
            test.run(),
            Err(IDkgCreateDealingVaultError::UnsupportedAlgorithm(proto_alg_id))
            if proto_alg_id.expect("missing algorithm id") as i32 == invalid_algorithm_id as i32
        );
    }

    #[test]
    fn should_fail_on_invalid_serialization_of_transcript_operation() {
        let mut test = IDkgCreateDealingTest::new_with_valid_params();
        test.transcript_operation =
            IDkgTranscriptOperation::ReshareOfMasked(transcript_with_invalid_encoding());
        assert_matches!(
            test.run(),
            Err(IDkgCreateDealingVaultError::SerializationError(e))
            if e.contains("CanisterThresholdSerializationError")
        );
    }

    #[test]
    fn should_fail_if_required_opening_not_in_sks() {
        let rng = &mut reproducible_rng();
        let mut test = IDkgCreateDealingTest::new_with_valid_params();
        test.transcript_operation =
            IDkgTranscriptOperation::ReshareOfMasked(transcript_with_random_ecc_point(rng));
        assert_matches!(
            test.run(),
            Err(IDkgCreateDealingVaultError::SecretSharesNotFound { .. })
        );
    }

    #[test]
    fn should_fail_if_reconstruction_threshold_is_invalid() {
        let mut test = IDkgCreateDealingTest::new_with_valid_params();
        test.reconstruction_threshold = NumberOfNodes::from(0);
        assert_matches!(
            test.run(),
            Err(IDkgCreateDealingVaultError::InternalError(e))
            if e.contains("InvalidThreshold")
        );
    }

    #[test]
    fn should_fail_if_requested_algorithm_id_is_invalid_for_dealing() {
        let mut test = IDkgCreateDealingTest::new_with_valid_params();
        test.algorithm_id = AlgorithmId::MultiBls12_381;
        assert_matches!(
            test.run(),
            Err(IDkgCreateDealingVaultError::InternalError(e))
            if e.contains("UnsupportedAlgorithm")
        );
    }

    struct IDkgCreateDealingTest {
        algorithm_id: AlgorithmId,
        context_data: Vec<u8>,
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_key_modifier_fn: ReceiverKeyModifierFn,
        transcript_operation: IDkgTranscriptOperation,
    }

    type ReceiverKeyModifierFn = Box<dyn FnOnce(AlgorithmId, Vec<u8>) -> (AlgorithmId, Vec<u8>)>;

    impl IDkgCreateDealingTest {
        fn new_with_valid_params() -> Self {
            Self {
                algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
                context_data: vec![49; 10],
                dealer_index: 0,
                reconstruction_threshold: NumberOfNodes::from(1),
                receiver_key_modifier_fn: Box::new(|algorithm_id, key_value| {
                    (algorithm_id, key_value)
                }),
                transcript_operation: IDkgTranscriptOperation::Random,
            }
        }

        fn run(self) -> Result<IDkgDealingInternalBytes, IDkgCreateDealingVaultError> {
            let vault = LocalCspVault::builder_for_test().build();
            let receiver_key = {
                let valid_pk = vault
                    .idkg_gen_dealing_encryption_key_pair()
                    .expect("failed to generate key pair");
                let valid_algorithm_id = AlgorithmId::MegaSecp256k1;
                let valid_key_serialization = valid_pk.serialize();
                let (algorithm_id, key_value) =
                    (self.receiver_key_modifier_fn)(valid_algorithm_id, valid_key_serialization);
                PublicKey {
                    version: 0,
                    algorithm: algorithm_id as i32,
                    key_value,
                    proof_data: None,
                    timestamp: None,
                }
            };

            vault.idkg_create_dealing(
                self.algorithm_id,
                self.context_data,
                self.dealer_index,
                self.reconstruction_threshold,
                vec![receiver_key],
                self.transcript_operation,
            )
        }
    }

    fn transcript_with_invalid_encoding() -> IDkgTranscript {
        let invalid_internal_transcript_raw = vec![0xFF, 100];
        IDkgTranscript {
            transcript_id: dummy_idkg_transcript_id_for_tests(123),
            receivers: dummy_receivers(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: Default::default(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::Placeholder,
            internal_transcript_raw: invalid_internal_transcript_raw,
        }
    }

    fn transcript_with_random_ecc_point<R: Rng + CryptoRng>(rng: &mut R) -> IDkgTranscript {
        let transcript_internal = IDkgTranscriptInternal {
            combined_commitment: CombinedCommitment::BySummation(random_polynomial_commitment(
                1,
                PolynomialCommitmentType::Simple,
                EccCurveType::K256,
                rng,
            )),
        };
        let internal_transcript_raw = serde_cbor::to_vec(&transcript_internal)
            .expect("failed to serialize internal transcript operation");
        IDkgTranscript {
            transcript_id: dummy_idkg_transcript_id_for_tests(123),
            receivers: dummy_receivers(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: Default::default(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::Placeholder,
            internal_transcript_raw,
        }
    }

    fn dummy_receivers() -> IDkgReceivers {
        IDkgReceivers::new([node_test_id(456)].into_iter().collect())
            .expect("should not fail to create IDkgReceivers with constant inputs")
    }
}

mod idkg_load_transcript {
    use super::*;

    use crate::canister_threshold::IDKG_THRESHOLD_KEYS_SCOPE;
    use crate::key_id::KeyId;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::secret_key_store::SecretKeyStoreWriteError;
    use crate::types::CspSecretKey;
    use crate::vault::api::{IDkgDealingInternalBytes, IDkgTranscriptInternalBytes};
    use crate::vault::local_csp_vault::idkg::IDkgDealingInternal;
    use assert_matches::assert_matches;
    use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
    use ic_crypto_internal_seed::Seed;
    use ic_crypto_internal_threshold_sig_ecdsa::test_utils::corrupt_dealing;
    use ic_crypto_internal_threshold_sig_ecdsa::{
        EccCurveType, EccPoint, EccScalar, IDkgComplaintInternal, IDkgTranscriptInternal,
        IDkgTranscriptOperationInternal, MEGaCiphertext,
    };
    use ic_crypto_internal_types::NodeIndex;
    use ic_crypto_secrets_containers::SecretArray;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_types::crypto::canister_threshold_sig::error::IDkgLoadTranscriptError;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation;
    use ic_types::crypto::AlgorithmId;
    use ic_types::NumberOfNodes;
    use rand::{CryptoRng, Rng};
    use std::collections::BTreeMap;

    /// In this test collection, we only use one party, so the dealer is the
    /// receiver and the index is always 0.
    const DEALER_RECEIVER_INDEX: NodeIndex = 0;

    #[test]
    fn should_work() {
        assert_matches!(
            IDkgLoadTranscriptTest::new_with_valid_params().run(),
            Ok(complaints)
            if complaints.is_empty()
        );
    }

    #[test]
    fn should_work_if_commitment_is_already_loaded_in_sks() {
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();
        test.load_twice = true;
        assert_matches!(test.run(), Ok(complaints) if complaints.is_empty());
    }

    #[test]
    fn should_fail_if_deserialization_of_internal_dealings_fails() {
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();
        test.additional_operation =
            Some(IDkgLoadTranscriptTestAdditionalOperation::CorruptDealingEncodingInLoadArgs);
        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::SerializationError { internal_error })
            if internal_error.contains("failed to deserialize internal dealing")
        );
    }

    #[test]
    fn should_fail_if_deserialization_of_internal_transcript_fails() {
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();
        test.additional_operation =
            Some(IDkgLoadTranscriptTestAdditionalOperation::CorruptTranscriptEncodingInLoadArgs);
        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::SerializationError { internal_error })
            if internal_error.contains("failed to deserialize internal transcript")
        );
    }

    #[test]
    fn should_fail_on_errors_from_compute_secret_shares() {
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();
        test.additional_operation =
            Some(IDkgLoadTranscriptTestAdditionalOperation::UseEmptyDealingMap);
        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::InvalidArguments { internal_error })
            if internal_error.contains("UnableToCombineOpenings")
        );
    }

    #[test]
    fn should_fail_if_key_bytes_from_sks_are_not_mega_encryption_k256() {
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();

        let custom_vault_fn = Box::new(|_vault: LocalCspVaultForTest| {
            let mut msks = MockSecretKeyStore::new();
            let invalid_key_for_idkg = CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
                SecretArray::new_and_dont_zeroize_argument(&[0; 32]),
            ));
            msks.expect_get()
                .times(1)
                .return_once(|_| Some(invalid_key_for_idkg));
            Box::new(
                LocalCspVault::builder_for_test()
                    .with_node_secret_key_store(msks)
                    .build(),
            ) as Box<dyn IDkgProtocolCspVault>
        });
        test.custom_vault_for_load_transcript_fn = Some(custom_vault_fn);

        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::SerializationError{internal_error})
            if internal_error.contains("is not a MEGa encryption key set")
        );
    }

    #[test]
    fn should_fail_if_mega_keys_not_found() {
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();

        let custom_vault_fn = Box::new(|_vault| {
            // By constructing a new vault here, we lose the keys, so
            // `load_transcript` will not find the required MEGA keyset.
            Box::new(LocalCspVault::builder_for_test().build()) as Box<dyn IDkgProtocolCspVault>
        });
        test.custom_vault_for_load_transcript_fn = Some(custom_vault_fn);

        assert_matches!(test.run(), Err(IDkgLoadTranscriptError::PrivateKeyNotFound));
    }

    #[test]
    fn should_fail_if_cannot_decrypt_openings() {
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();
        test.additional_operation =
            Some(IDkgLoadTranscriptTestAdditionalOperation::CorruptInternalDealingCiphertext);
        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::InvalidArguments{internal_error})
            if internal_error.contains("InvalidCiphertext") && internal_error.contains("CurveMismatch")
        );
    }

    #[test]
    fn should_issue_complaint_on_corrupted_dealing() {
        // In addition to this test, there are also integration tests in the
        // crypto component that ensure that this works in the higher-level API.
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();
        test.additional_operation =
            Some(IDkgLoadTranscriptTestAdditionalOperation::CorruptInternalDealingForComplaint);
        assert_matches!(test.run(), Ok(complaints) if complaints.len() == 1);
    }

    #[test]
    fn should_fail_if_sks_insertion_fails() {
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();

        let custom_vault_fn = custom_vault_fn_returning(
            SecretKeyStoreWriteError::SerializationError("test".to_string()),
        );
        test.custom_vault_for_load_transcript_fn = Some(custom_vault_fn);

        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::InternalError{internal_error})
            if internal_error == "test"
        );
    }

    #[test]
    fn should_fail_on_transient_internal_errors_from_sks() {
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();
        let custom_vault_fn =
            custom_vault_fn_returning(SecretKeyStoreWriteError::TransientError("test".to_string()));
        test.custom_vault_for_load_transcript_fn = Some(Box::new(custom_vault_fn));

        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::TransientInternalError{internal_error})
            if internal_error == "test"
        );
    }

    #[test]
    fn should_use_correct_key_scope() {
        let mut test = IDkgLoadTranscriptTest::new_with_valid_params();

        let custom_vault_fn = Box::new(|vault: LocalCspVaultForTest| {
            let LocalCspVaultForTest {
                node_secret_key_store,
                canister_secret_key_store,
                public_key_store,
                ..
            } = vault;
            let csks = Arc::new(canister_secret_key_store);

            let mut mcsks = MockSecretKeyStore::new();
            {
                let csks = Arc::clone(&csks);
                mcsks
                    .expect_get()
                    .times(1)
                    .return_once(move |id| csks.read().get(id));
            }
            {
                let csks = Arc::clone(&csks);
                mcsks
                    .expect_insert_or_replace()
                    .times(1)
                    .withf(|_, _, scope| scope == &Some(IDKG_THRESHOLD_KEYS_SCOPE))
                    .return_once(move |id, key, scope| {
                        csks.write().insert_or_replace(id, key, scope)
                    });
            }

            Box::new(
                LocalCspVault::builder_for_test()
                    .with_canister_secret_key_store(mcsks)
                    .with_node_secret_key_store(node_secret_key_store.rw_lock.into_inner())
                    .with_public_key_store(public_key_store.rw_lock.into_inner())
                    .build(),
            ) as Box<dyn IDkgProtocolCspVault>
        });
        test.custom_vault_for_load_transcript_fn = Some(custom_vault_fn);

        assert_matches!(test.run(), Ok(complaints) if complaints.is_empty());
    }

    struct IDkgLoadTranscriptTest {
        algorithm_id: AlgorithmId,
        context_data: Vec<u8>,
        reconstruction_threshold: NumberOfNodes,
        transcript_operation: IDkgTranscriptOperation,
        key_id: Option<KeyId>,
        // perform `load_transcript` twice in a row
        load_twice: bool,
        /// A function for constructing a vault to be used in the call to
        /// `load_transctipt`. This allows to mock the canister/node secret key
        /// store or to remove the keys from the vault to trigger particular
        /// kinds of errors from the `load_transcript` call.
        custom_vault_for_load_transcript_fn: Option<CustomVaultFn>,
        additional_operation: Option<IDkgLoadTranscriptTestAdditionalOperation>,
    }

    #[derive(PartialEq)]
    enum IDkgLoadTranscriptTestAdditionalOperation {
        CorruptDealingEncodingInLoadArgs,
        CorruptInternalDealingForComplaint,
        CorruptInternalDealingCiphertext,
        CorruptTranscriptEncodingInLoadArgs,
        UseEmptyDealingMap,
    }

    impl IDkgLoadTranscriptTest {
        fn new_with_valid_params() -> Self {
            Self {
                algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
                context_data: vec![49; 10],
                reconstruction_threshold: NumberOfNodes::from(1),
                transcript_operation: IDkgTranscriptOperation::Random,
                load_twice: false,
                key_id: None,
                custom_vault_for_load_transcript_fn: None,
                additional_operation: None,
            }
        }

        fn run(
            self,
        ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
            let rng = &mut reproducible_rng();
            let vault = LocalCspVault::builder_for_test().build();
            let pk = vault
                .idkg_gen_dealing_encryption_key_pair()
                .expect("failed to generate key pair");
            let key_id = self.key_id.unwrap_or_else(|| {
                KeyId::try_from(&pk).expect("failed to generate the key id for the MEGA pubkey")
            });
            let pk_proto = idkg_dealing_encryption_pk_to_proto(pk.clone());
            let (dealing_bytes, internal_transcript) =
                self.dealing_bytes_and_internal_transcript(pk_proto, &vault);

            let signed_dealings = if self.additional_operation
                == Some(IDkgLoadTranscriptTestAdditionalOperation::UseEmptyDealingMap)
            {
                BTreeMap::new()
            } else {
                let internal_dealing_raw = self.internal_dealing_raw(dealing_bytes, rng);
                BTreeMap::from([(
                    DEALER_RECEIVER_INDEX,
                    // the signature is not verified here, so we just need some
                    // signature that contains the required content
                    dummy_batch_signed_dealing_with(internal_dealing_raw, node_id(456)),
                )])
            };

            let internal_transcript_bytes = IDkgTranscriptInternalBytes::from(
                if self.additional_operation
                == Some(IDkgLoadTranscriptTestAdditionalOperation::CorruptTranscriptEncodingInLoadArgs) {
                    vec![0xFF; 100]
                } else {
                    internal_transcript
                        .serialize()
                        .expect("failed to serialize transcript")
                },
            );

            let loader_vault: Box<dyn IDkgProtocolCspVault> =
                if let Some(f) = self.custom_vault_for_load_transcript_fn {
                    f(vault)
                } else {
                    Box::new(vault)
                };

            // load the same transcript twice in a row if requested, since the
            // second time should be a no-op
            let mut remaining_iterations = 1 + self.load_twice as usize;
            loop {
                let result = loader_vault.idkg_load_transcript(
                    self.algorithm_id,
                    signed_dealings.clone(),
                    self.context_data.clone(),
                    DEALER_RECEIVER_INDEX,
                    key_id,
                    IDkgTranscriptInternalBytes::from(internal_transcript_bytes.as_ref().to_vec()),
                )?;
                remaining_iterations -= 1;
                if remaining_iterations == 0 {
                    break Ok(result);
                }
            }
        }

        fn dealing_bytes_and_internal_transcript(
            &self,
            pk_proto: PublicKey,
            vault: &LocalCspVaultForTest,
        ) -> (IDkgDealingInternalBytes, IDkgTranscriptInternal) {
            let dealing_bytes = vault
                .idkg_create_dealing(
                    self.algorithm_id,
                    self.context_data.clone(),
                    DEALER_RECEIVER_INDEX,
                    self.reconstruction_threshold,
                    vec![pk_proto],
                    self.transcript_operation.clone(),
                )
                .expect("failed to generate dealing");

            let internal_transcript = IDkgTranscriptInternal::new(
                EccCurveType::K256,
                self.reconstruction_threshold.get() as usize,
                &BTreeMap::from([(
                    DEALER_RECEIVER_INDEX,
                    IDkgDealingInternal::deserialize(dealing_bytes.as_ref())
                        .expect("failed to deserialize internal dealing"),
                )]),
                &IDkgTranscriptOperationInternal::Random,
            )
            .expect("failed to create internal transcript");
            (dealing_bytes, internal_transcript)
        }

        fn internal_dealing_raw<R: Rng + CryptoRng>(
            &self,
            dealing_bytes: IDkgDealingInternalBytes,
            rng: &mut R,
        ) -> Vec<u8> {
            if self.additional_operation
                == Some(IDkgLoadTranscriptTestAdditionalOperation::CorruptDealingEncodingInLoadArgs)
            {
                vec![0xFF; 100]
            } else if self.additional_operation
                == Some(
                    IDkgLoadTranscriptTestAdditionalOperation::CorruptInternalDealingForComplaint,
                )
            {
                let internal_dealing = IDkgDealingInternal::deserialize(dealing_bytes.as_ref())
                    .expect("failed to deserialize dealing");
                let corrupted_internal_dealing =
                    corrupt_dealing(&internal_dealing, &[0], Seed::from_rng(rng))
                        .expect("failed to corrupt dealing");
                corrupted_internal_dealing
                    .serialize()
                    .expect("failed to serialize corrupted internal dealing")
            } else if self.additional_operation
                == Some(IDkgLoadTranscriptTestAdditionalOperation::CorruptInternalDealingCiphertext)
            {
                let mut internal_dealing = IDkgDealingInternal::deserialize(dealing_bytes.as_ref())
                    .expect("failed to deserialize dealing");
                let mismatching_curve = EccCurveType::P256;
                let random_ephemeral_key = EccPoint::generator_g(mismatching_curve)
                    .scalar_mul(&EccScalar::random(mismatching_curve, rng))
                    .expect("failed to generate a random point");
                match &mut internal_dealing.ciphertext {
                    MEGaCiphertext::Single(c) => c.ephemeral_key = random_ephemeral_key,
                    MEGaCiphertext::Pairs(c) => c.ephemeral_key = random_ephemeral_key,
                }
                internal_dealing
                    .serialize()
                    .expect("failed to serialize corrupted internal dealing")
            } else {
                dealing_bytes.as_ref().to_vec()
            }
        }
    }
}

mod idkg_load_transcript_with_openings {
    use super::*;

    use crate::key_id::KeyId;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::secret_key_store::SecretKeyStoreWriteError;
    use crate::types::CspSecretKey;
    use crate::vault::api::{IDkgDealingInternalBytes, IDkgTranscriptInternalBytes};
    use crate::vault::local_csp_vault::idkg::IDkgDealingInternal;
    use assert_matches::assert_matches;
    use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
    use ic_crypto_internal_seed::Seed;
    use ic_crypto_internal_threshold_sig_ecdsa::test_utils::corrupt_dealing;
    use ic_crypto_internal_threshold_sig_ecdsa::{
        EccCurveType, EccPoint, EccScalar, IDkgTranscriptInternal, IDkgTranscriptOperationInternal,
        MEGaCiphertext,
    };
    use ic_crypto_internal_types::NodeIndex;
    use ic_crypto_secrets_containers::SecretArray;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_types::crypto::canister_threshold_sig::error::IDkgLoadTranscriptError;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation;
    use ic_types::crypto::AlgorithmId;
    use ic_types::NumberOfNodes;
    use rand::{CryptoRng, Rng};
    use std::collections::BTreeMap;

    type CustomVaultFn = Box<dyn FnOnce(LocalCspVaultForTest) -> Box<dyn IDkgProtocolCspVault>>;

    /// In this test collection, we only use one party, so the dealer is the
    /// receiver and the index is always 0.
    const DEALER_RECEIVER_INDEX: NodeIndex = 0;

    // In addition to these tests, there are also some integration tests in the
    // crypto component that ensure that this works in the higher-level API.
    #[test]
    fn should_work_if_openings_are_not_needed() {
        assert_matches!(
            IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params().run(),
            Ok(())
        );
    }

    #[test]
    fn should_work_if_enough_openings_provided() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();
        test.additional_operation = Some(
            IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::CorruptInternalDealingForComplaint,
        );
        assert_matches!(test.run(), Ok(()));
    }

    #[test]
    fn should_work_if_enough_openings_provided_and_commitment_is_already_loaded_in_sks() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();
        test.load_twice = true;
        assert_matches!(test.run(), Ok(()));
    }

    #[test]
    fn should_fail_if_deserialization_of_internal_dealings_fails() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();
        test.additional_operation = Some(
            IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::CorruptDealingEncodingInLoadArgs,
        );
        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::SerializationError { internal_error })
            if internal_error.contains("failed to deserialize internal dealing")
        );
    }

    #[test]
    fn should_fail_if_deserialization_of_internal_transcript_fails() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();
        test.additional_operation = Some(
            IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::CorruptTranscriptEncodingInLoadArgs,
        );
        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::SerializationError { internal_error })
            if internal_error.contains("failed to deserialize internal transcript")
        );
    }

    #[test]
    fn should_fail_on_errors_from_compute_secret_shares() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();
        test.additional_operation =
            Some(IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::UseEmptyDealingMap);
        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::InvalidArguments { internal_error })
            if internal_error.contains("UnableToCombineOpenings")
        );
    }

    #[test]
    fn should_fail_if_key_bytes_from_sks_are_not_mega_encryption_k256() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();

        let custom_vault_fn = Box::new(|_vault: LocalCspVaultForTest| {
            let mut mnsks = MockSecretKeyStore::new();
            let invalid_key_for_idkg = CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
                SecretArray::new_and_dont_zeroize_argument(&[0; 32]),
            ));
            mnsks
                .expect_get()
                .times(1)
                .return_once(|_| Some(invalid_key_for_idkg));
            Box::new(
                LocalCspVault::builder_for_test()
                    .with_node_secret_key_store(mnsks)
                    .build(),
            ) as Box<dyn IDkgProtocolCspVault>
        });
        test.custom_vault_for_load_transcript_with_openings_fn = Some(custom_vault_fn);

        assert_matches!(test.run(),
            Err(IDkgLoadTranscriptError::SerializationError{ internal_error })
            if internal_error.contains("is not a MEGa encryption key set")
        );
    }

    #[test]
    fn should_fail_if_mega_keys_not_found() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();
        let custom_vault_fn = Box::new(|_vault| {
            // By constructing a new vault here, we lose the keys, so the call
            // to `load_transcripts` will not find the needed private key.
            Box::new(LocalCspVault::builder_for_test().build()) as Box<dyn IDkgProtocolCspVault>
        });
        test.custom_vault_for_load_transcript_with_openings_fn = Some(custom_vault_fn);

        assert_matches!(test.run(), Err(IDkgLoadTranscriptError::PrivateKeyNotFound));
    }

    #[test]
    fn should_fail_if_cannot_decrypt_openings() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();
        test.additional_operation = Some(
            IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::CorruptInternalDealingCiphertext,
        );
        test.use_empty_openings = true;
        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::InvalidArguments{internal_error})
            if internal_error.contains("InvalidCiphertext") && internal_error.contains("CurveMismatch")
        );
    }

    #[test]
    fn should_fail_if_sks_insertion_fails() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();

        let custom_vault_fn = custom_vault_fn_returning(
            SecretKeyStoreWriteError::SerializationError("test".to_string()),
        );
        test.custom_vault_for_load_transcript_with_openings_fn = Some(custom_vault_fn);

        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::InternalError{internal_error})
            if internal_error == "test"
        );
    }

    #[test]
    fn should_fail_on_transient_internal_errors_from_sks() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();
        let custom_vault_fn =
            custom_vault_fn_returning(SecretKeyStoreWriteError::TransientError("test".to_string()));
        test.custom_vault_for_load_transcript_with_openings_fn = Some(Box::new(custom_vault_fn));

        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::TransientInternalError{internal_error})
            if internal_error == "test"
        );
    }

    #[test]
    fn should_fail_if_openings_needed_but_none_were_provided() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();
        test.additional_operation =
        Some(IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::CorruptInternalDealingForComplaint);
        test.use_empty_openings = true;
        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::InvalidArguments { internal_error })
            if internal_error == "An invalid dealing with no openings was provided"
        );
    }

    #[test]
    fn should_fail_on_insufficient_number_of_openings() {
        let mut test = IDkgLoadTranscriptWithOpeningsTest::new_with_valid_params();
        test.reconstruction_threshold_in_transcript = Some(NumberOfNodes::from(2));

        assert_matches!(
            test.run(),
            Err(IDkgLoadTranscriptError::InsufficientOpenings { internal_error })
            if internal_error == "InsufficientOpenings(1, 2)"
        );
    }

    struct IDkgLoadTranscriptWithOpeningsTest {
        algorithm_id: AlgorithmId,
        context_data: Vec<u8>,
        reconstruction_threshold: NumberOfNodes,
        /// An eventually different threshold to trigger the
        /// `InsufficientOpenings` error
        reconstruction_threshold_in_transcript: Option<NumberOfNodes>,
        transcript_operation: IDkgTranscriptOperation,
        key_id: Option<KeyId>,
        /// Perform `load_transcript_with_openings` twice in a row
        load_twice: bool,
        use_empty_openings: bool,
        /// A function for constructing a vault to be used in the call to
        /// `load_transctipt`. This allows to mock the canister/node secret key
        /// store or to remove the keys from the vault to trigger particular
        /// kinds of errors from the `load_transcript_with_openings` call.
        custom_vault_for_load_transcript_with_openings_fn: Option<CustomVaultFn>,
        additional_operation: Option<IDkgLoadTranscriptWithOpeningsTestAdditionalOperation>,
    }

    #[derive(PartialEq)]
    enum IDkgLoadTranscriptWithOpeningsTestAdditionalOperation {
        CorruptDealingEncodingInLoadArgs,
        CorruptInternalDealingForComplaint,
        CorruptInternalDealingCiphertext,
        CorruptTranscriptEncodingInLoadArgs,
        UseEmptyDealingMap,
    }

    impl IDkgLoadTranscriptWithOpeningsTest {
        fn new_with_valid_params() -> Self {
            Self {
                algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
                context_data: vec![49; 10],
                reconstruction_threshold: NumberOfNodes::from(1),
                reconstruction_threshold_in_transcript: None,
                transcript_operation: IDkgTranscriptOperation::Random,
                load_twice: false,
                use_empty_openings: false,
                key_id: None,
                custom_vault_for_load_transcript_with_openings_fn: None,
                additional_operation: None,
            }
        }

        fn run(self) -> Result<(), IDkgLoadTranscriptError> {
            let rng = &mut reproducible_rng();
            let vault = LocalCspVault::builder_for_test().build();

            let pk = vault
                .idkg_gen_dealing_encryption_key_pair()
                .expect("failed to generate key pair");
            let key_id = self.key_id.unwrap_or_else(|| {
                KeyId::try_from(&pk).expect("failed to generate the key id for the MEGA pubkey")
            });
            let pk_proto = idkg_dealing_encryption_pk_to_proto(pk.clone());
            let (dealing_bytes, internal_transcript) =
                self.dealing_bytes_and_internal_transcript(pk_proto, &vault);

            let correct_signed_dealings_for_open_dealing = {
                let internal_dealing_raw = dealing_bytes.as_ref().to_vec();
                BTreeMap::from([(
                    DEALER_RECEIVER_INDEX,
                    // the signature is not verified here, so we just need some
                    // signature that contains the required content
                    dummy_batch_signed_dealing_with(internal_dealing_raw, node_id(456)),
                )])
            };

            let signed_dealings = if self.additional_operation
                == Some(IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::UseEmptyDealingMap)
            {
                BTreeMap::new()
            } else {
                let internal_dealing_raw = self.internal_dealing_raw(dealing_bytes, rng);
                BTreeMap::from([(
                    DEALER_RECEIVER_INDEX,
                    // the signature is not verified here, so we just need some
                    // signature that contains the required content
                    dummy_batch_signed_dealing_with(internal_dealing_raw, node_id(456)),
                )])
            };

            let internal_transcript_bytes = IDkgTranscriptInternalBytes::from(
                if self.additional_operation
                == Some(IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::CorruptTranscriptEncodingInLoadArgs) {
                    vec![0xFF; 100]
                } else {
                    internal_transcript
                        .serialize()
                        .expect("failed to serialize transcript")
                },
            );

            let opening = vault
                .idkg_open_dealing(
                    self.algorithm_id,
                    correct_signed_dealings_for_open_dealing
                        .values()
                        .next()
                        .expect("empty dealings")
                        .clone(),
                    0,
                    self.context_data.clone(),
                    0,
                    key_id,
                )
                .expect("failed to obtain opening");

            let openings = if self.use_empty_openings {
                BTreeMap::new()
            } else {
                BTreeMap::from([(0u32, BTreeMap::from([(0u32, opening.clone())]))])
            };

            let loader_vault: Box<dyn IDkgProtocolCspVault> =
                if let Some(f) = self.custom_vault_for_load_transcript_with_openings_fn {
                    f(vault)
                } else {
                    Box::new(vault)
                };

            // load the same transcript and openings twice in a row if
            // requested, since the second time should be a no-op
            let mut remaining_iterations = 1 + self.load_twice as usize;
            while remaining_iterations != 0 {
                loader_vault.idkg_load_transcript_with_openings(
                    self.algorithm_id,
                    signed_dealings.clone(),
                    openings.clone(),
                    self.context_data.clone(),
                    DEALER_RECEIVER_INDEX,
                    key_id,
                    internal_transcript_bytes.as_ref().to_vec().into(),
                )?;
                remaining_iterations -= 1;
            }
            Ok(())
        }

        fn dealing_bytes_and_internal_transcript(
            &self,
            pk_proto: PublicKey,
            vault: &LocalCspVaultForTest,
        ) -> (IDkgDealingInternalBytes, IDkgTranscriptInternal) {
            let reconstruction_threshold_in_transcript = self
                .reconstruction_threshold_in_transcript
                .unwrap_or(self.reconstruction_threshold);
            let receiver_keys = {
                let mut result = vec![];
                for _ in 0..reconstruction_threshold_in_transcript.get() {
                    result.push(pk_proto.clone());
                }
                result
            };

            let dealing_bytes = vault
                .idkg_create_dealing(
                    self.algorithm_id,
                    self.context_data.clone(),
                    DEALER_RECEIVER_INDEX,
                    reconstruction_threshold_in_transcript,
                    receiver_keys,
                    self.transcript_operation.clone(),
                )
                .expect("failed to generate dealing");

            let dealing_map = BTreeMap::from([(
                DEALER_RECEIVER_INDEX,
                IDkgDealingInternal::deserialize(dealing_bytes.as_ref())
                    .expect("failed to deserialize internal dealing"),
            )]);

            let internal_transcript = IDkgTranscriptInternal::new(
                EccCurveType::K256,
                reconstruction_threshold_in_transcript.get() as usize,
                &dealing_map,
                &IDkgTranscriptOperationInternal::Random,
            )
            .expect("failed to create internal transcript");
            (dealing_bytes, internal_transcript)
        }

        fn internal_dealing_raw<R: Rng + CryptoRng>(
            &self,
            dealing_bytes: IDkgDealingInternalBytes,
            rng: &mut R,
        ) -> Vec<u8> {
            if self.additional_operation
                == Some(IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::CorruptDealingEncodingInLoadArgs)
            {
                vec![0xFF; 100]
            } else if self.additional_operation
                == Some(
                    IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::CorruptInternalDealingForComplaint,
                )
            {
                let internal_dealing = IDkgDealingInternal::deserialize(dealing_bytes.as_ref())
                    .expect("failed to deserialize dealing");
                let corrupted_internal_dealing =
                    corrupt_dealing(&internal_dealing, &[0], Seed::from_rng(rng))
                        .expect("failed to corrupt dealing");
                corrupted_internal_dealing
                    .serialize()
                    .expect("failed to serialize corrupted internal dealing")
            } else if self.additional_operation
                == Some(IDkgLoadTranscriptWithOpeningsTestAdditionalOperation::CorruptInternalDealingCiphertext)
            {
                let mut internal_dealing = IDkgDealingInternal::deserialize(dealing_bytes.as_ref())
                    .expect("failed to deserialize dealing");
                let mismatching_curve = EccCurveType::P256;
                let random_ephemeral_key = EccPoint::generator_g(mismatching_curve)
                    .scalar_mul(&EccScalar::random(mismatching_curve, rng))
                    .expect("failed to generate a random point");
                match &mut internal_dealing.ciphertext {
                    MEGaCiphertext::Single(c) => c.ephemeral_key = random_ephemeral_key,
                    MEGaCiphertext::Pairs(c) => c.ephemeral_key = random_ephemeral_key,
                }
                internal_dealing
                    .serialize()
                    .expect("failed to serialize corrupted internal dealing")
            } else {
                dealing_bytes.as_ref().to_vec()
            }
        }
    }
}

mod idkg_open_dealing {
    use super::*;
    use crate::{types::CspSecretKey, vault::api::IDkgDealingInternalBytes};
    use ic_crypto_internal_threshold_sig_ecdsa::{CommitmentOpening, MEGaPublicKeyK256Bytes};
    use ic_types::{
        crypto::{
            canister_threshold_sig::{
                error::IDkgOpenTranscriptError, idkg::IDkgTranscriptOperation,
            },
            AlgorithmId,
        },
        NumberOfNodes,
    };

    /// Dealer/receiver/opener index.
    const NODE_INDEX: NodeIndex = 0;
    const CONTEXT_DATA: [u8; 10] = [49; 10];

    #[test]
    fn should_work() {
        assert_matches!(IDkgOpenDealingTest::new_with_valid_params().run(), Ok(_));
    }

    #[test]
    fn should_fail_on_invalid_dealing_raw_encoding() {
        let mut test = IDkgOpenDealingTest::new_with_valid_params();
        test.additional_operation =
            Some(IDkgOpenDealingTestAdditionalOperation::UseDealingWithInvalidEncoding);

        assert_matches!(
            test.run(),
            Err(IDkgOpenTranscriptError::InternalError { internal_error })
            if internal_error.contains("Error deserializing a signed dealing: CanisterThresholdSerializationError")
        );
    }

    #[test]
    fn should_fail_if_private_key_not_found() {
        let mut test = IDkgOpenDealingTest::new_with_valid_params();
        // Using a new vault here will cause the private key to be missing
        test.custom_vault_fn =
            Box::new(|_vault| Box::new(LocalCspVault::builder_for_test().build()));
        assert_matches!(
            test.run(),
            Err(IDkgOpenTranscriptError::PrivateKeyNotFound { .. })
        );
    }

    #[test]
    fn should_fail_if_mega_keyset_has_invalid_serialization() {
        let mut test = IDkgOpenDealingTest::new_with_valid_params();

        test.custom_vault_fn = Box::new(|vault| {
            let vault_arc = Arc::new(vault);
            let mut mnsks = MockSecretKeyStore::new();

            let encoding_with_invalid_k256_point = [
                33, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ];
            let mega_pk_bytes_with_invalid_point_encoding: MEGaPublicKeyK256Bytes =
                bincode::deserialize(&encoding_with_invalid_k256_point).expect(
                    "failed to deserialize an invalid k256 point into MEGaPublicKeyK256Bytes",
                );

            {
                let vault_arc = Arc::clone(&vault_arc);
                mnsks.expect_get().times(1).return_once(move |key_id| {
                    let mut key = vault_arc.sks_read_lock().get(key_id);
                    match &mut key {
                        Some(CspSecretKey::MEGaEncryptionK256(keyset_bytes)) => {
                            // replace public key with one on a wrong curve
                            keyset_bytes.public_key = mega_pk_bytes_with_invalid_point_encoding;
                        }
                        _ => panic!("expected a call to N-SKS to get a MEGa keyset"),
                    }
                    key
                });
            }

            Box::new(
                LocalCspVault::builder_for_test()
                    .with_node_secret_key_store(mnsks)
                    .build(),
            )
        });
        assert_matches!(
            test.run(),
            Err(IDkgOpenTranscriptError::InternalError { internal_error })
            if internal_error.contains("DeserializationError") && internal_error.contains("InvalidPoint")
        );
    }

    #[test]
    fn should_fail_on_invalid_commitment() {
        let mut test = IDkgOpenDealingTest::new_with_valid_params();
        test.custom_vault_fn = Box::new(|_vault| {
            // create a new keyset
            let tmp_vault = LocalCspVault::builder_for_test().build();
            let pk = tmp_vault
                .idkg_gen_dealing_encryption_key_pair()
                .expect("failed to generate key pair");

            let mut mnsks = MockSecretKeyStore::new();
            mnsks.expect_get().times(1).return_once(move |_key_id| {
                let wrong_key_that_will_fail_to_decrypt_ciphertexts =
                    tmp_vault.sks_read_lock().get(
                        &KeyId::try_from(&pk).expect("failed to convert a public key to the KeyId"),
                    );
                wrong_key_that_will_fail_to_decrypt_ciphertexts
            });

            Box::new(
                LocalCspVault::builder_for_test()
                    .with_node_secret_key_store(mnsks)
                    .build(),
            )
        });

        // because we replaced the keyset, the decryption results in an invalid
        // opening, which is mapped to an `InvalidCommitment` error
        assert_matches!(
            test.run(),
            Err(IDkgOpenTranscriptError::InternalError { internal_error })
            if internal_error.contains("InvalidCommitment")
        );
    }

    struct IDkgOpenDealingTest {
        additional_operation: Option<IDkgOpenDealingTestAdditionalOperation>,
        custom_vault_fn: CustomVaultFn,
        algorithm_id: AlgorithmId,
    }

    #[derive(PartialEq)]
    enum IDkgOpenDealingTestAdditionalOperation {
        UseDealingWithInvalidEncoding,
    }

    impl IDkgOpenDealingTest {
        fn new_with_valid_params() -> Self {
            Self {
                additional_operation: None,
                custom_vault_fn: Box::new(|vault| Box::new(vault) as Box<dyn IDkgProtocolCspVault>),
                algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            }
        }

        fn run(self) -> Result<CommitmentOpening, IDkgOpenTranscriptError> {
            let vault = LocalCspVault::builder_for_test().build();

            let pk = vault
                .idkg_gen_dealing_encryption_key_pair()
                .expect("failed to generate key pair");
            let key_id =
                KeyId::try_from(&pk).expect("failed to generate the key id for the MEGA pubkey");
            let pk_proto = idkg_dealing_encryption_pk_to_proto(pk.clone());
            let dealing_bytes = self.dealing_bytes(pk_proto, &vault);

            let signed_dealings = BTreeMap::from([(
                NODE_INDEX,
                // the signature is not verified here, so we just need some
                // signature that contains the required content
                dummy_batch_signed_dealing_with(dealing_bytes.as_ref().to_vec(), node_id(456)),
            )]);

            let dealing = match self.additional_operation {
                Some(IDkgOpenDealingTestAdditionalOperation::UseDealingWithInvalidEncoding) => {
                    let invalid_internal_dealing_raw = vec![0xFFu8; 100];
                    dummy_batch_signed_dealing_with(invalid_internal_dealing_raw, node_id(456))
                }
                None => signed_dealings
                    .values()
                    .next()
                    .expect("empty dealings")
                    .clone(),
            };

            let opener_vault = (self.custom_vault_fn)(vault);
            opener_vault.idkg_open_dealing(
                self.algorithm_id,
                dealing,
                NODE_INDEX,
                CONTEXT_DATA.to_vec(),
                NODE_INDEX,
                key_id,
            )
        }

        fn dealing_bytes(
            &self,
            pk_proto: PublicKey,
            vault: &LocalCspVaultForTest,
        ) -> IDkgDealingInternalBytes {
            let reconstruction_threshold_in_transcript = NumberOfNodes::from(2);
            let receiver_keys = {
                let mut result = vec![];
                for _ in 0..reconstruction_threshold_in_transcript.get() {
                    result.push(pk_proto.clone());
                }
                result
            };

            vault
                .idkg_create_dealing(
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    CONTEXT_DATA.to_vec(),
                    NODE_INDEX,
                    reconstruction_threshold_in_transcript,
                    receiver_keys,
                    IDkgTranscriptOperation::Random,
                )
                .expect("failed to generate dealing")
        }
    }
}

pub(crate) fn dummy_batch_signed_dealing_with(
    internal_dealing_raw: Vec<u8>,
    dealer_id: NodeId,
) -> BatchSignedIDkgDealing {
    let dealing = IDkgDealing {
        transcript_id: dummy_idkg_transcript_id_for_tests(123),
        internal_dealing_raw,
    };
    let signed_dealing = SignedIDkgDealing {
        content: dealing,
        signature: BasicSignature {
            signature: BasicSigOf::new(BasicSig(vec![1, 2, 3])),
            signer: dealer_id,
        },
    };
    BatchSignedIDkgDealing {
        content: signed_dealing,
        signature: BasicSignatureBatch {
            signatures_map: BTreeMap::new(),
        },
    }
}

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

/// Creates a new vault with mocked SKSs that will be used in
/// `load_transcript[_with_openings]` and returns `csks_insert_or_replace_error`
/// in an internal call to `canister_secret_key_store.insert_or_replace()`.
fn custom_vault_fn_returning(
    csks_insert_or_replace_error: SecretKeyStoreWriteError,
) -> CustomVaultFn {
    let f = |vault: LocalCspVaultForTest| {
        let mut sequence = Sequence::new();
        let vault_arc = Arc::new(vault);

        let mut mnsks = MockSecretKeyStore::new();
        let mut mcsks = MockSecretKeyStore::new();

        {
            let vault_arc = vault_arc.clone();
            mcsks
                .expect_get()
                .times(1)
                .return_once(move |key_id| vault_arc.canister_sks_read_lock().get(key_id))
                .in_sequence(&mut sequence);
        }

        mnsks
            .expect_get()
            .times(1)
            .return_once(move |key_id| vault_arc.sks_read_lock().get(key_id))
            .in_sequence(&mut sequence);

        mcsks
            .expect_insert_or_replace()
            .times(1)
            .return_once(move |_, _, _| Err(csks_insert_or_replace_error))
            .in_sequence(&mut sequence);

        Box::new(
            LocalCspVault::builder_for_test()
                .with_canister_secret_key_store(mcsks)
                .with_node_secret_key_store(mnsks)
                .build(),
        ) as Box<dyn IDkgProtocolCspVault>
    };
    Box::new(f)
}
