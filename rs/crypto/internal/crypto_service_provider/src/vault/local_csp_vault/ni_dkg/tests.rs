//! Tests of the whole NiDKG protocol
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::public_key_store::PublicKeySetOnceError;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::secret_key_store::SecretKeyStoreError;
use crate::secret_key_store::SecretKeyStorePersistenceError;
use crate::vault::api::NiDkgCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::test_utils;
use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;
use assert_matches::assert_matches;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InternalError;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgCreateFsKeyError;
use ic_types_test_utils::ids::NODE_42;

use mockall::Sequence;
use proptest::prelude::*;
use std::io;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly(seed: [u8;32], network_size in MockNetwork::MIN_SIZE..MockNetwork::DEFAULT_MAX_SIZE, num_reshares in 0..4) {
      test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(seed, network_size, num_reshares, || LocalCspVault::builder().build_into_arc() );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn create_dealing_should_detect_errors(seed: [u8;32], network_size in MockNetwork::MIN_SIZE..=MockNetwork::DEFAULT_MAX_SIZE, num_reshares in 0..4) {
      test_utils::ni_dkg::test_create_dealing_should_detect_errors(seed, network_size, num_reshares, || LocalCspVault::builder().build_into_arc());
    }
}

#[test]
fn test_retention() {
    test_utils::ni_dkg::test_retention(|| LocalCspVault::builder().build_into_arc());
}

#[test]
fn should_generate_dealing_encryption_key_pair_and_store_keys() {
    test_utils::ni_dkg::should_generate_dealing_encryption_key_pair_and_store_keys(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_store_dkg_dealing_encryption_secret_key_before_public_key() {
    let mut seq = Sequence::new();
    let mut sks = MockSecretKeyStore::new();
    sks.expect_insert()
        .times(1)
        .returning(|_key, _key_id, _scope| Ok(()))
        .in_sequence(&mut seq);
    let mut pks = MockPublicKeyStore::new();
    pks.expect_set_once_ni_dkg_dealing_encryption_pubkey()
        .times(1)
        .returning(|_key| Ok(()))
        .in_sequence(&mut seq);
    let vault = LocalCspVault::builder()
        .with_node_secret_key_store(sks)
        .with_public_key_store(pks)
        .build_into_arc();

    assert!(vault.gen_dealing_encryption_key_pair(NODE_42).is_ok());
}

#[test]
fn should_fail_with_internal_error_if_dkg_dealing_encryption_key_already_set() {
    let mut pks_returning_already_set_error = MockPublicKeyStore::new();
    pks_returning_already_set_error
        .expect_set_once_ni_dkg_dealing_encryption_pubkey()
        .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
    let vault = LocalCspVault::builder()
        .with_public_key_store(pks_returning_already_set_error)
        .build_into_arc();
    test_utils::ni_dkg::should_fail_with_internal_error_if_ni_dkg_dealing_encryption_key_already_set(vault);
}

#[test]
fn should_fail_with_internal_error_if_dkg_dealing_encryption_key_generated_more_than_once() {
    let vault = LocalCspVault::builder().build_into_arc();
    test_utils::ni_dkg::should_fail_with_internal_error_if_dkg_dealing_encryption_key_generated_more_than_once(vault);
}

#[test]
fn should_fail_with_transient_internal_error_if_dkg_dealing_encryption_key_persistence_fails() {
    let mut pks_returning_io_error = MockPublicKeyStore::new();
    let io_error = io::Error::new(io::ErrorKind::Other, "oh no!");
    pks_returning_io_error
        .expect_set_once_ni_dkg_dealing_encryption_pubkey()
        .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
    let vault = LocalCspVault::builder()
        .with_public_key_store(pks_returning_io_error)
        .build_into_arc();
    test_utils::ni_dkg::should_fail_with_transient_internal_error_if_dkg_dealing_encryption_key_persistence_fails(
        vault,
    );
}

#[test]
fn should_fail_with_transient_internal_error_if_nidkg_secret_key_persistence_fails_due_to_io_error()
{
    let mut sks_returning_io_error = MockSecretKeyStore::new();
    let expected_io_error = "cannot write to file".to_string();
    sks_returning_io_error
        .expect_insert()
        .times(1)
        .return_const(Err(SecretKeyStoreError::PersistenceError(
            SecretKeyStorePersistenceError::IoError(expected_io_error.clone()),
        )));
    let vault = LocalCspVault::builder()
        .with_node_secret_key_store(sks_returning_io_error)
        .build();

    let result = vault.gen_dealing_encryption_key_pair(NODE_42);

    assert_matches!(
        result,
        Err(CspDkgCreateFsKeyError::TransientInternalError (internal_error))
        if internal_error.contains(&expected_io_error)
    );
}

#[test]
fn should_fail_with_internal_error_if_nidkg_secret_key_persistence_fails_due_to_serialization_error(
) {
    let mut sks_returning_serialization_error = MockSecretKeyStore::new();
    let expected_serialization_error = "cannot serialize keys".to_string();
    sks_returning_serialization_error
        .expect_insert()
        .times(1)
        .return_const(Err(SecretKeyStoreError::PersistenceError(
            SecretKeyStorePersistenceError::SerializationError(
                expected_serialization_error.clone(),
            ),
        )));
    let vault = LocalCspVault::builder()
        .with_node_secret_key_store(sks_returning_serialization_error)
        .build();

    let result = vault.gen_dealing_encryption_key_pair(NODE_42);

    assert_matches!(
        result,
        Err(CspDkgCreateFsKeyError::InternalError(InternalError{ internal_error }))
        if internal_error.contains(&expected_serialization_error)
    );
}
