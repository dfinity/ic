//! Tests of Multi-Signature operations in the CSP vault.
use mockall::Sequence;

use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::public_key_store::PublicKeySetOnceError;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::vault::api::CspMultiSignatureKeygenError;
use crate::vault::api::MultiSignatureCspVault;
use crate::vault::local_csp_vault::multi_sig::SecretKeyStoreError;
use crate::vault::local_csp_vault::multi_sig::SecretKeyStorePersistenceError;
use crate::vault::test_utils;
use crate::LocalCspVault;
use assert_matches::assert_matches;

#[test]
fn should_generate_committee_signing_key_pair_and_store_keys() {
    test_utils::multi_sig::should_generate_committee_signing_key_pair_and_store_keys(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_store_committee_signing_secret_key_before_public_key() {
    let mut seq = Sequence::new();
    let mut sks = MockSecretKeyStore::new();
    sks.expect_insert()
        .times(1)
        .returning(|_key, _key_id, _scope| Ok(()))
        .in_sequence(&mut seq);
    let mut pks = MockPublicKeyStore::new();
    pks.expect_set_once_committee_signing_pubkey()
        .times(1)
        .returning(|_key| Ok(()))
        .in_sequence(&mut seq);
    let vault = LocalCspVault::builder()
        .with_node_secret_key_store(sks)
        .with_public_key_store(pks)
        .build_into_arc();

    let _ = vault.gen_committee_signing_key_pair();
}

#[test]
fn should_fail_with_internal_error_if_committee_signing_key_already_set() {
    let mut pks_returning_already_set_error = MockPublicKeyStore::new();
    pks_returning_already_set_error
        .expect_set_once_committee_signing_pubkey()
        .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
    let vault = LocalCspVault::builder()
        .with_public_key_store(pks_returning_already_set_error)
        .build_into_arc();
    test_utils::multi_sig::should_fail_with_internal_error_if_committee_signing_key_already_set(
        vault,
    );
}

#[test]
fn should_fail_with_transient_internal_error_if_node_signing_secret_key_persistence_fails_due_to_io_error(
) {
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

    let result = vault.gen_committee_signing_key_pair();

    assert_matches!(
        result,
        Err(CspMultiSignatureKeygenError::TransientInternalError { internal_error })
        if internal_error.contains(&expected_io_error)
    );
}

#[test]
fn should_fail_with_internal_error_if_node_signing_secret_key_persistence_fails_due_to_serialization_error(
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

    let result = vault.gen_committee_signing_key_pair();

    assert_matches!(
        result,
        Err(CspMultiSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains(&expected_serialization_error)
    );
}

#[test]
fn should_fail_with_internal_error_if_committee_signing_key_generated_more_than_once() {
    let vault = LocalCspVault::builder().build_into_arc();
    test_utils::multi_sig::should_fail_with_internal_error_if_committee_signing_key_generated_more_than_once(vault);
}

#[test]
fn should_fail_with_transient_internal_error_if_committee_signing_key_persistence_fails() {
    let mut pks_returning_io_error = MockPublicKeyStore::new();
    let io_error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!");
    pks_returning_io_error
        .expect_set_once_committee_signing_pubkey()
        .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
    let vault = LocalCspVault::builder()
        .with_public_key_store(pks_returning_io_error)
        .build_into_arc();
    test_utils::multi_sig::should_fail_with_transient_internal_error_if_committee_signing_key_persistence_fails(
        vault,
    );
}

#[test]
fn should_generate_verifiable_pop() {
    test_utils::multi_sig::should_generate_verifiable_pop(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_multi_sign_and_verify_with_generated_key() {
    test_utils::multi_sig::should_multi_sign_and_verify_with_generated_key(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
    test_utils::multi_sig::should_not_multi_sign_with_unsupported_algorithm_id(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
    test_utils::multi_sig::should_not_multi_sign_if_secret_key_in_store_has_wrong_type(
        LocalCspVault::builder().build_into_arc(),
    );
}
