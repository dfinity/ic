//! Tests of the whole NiDKG protocol
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
use crate::public_key_store::PublicKeySetOnceError;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
use crate::secret_key_store::SecretKeyStoreInsertionError;
use crate::vault::api::NiDkgCspVault;
use crate::vault::local_csp_vault::ni_dkg::ni_dkg_clib::types::FsEncryptionKeySetWithPop;
use crate::vault::local_csp_vault::ni_dkg::ni_dkg_clib::types::FsEncryptionSecretKey;
use crate::vault::local_csp_vault::ni_dkg::CspFsEncryptionKeySet;
use crate::vault::local_csp_vault::ni_dkg::CspNiDkgTranscript;
use crate::vault::local_csp_vault::ni_dkg::CspSecretKey;
use crate::vault::local_csp_vault::ni_dkg::Epoch;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::test_utils;
use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;
use assert_matches::assert_matches;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InternalError;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateFsKeyError, CspDkgLoadPrivateKeyError,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::FsEncryptionPop;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::FsEncryptionPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::Transcript;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_types::crypto::AlgorithmId;
use ic_types_test_utils::ids::NODE_42;

use crate::key_id::KeyId;
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
      test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(seed, network_size, num_reshares, || LocalCspVault::builder_for_test().build_into_arc() );
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
      test_utils::ni_dkg::test_create_dealing_should_detect_errors(seed, network_size, num_reshares, || LocalCspVault::builder_for_test().build_into_arc());
    }
}

#[test]
fn test_retention() {
    test_utils::ni_dkg::test_retention(|| LocalCspVault::builder_for_test().build_into_arc());
}

#[test]
fn should_generate_dealing_encryption_key_pair_and_store_keys() {
    test_utils::ni_dkg::should_generate_dealing_encryption_key_pair_and_store_keys(
        LocalCspVault::builder_for_test().build_into_arc(),
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
    let vault = LocalCspVault::builder_for_test()
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
    let vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks_returning_already_set_error)
        .build_into_arc();
    test_utils::ni_dkg::should_fail_with_internal_error_if_ni_dkg_dealing_encryption_key_already_set(vault);
}

#[test]
fn should_fail_with_internal_error_if_dkg_dealing_encryption_key_generated_more_than_once() {
    let vault = LocalCspVault::builder_for_test().build_into_arc();
    test_utils::ni_dkg::should_fail_with_internal_error_if_dkg_dealing_encryption_key_generated_more_than_once(vault);
}

#[test]
fn should_fail_with_transient_internal_error_if_dkg_dealing_encryption_key_persistence_fails() {
    let mut pks_returning_io_error = MockPublicKeyStore::new();
    let io_error = io::Error::new(io::ErrorKind::Other, "oh no!");
    pks_returning_io_error
        .expect_set_once_ni_dkg_dealing_encryption_pubkey()
        .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
    let vault = LocalCspVault::builder_for_test()
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
        .return_const(Err(SecretKeyStoreInsertionError::TransientError(
            expected_io_error.clone(),
        )));
    let vault = LocalCspVault::builder_for_test()
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
        .return_const(Err(SecretKeyStoreInsertionError::SerializationError(
            expected_serialization_error.clone(),
        )));
    let vault = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks_returning_serialization_error)
        .build();

    let result = vault.gen_dealing_encryption_key_pair(NODE_42);

    assert_matches!(
        result,
        Err(CspDkgCreateFsKeyError::InternalError(InternalError{ internal_error }))
        if internal_error.contains(&expected_serialization_error)
    );
}

#[test]
fn should_return_internal_error_from_load_threshold_signing_key_internal_if_nidkg_secret_key_persistence_fails_due_to_serialization_error(
) {
    const INTERNAL_ERROR: &str = "cannot serialize keys";
    let fs_key_id = KeyId::from([0u8; 32]);
    let vault = csp_vault_with_fs_key_id_and_mock_secret_key_store_insert_error(
        fs_key_id,
        SecretKeyStoreInsertionError::SerializationError(INTERNAL_ERROR.to_string()),
    );

    let result = load_threshold_signing_key_for_empty_transcript_with_key_id(fs_key_id, vault);

    assert_matches!(
        result,
        Err(CspDkgLoadPrivateKeyError::InternalError(InternalError{internal_error}))
        if internal_error.contains(INTERNAL_ERROR)
    );
}

#[test]
fn should_return_transient_internal_error_from_load_threshold_signing_key_if_nidkg_secret_key_persistence_fails_due_to_transient_internal_error(
) {
    const INTERNAL_ERROR: &str = "transient internal error";
    let fs_key_id = KeyId::from([0u8; 32]);
    let vault = csp_vault_with_fs_key_id_and_mock_secret_key_store_insert_error(
        fs_key_id,
        SecretKeyStoreInsertionError::TransientError(INTERNAL_ERROR.to_string()),
    );

    let result = load_threshold_signing_key_for_empty_transcript_with_key_id(fs_key_id, vault);

    assert_matches!(
        result,
        Err(CspDkgLoadPrivateKeyError::TransientInternalError(InternalError{internal_error}))
        if internal_error.contains(INTERNAL_ERROR)
    );
}

fn csp_vault_with_fs_key_id_and_mock_secret_key_store_insert_error(
    fs_key_id: KeyId,
    insert_error: SecretKeyStoreInsertionError,
) -> LocalCspVault<ReproducibleRng, MockSecretKeyStore, TempSecretKeyStore, TempPublicKeyStore> {
    let mut sks_returning_transient_internal_error = MockSecretKeyStore::new();
    sks_returning_transient_internal_error
        .expect_insert()
        .times(1)
        .return_const(Err(insert_error));
    sks_returning_transient_internal_error
        .expect_get()
        .withf(move |key_id| key_id == &fs_key_id)
        .return_const(arbitrary_fs_encryption_key_set());
    sks_returning_transient_internal_error
        .expect_get()
        .return_const(None);
    LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks_returning_transient_internal_error)
        .build()
}

fn load_threshold_signing_key_for_empty_transcript_with_key_id(
    fs_key_id: KeyId,
    vault: LocalCspVault<
        ReproducibleRng,
        MockSecretKeyStore,
        TempSecretKeyStore,
        TempPublicKeyStore,
    >,
) -> Result<(), CspDkgLoadPrivateKeyError> {
    let algorithm_id = AlgorithmId::NiDkg_Groth20_Bls12_381;
    let epoch = Epoch::new(135);
    let csp_transcript = empty_ni_csp_dkg_transcript();
    let receiver_index = 37_u32;

    vault.load_threshold_signing_key(
        algorithm_id,
        epoch,
        csp_transcript,
        fs_key_id,
        receiver_index,
    )
}

fn arbitrary_fs_encryption_key_set() -> CspSecretKey {
    // TODO(CRP-862): produce random values rather than default.
    //  Copied from ic_crypto_internal_csp::types::test_utils::arbitrary_fs_encryption_key_set
    let fs_enc_key_set = FsEncryptionKeySetWithPop {
        public_key: FsEncryptionPublicKey(Default::default()),
        pop: FsEncryptionPop {
            pop_key: Default::default(),
            challenge: Default::default(),
            response: Default::default(),
        },
        secret_key: FsEncryptionSecretKey { bte_nodes: vec![] },
    };
    CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(
        fs_enc_key_set,
    ))
}

fn empty_ni_csp_dkg_transcript() -> CspNiDkgTranscript {
    CspNiDkgTranscript::Groth20_Bls12_381(Transcript {
        public_coefficients: PublicCoefficientsBytes {
            coefficients: vec![],
        },
        receiver_data: Default::default(),
    })
}
