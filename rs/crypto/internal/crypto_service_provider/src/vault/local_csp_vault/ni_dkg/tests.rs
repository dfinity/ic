//! Tests of the whole NiDKG protocol
use crate::public_key_store::PublicKeySetOnceError;
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
use crate::secret_key_store::SecretKeyStoreInsertionError;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
use crate::threshold::ni_dkg::NIDKG_THRESHOLD_SCOPE;
use crate::vault::api::NiDkgCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::local_csp_vault::ni_dkg::CspFsEncryptionKeySet;
use crate::vault::local_csp_vault::ni_dkg::CspNiDkgTranscript;
use crate::vault::local_csp_vault::ni_dkg::CspSecretKey;
use crate::vault::local_csp_vault::ni_dkg::Epoch;
use crate::vault::local_csp_vault::ni_dkg::NIDKG_FS_SCOPE;
use crate::vault::local_csp_vault::ni_dkg::ni_dkg_clib::types::FsEncryptionKeySetWithPop;
use crate::vault::local_csp_vault::ni_dkg::ni_dkg_clib::types::FsEncryptionSecretKey;
use crate::vault::test_utils;
use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;
use assert_matches::assert_matches;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InternalError;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgUpdateFsEpochError;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateFsKeyError, CspDkgLoadPrivateKeyError,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::FsEncryptionPop;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::FsEncryptionPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::Transcript;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_test_utils::set_of;
use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::error::KeyNotFoundError;
use ic_types_test_utils::ids::NODE_42;

use crate::key_id::KeyId;
use ic_crypto_internal_seed::Seed;
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
fn should_not_call_retain_if_keystore_would_not_be_modified() {
    let active_key_ids = set_of(&[KeyId::from([0u8; 32])]);
    let mut sks = MockSecretKeyStore::new();
    sks.expect_retain_would_modify_keystore()
        .withf(|_filter, scope| *scope == NIDKG_THRESHOLD_SCOPE)
        .return_const(false)
        .times(1);
    sks.expect_retain().never();
    let csp = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .build();

    assert_eq!(csp.retain_threshold_keys_if_present(active_key_ids), Ok(()));
}

#[test]
fn should_call_retain_if_keystore_would_be_modified() {
    let active_key_ids = set_of(&[KeyId::from([0u8; 32])]);
    let mut sks = MockSecretKeyStore::new();
    let mut seq = Sequence::new();
    sks.expect_retain_would_modify_keystore()
        .times(1)
        .in_sequence(&mut seq)
        .withf(|_filter, scope| *scope == NIDKG_THRESHOLD_SCOPE)
        .return_const(true);
    sks.expect_retain()
        .times(1)
        .in_sequence(&mut seq)
        .withf(|_filter, scope| *scope == NIDKG_THRESHOLD_SCOPE)
        .return_const(Ok(()));
    let csp = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .build();

    assert_eq!(csp.retain_threshold_keys_if_present(active_key_ids), Ok(()));
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
    let io_error = io::Error::other("oh no!");
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
fn should_fail_with_internal_error_if_nidkg_secret_key_persistence_fails_due_to_serialization_error()
 {
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
fn should_return_internal_error_from_load_threshold_signing_key_internal_if_nidkg_secret_key_persistence_fails_due_to_serialization_error()
 {
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
fn should_return_transient_internal_error_from_load_threshold_signing_key_if_nidkg_secret_key_persistence_fails_due_to_transient_internal_error()
 {
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

#[test]
fn should_return_error_if_update_forward_secure_key_with_wrong_algorithm_id() {
    let mut sks = MockSecretKeyStore::new();
    let key_id = KeyId::from([0u8; 32]);
    sks.expect_get().never();
    sks.expect_insert_or_replace().never();
    let csp = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .build();
    let epoch_to_update_to = Epoch::from(2);

    let wrong_algorithm = AlgorithmId::from(0);

    let result = csp.update_forward_secure_epoch(wrong_algorithm, key_id, epoch_to_update_to);
    assert_matches!(
        result,
        Err(CspDkgUpdateFsEpochError::UnsupportedAlgorithmId(
            AlgorithmId::Placeholder
        ))
    );
}

#[test]
fn should_not_update_forward_secure_key_if_key_is_missing() {
    const INTERNAL_ERROR: &str = "Cannot update forward secure key if it is missing";
    let mut sks = MockSecretKeyStore::new();
    let sks_key_id = KeyId::from([0u8; 32]);
    sks.expect_get()
        .withf(move |key_id_| key_id_ == &sks_key_id)
        .times(1)
        .return_const(None);
    sks.expect_insert_or_replace().never();
    let csp = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .build();
    let epoch_to_update_to = Epoch::from(2);

    let result = csp.update_forward_secure_epoch(
        AlgorithmId::NiDkg_Groth20_Bls12_381,
        sks_key_id,
        epoch_to_update_to,
    );

    assert_matches!(
        result,
        Err(CspDkgUpdateFsEpochError::FsKeyNotInSecretKeyStoreError(KeyNotFoundError{internal_error, key_id}))
        if internal_error.contains(INTERNAL_ERROR) && key_id.contains(&sks_key_id.to_string())
    );
}

#[test]
fn should_not_update_forward_secure_key_if_epoch_in_sks_is_newer_than_the_one_to_update_to() {
    let mut sks = MockSecretKeyStore::new();
    let key_id = KeyId::from([0u8; 32]);
    let rng = &mut reproducible_rng();
    let epoch_in_sks = Epoch::from(3);
    let fs_enc_key_set = fs_encryption_key_set_with_epoch(key_id, epoch_in_sks, rng);
    sks.expect_get()
        .withf(move |key_id_| key_id_ == &key_id)
        .times(1)
        .return_const(Some(fs_enc_key_set));
    sks.expect_insert_or_replace().never();
    let csp = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .build();
    let epoch_to_update_to = Epoch::from(2);

    assert_eq!(
        csp.update_forward_secure_epoch(
            AlgorithmId::NiDkg_Groth20_Bls12_381,
            key_id,
            epoch_to_update_to
        ),
        Ok(())
    );
}

#[test]
fn should_not_update_forward_secure_key_if_epoch_to_update_to_is_identical_to_that_in_sks() {
    let mut sks = MockSecretKeyStore::new();
    let key_id = KeyId::from([0u8; 32]);
    let rng = &mut reproducible_rng();
    let epoch = Epoch::from(1);
    let fs_enc_key_set = fs_encryption_key_set_with_epoch(key_id, epoch, rng);
    sks.expect_get()
        .withf(move |key_id_| key_id_ == &key_id)
        .times(1)
        .return_const(Some(fs_enc_key_set));
    sks.expect_insert_or_replace().never();
    let csp = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .build();

    assert_eq!(
        csp.update_forward_secure_epoch(AlgorithmId::NiDkg_Groth20_Bls12_381, key_id, epoch),
        Ok(())
    );
}

#[test]
fn should_update_forward_secure_key_if_epoch_to_update_to_is_newer_than_that_in_sks() {
    let mut sks = MockSecretKeyStore::new();
    let key_id = KeyId::from([0u8; 32]);
    let rng = &mut reproducible_rng();
    let epoch_in_sks = Epoch::from(1);
    let fs_enc_key_set = fs_encryption_key_set_with_epoch(key_id, epoch_in_sks, rng);
    let epoch_to_update_to = Epoch::from(2);
    sks.expect_get()
        .withf(move |key_id_| key_id_ == &key_id)
        .times(2)
        .return_const(Some(fs_enc_key_set));
    sks.expect_insert_or_replace()
        .withf(move |key_id_, key_, _scope| {
            key_id_ == &key_id
                && key_epoch_matches(key_id, key_.clone(), epoch_to_update_to)
                && _scope == &Some(NIDKG_FS_SCOPE)
        })
        .times(1)
        .return_const(Ok(()));
    let csp = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .build();

    assert_eq!(
        csp.update_forward_secure_epoch(
            AlgorithmId::NiDkg_Groth20_Bls12_381,
            key_id,
            epoch_to_update_to
        ),
        Ok(())
    );
}

#[test]
fn should_not_update_forward_secure_key_in_sks_if_epoch_in_sks_was_updated_to_the_epoch_to_update_to_in_the_meantime()
 {
    let mut sks = MockSecretKeyStore::new();
    let key_id = KeyId::from([0u8; 32]);
    let rng = &mut reproducible_rng();
    let old_epoch_in_sks = Epoch::from(1);
    let fs_enc_key_set = fs_encryption_key_set_with_epoch(key_id, old_epoch_in_sks, rng);
    let epoch_to_update_to = Epoch::from(2);
    let fs_enc_key_set_with_updated_epoch =
        update_fs_encryption_key_set_epoch(fs_enc_key_set.clone(), key_id, epoch_to_update_to, rng);
    let mut get_call_counter = 0;
    sks.expect_get()
        .withf(move |key_id_| key_id_ == &key_id)
        .returning(move |_| match get_call_counter {
            0 => {
                get_call_counter += 1;
                Some(fs_enc_key_set.clone())
            }
            1 => {
                get_call_counter += 1;
                Some(fs_enc_key_set_with_updated_epoch.clone())
            }
            _ => panic!("get called too many times!"),
        });
    sks.expect_insert_or_replace().never();
    let csp = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .build();

    assert_eq!(
        csp.update_forward_secure_epoch(
            AlgorithmId::NiDkg_Groth20_Bls12_381,
            key_id,
            epoch_to_update_to
        ),
        Ok(())
    );
}

#[test]
fn should_update_forward_secure_key_in_sks_if_epoch_in_sks_was_updated_to_an_older_epoch_than_the_one_to_update_to()
 {
    let mut sks = MockSecretKeyStore::new();
    let key_id = KeyId::from([0u8; 32]);
    let rng = &mut reproducible_rng();
    let old_epoch_in_sks = Epoch::from(1);
    let fs_enc_key_set = fs_encryption_key_set_with_epoch(key_id, old_epoch_in_sks, rng);
    let intermediate_epoch_in_sks = Epoch::from(2);
    let new_epoch_to_update_to = Epoch::from(3);
    let fs_enc_key_set_with_intermediate_epoch = update_fs_encryption_key_set_epoch(
        fs_enc_key_set.clone(),
        key_id,
        intermediate_epoch_in_sks,
        rng,
    );
    let mut get_call_counter = 0;
    sks.expect_get()
        .withf(move |key_id_| key_id_ == &key_id)
        .returning(move |_| match get_call_counter {
            0 => {
                get_call_counter += 1;
                Some(fs_enc_key_set.clone())
            }
            1 => {
                get_call_counter += 1;
                Some(fs_enc_key_set_with_intermediate_epoch.clone())
            }
            _ => panic!("get called too many times!"),
        });
    sks.expect_insert_or_replace()
        .withf(move |key_id_, key_, _scope| {
            key_id_ == &key_id
                && key_epoch_matches(key_id, key_.clone(), new_epoch_to_update_to)
                && _scope == &Some(NIDKG_FS_SCOPE)
        })
        .times(1)
        .return_const(Ok(()));
    let csp = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .build();

    assert_eq!(
        csp.update_forward_secure_epoch(
            AlgorithmId::NiDkg_Groth20_Bls12_381,
            key_id,
            new_epoch_to_update_to
        ),
        Ok(())
    );
}

fn key_epoch_matches(key_id: KeyId, csp_secret_key: CspSecretKey, epoch: Epoch) -> bool {
    let (_key_set, secret_key) =
        super::specialize_key_set_and_deserialize_secret_key(key_id, Some(csp_secret_key))
            .expect("specializing should succeed");
    secret_key.current_epoch() == Some(epoch)
}

fn fs_encryption_key_set_with_epoch(
    key_id: KeyId,
    epoch: Epoch,
    rng: &mut ReproducibleRng,
) -> CspSecretKey {
    let fs_key_pair = ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::create_forward_secure_key_pair(Seed::from_rng(rng), &[0u8; 4]);
    let fs_enc_key_set =
        CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(fs_key_pair));
    update_fs_encryption_key_set_epoch(fs_enc_key_set, key_id, epoch, rng)
}

fn update_fs_encryption_key_set_epoch(
    csp_secret_key: CspSecretKey,
    key_id: KeyId,
    epoch: Epoch,
    rng: &mut ReproducibleRng,
) -> CspSecretKey {
    use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::forward_secure::SysParam;

    let (mut key_set, mut secret_key) =
        super::specialize_key_set_and_deserialize_secret_key(key_id, Some(csp_secret_key))
            .expect("specializing should succeed");
    secret_key.update_to(epoch, SysParam::global(), rng);
    assert_eq!(secret_key.current_epoch(), Some(epoch));
    key_set.secret_key = secret_key.serialize();
    CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set))
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
