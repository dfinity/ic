//! Tests of Multi-Signature operations in the CSP vault.
use crate::Csp;
use crate::KeyId;
use crate::LocalCspVault;
use crate::api::CspSigner;
use crate::public_key_store::PublicKeySetOnceError;
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::types::CspPublicKey;
use crate::vault::api::BasicSignatureCspVault;
use crate::vault::api::MultiSignatureCspVault;
use crate::vault::api::PublicKeyStoreCspVault;
use crate::vault::api::SecretKeyStoreCspVault;
use crate::vault::api::{CspMultiSignatureError, CspMultiSignatureKeygenError};
use crate::vault::local_csp_vault::multi_sig::SecretKeyStoreInsertionError;
use crate::vault::local_csp_vault::multi_sig::committee_signing_pk_to_proto;
use assert_matches::assert_matches;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::AlgorithmId;
use mockall::Sequence;
use rand::Rng;
use strum::IntoEnumIterator;

#[test]
fn should_generate_committee_signing_key_pair_and_store_keys() {
    let csp_vault = LocalCspVault::builder_for_test().build();
    let (pk, pop) = csp_vault
        .gen_committee_signing_key_pair()
        .expect("Failure generating key pair with pop");

    assert_matches!(pk, CspPublicKey::MultiBls12_381(_));
    assert!(csp_vault.sks_contains(KeyId::from(&pk)).is_ok());
    assert_eq!(
        csp_vault
            .current_node_public_keys()
            .expect("missing public keys")
            .committee_signing_public_key
            .expect("missing node signing key"),
        committee_signing_pk_to_proto((pk, pop))
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
    let vault = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .with_public_key_store(pks)
        .build();

    let _ = vault.gen_committee_signing_key_pair();
}

#[test]
fn should_fail_with_internal_error_if_committee_signing_key_already_set() {
    let mut pks_returning_already_set_error = MockPublicKeyStore::new();
    pks_returning_already_set_error
        .expect_set_once_committee_signing_pubkey()
        .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
    let vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks_returning_already_set_error)
        .build();

    let result = vault.gen_committee_signing_key_pair();

    assert_matches!(result,
        Err(CspMultiSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains("committee signing public key already set")
    );
}

#[test]
fn should_fail_with_transient_internal_error_if_node_signing_secret_key_persistence_fails_due_to_io_error()
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

    let result = vault.gen_committee_signing_key_pair();

    assert_matches!(
        result,
        Err(CspMultiSignatureKeygenError::TransientInternalError { internal_error })
        if internal_error.contains(&expected_io_error)
    );
}

#[test]
fn should_fail_with_internal_error_if_node_signing_secret_key_persistence_fails_due_to_serialization_error()
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

    let result = vault.gen_committee_signing_key_pair();

    assert_matches!(
        result,
        Err(CspMultiSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains(&expected_serialization_error)
    );
}

#[test]
fn should_fail_with_internal_error_if_committee_signing_key_generated_more_than_once() {
    let vault = LocalCspVault::builder_for_test().build();
    assert!(vault.gen_committee_signing_key_pair().is_ok());

    let result = vault.gen_committee_signing_key_pair();

    assert_matches!(result,
        Err(CspMultiSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains("committee signing public key already set")
    );
}

#[test]
fn should_fail_with_transient_internal_error_if_committee_signing_key_persistence_fails() {
    let mut pks_returning_io_error = MockPublicKeyStore::new();
    let io_error = std::io::Error::other("oh no!");
    pks_returning_io_error
        .expect_set_once_committee_signing_pubkey()
        .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
    let vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks_returning_io_error)
        .build();
    let result = vault.gen_committee_signing_key_pair();

    assert_matches!(result,
        Err(CspMultiSignatureKeygenError::TransientInternalError { internal_error })
        if internal_error.contains("IO error")
    );
}

#[test]
fn should_generate_verifiable_pop() {
    let csp_vault = LocalCspVault::builder_for_test().build();
    let (public_key, pop) = csp_vault
        .gen_committee_signing_key_pair()
        .expect("Failed to generate key pair with PoP");
    let verifier = Csp::builder_for_test().build();

    assert!(
        verifier
            .verify_pop(&pop, AlgorithmId::MultiBls12_381, public_key)
            .is_ok()
    );
}

#[test]
fn should_multi_sign_and_verify_with_generated_key() {
    let rng = &mut reproducible_rng();
    let csp_vault = LocalCspVault::builder_for_test()
        .with_rng(rng.fork())
        .build();
    let (csp_pub_key, csp_pop) = csp_vault
        .gen_committee_signing_key_pair()
        .expect("failed to generate keys");
    let key_id = KeyId::from(&csp_pub_key);

    let msg_len: usize = rng.gen_range(0..1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.r#gen::<u8>()).collect();

    let verifier = Csp::builder_for_test()
        .with_vault(
            LocalCspVault::builder_for_test()
                .with_rng(rng.fork())
                .build(),
        )
        .build();
    let sig = csp_vault
        .multi_sign(AlgorithmId::MultiBls12_381, msg.clone(), key_id)
        .expect("failed to generate signature");

    assert!(
        verifier
            .verify(&sig, &msg, AlgorithmId::MultiBls12_381, csp_pub_key.clone())
            .is_ok()
    );

    assert!(
        verifier
            .verify_pop(&csp_pop, AlgorithmId::MultiBls12_381, csp_pub_key)
            .is_ok()
    );
}

#[test]
fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
    let csp_vault = LocalCspVault::builder_for_test().build();
    let (csp_pub_key, _csp_pop) = csp_vault
        .gen_committee_signing_key_pair()
        .expect("failed to generate keys");
    let key_id = KeyId::from(&csp_pub_key);

    let msg = vec![31; 41];

    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::MultiBls12_381 {
            assert_eq!(
                csp_vault
                    .multi_sign(algorithm_id, msg.clone(), key_id)
                    .expect_err("Unexpected success."),
                CspMultiSignatureError::UnsupportedAlgorithm {
                    algorithm: algorithm_id,
                }
            );
        }
    }
}

#[test]
fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
    let csp_vault = LocalCspVault::builder_for_test().build();
    let wrong_csp_pub_key = csp_vault
        .gen_node_signing_key_pair()
        .expect("failed to generate keys");

    let msg = vec![31; 41];
    let result = csp_vault.multi_sign(
        AlgorithmId::MultiBls12_381,
        msg,
        KeyId::from(&wrong_csp_pub_key),
    );

    assert_eq!(
        result.expect_err("Unexpected success."),
        CspMultiSignatureError::WrongSecretKeyType {
            algorithm: AlgorithmId::MultiBls12_381,
            secret_key_variant: "Ed25519".to_string()
        }
    );
}
