//! Tests of Basic Signature operations in the CSP vault.
use crate::imported_test_utils::ed25519::csp_testvec;
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
use crate::public_key_store::PublicKeySetOnceError;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreInsertionError};
use crate::types::{CspPublicKey, CspSecretKey, CspSignature};
use crate::vault::api::PublicKeyStoreCspVault;
use crate::vault::api::SecretKeyStoreCspVault;
use crate::vault::api::{BasicSignatureCspVault, CspBasicSignatureKeygenError};
use crate::vault::api::{CspBasicSignatureError, CspVault};
use crate::vault::local_csp_vault::basic_sig::node_signing_pk_to_proto;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::KeyId;
use assert_matches::assert_matches;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_basic_sig_ed25519::types::PublicKeyBytes;
use ic_crypto_internal_test_vectors::ed25519::Ed25519TestVector::RFC8032_ED25519_SHA_ABC;
use ic_crypto_internal_tls::TlsEd25519SecretKeyDerBytes;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::crypto::AlgorithmId;
use mockall::Sequence;
use rand::Rng;
use std::io;
use std::sync::Arc;
use strum::IntoEnumIterator;

#[test]
fn should_generate_node_signing_key_pair_and_store_keys() {
    let csp_vault = LocalCspVault::builder_for_test().build_into_arc();

    let gen_key_result = csp_vault
        .gen_node_signing_key_pair()
        .expect("failed creating key pair");

    assert_matches!(gen_key_result, CspPublicKey::Ed25519(_));
    assert!(csp_vault.sks_contains(KeyId::from(&gen_key_result)).is_ok());
    assert_eq!(
        csp_vault
            .current_node_public_keys()
            .expect("missing public keys")
            .node_signing_public_key
            .expect("missing node signing key"),
        node_signing_pk_to_proto(gen_key_result)
    );
}

#[test]
fn should_store_node_signing_secret_key_before_public_key() {
    let mut seq = Sequence::new();
    let mut sks = MockSecretKeyStore::new();
    sks.expect_insert()
        .times(1)
        .returning(|_key, _key_id, _scope| Ok(()))
        .in_sequence(&mut seq);
    let mut pks = MockPublicKeyStore::new();
    pks.expect_set_once_node_signing_pubkey()
        .times(1)
        .returning(|_key| Ok(()))
        .in_sequence(&mut seq);
    let vault = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks)
        .with_public_key_store(pks)
        .build_into_arc();

    assert!(vault.gen_node_signing_key_pair().is_ok());
}

#[test]
fn should_fail_with_internal_error_if_node_signing_key_already_set() {
    let mut pks_returning_already_set_error = MockPublicKeyStore::new();
    pks_returning_already_set_error
        .expect_set_once_node_signing_pubkey()
        .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
    let vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks_returning_already_set_error)
        .build_into_arc();

    let result = vault.gen_node_signing_key_pair();

    assert_matches!(result,
        Err(CspBasicSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains("node signing public key already set")
    );
}

#[test]
fn should_fail_with_internal_error_if_node_signing_key_generated_more_than_once() {
    let vault = LocalCspVault::builder_for_test().build_into_arc();
    assert!(vault.gen_node_signing_key_pair().is_ok());

    let result = vault.gen_node_signing_key_pair();

    assert_matches!(result,
        Err(CspBasicSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains("node signing public key already set")
    );
}

#[test]
fn should_fail_with_transient_internal_error_if_node_signing_public_key_persistence_fails() {
    let mut pks_returning_io_error = MockPublicKeyStore::new();
    let io_error = io::Error::new(io::ErrorKind::Other, "oh no!");
    pks_returning_io_error
        .expect_set_once_node_signing_pubkey()
        .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
    let vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks_returning_io_error)
        .build_into_arc();

    let result = vault.gen_node_signing_key_pair();

    assert_matches!(result,
        Err(CspBasicSignatureKeygenError::TransientInternalError { internal_error })
        if internal_error.contains("IO error")
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
        .return_const(Err(SecretKeyStoreInsertionError::TransientError(
            expected_io_error.clone(),
        )));
    let vault = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks_returning_io_error)
        .build();

    let result = vault.gen_node_signing_key_pair();

    assert_matches!(
        result,
        Err(CspBasicSignatureKeygenError::TransientInternalError { internal_error })
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
        .return_const(Err(SecretKeyStoreInsertionError::SerializationError(
            expected_serialization_error.clone(),
        )));
    let vault = LocalCspVault::builder_for_test()
        .with_node_secret_key_store(sks_returning_serialization_error)
        .build();

    let result = vault.gen_node_signing_key_pair();

    assert_matches!(
        result,
        Err(CspBasicSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains(&expected_serialization_error)
    );
}

#[test]
fn should_correctly_sign_compared_to_testvec() {
    // Here we only test with a single test vector: an extensive test with the
    // entire test vector suite is done at the crypto lib level.

    let (sk, pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);

    let csp_vault = {
        let node_signing_public_key = node_signing_pk_to_proto(pk);
        let key_id =
            KeyId::try_from((AlgorithmId::Ed25519, &node_signing_public_key.key_value)).unwrap();

        let mut node_pks = TempPublicKeyStore::new();
        node_pks
            .set_once_node_signing_pubkey(node_signing_public_key)
            .expect("failed to set pubkey in PKS");

        let mut node_sks = TempSecretKeyStore::new();
        node_sks
            .insert(key_id, sk, None)
            .expect("failed to insert key into SKS");

        LocalCspVault::builder_for_test()
            .with_public_key_store(node_pks)
            .with_node_secret_key_store(node_sks)
            .build()
    };

    assert_eq!(
        csp_vault
            .sign(AlgorithmId::Ed25519, msg)
            .expect("failed to create signature"),
        sig
    );
}

#[test]
fn should_sign_verifiably_with_generated_node_signing_key() {
    let csp_vault = LocalCspVault::builder_for_test().build_into_arc();
    let rng = &mut reproducible_rng();
    let msg_len_in_bytes = rng.gen_range(0..1024);
    let message = random_message(rng, msg_len_in_bytes);

    generate_key_pair_and_sign_and_verify_message(csp_vault, &message);
}

#[test]
fn should_fail_to_sign_if_node_signing_public_key_not_found() {
    let mut pks_returning_none = MockPublicKeyStore::new();
    pks_returning_none
        .expect_node_signing_pubkey()
        .return_const(None);
    let vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks_returning_none)
        .build();

    let result = vault.sign(AlgorithmId::Ed25519, b"sample message".to_vec());

    assert_eq!(result, Err(CspBasicSignatureError::PublicKeyNotFound));
}

#[test]
fn should_fail_to_sign_if_key_id_instantiation_fails() {
    // This would only fail if the node signing public key is larger than 4 GB.
    // Given that creating such large keys in a test is very expensive, and
    // that this scenario is extremely unlikely (as the node key generation
    // logic has to be broken) we are not explicitly testing this.
}

#[test]
fn should_fail_to_sign_if_secret_key_not_found() {
    let mut pks_returning_some_key = MockPublicKeyStore::new();
    pks_returning_some_key
        .expect_node_signing_pubkey()
        .return_const(some_public_key_proto());
    let vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks_returning_some_key)
        .build();

    let result = vault.sign(AlgorithmId::Ed25519, b"sample message".to_vec());

    assert_matches!(
        result,
        Err(CspBasicSignatureError::SecretKeyNotFound { .. })
    );
}

#[test]
fn should_fail_to_sign_with_unsupported_algorithm_id() {
    let csp_vault = LocalCspVault::builder_for_test().build_into_arc();
    let _ = csp_vault
        .gen_node_signing_key_pair()
        .expect("failed to generate keys");

    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::Ed25519 {
            let sign_result = csp_vault.sign(algorithm_id, b"msg".to_vec());

            assert_eq!(
                sign_result,
                Err(CspBasicSignatureError::UnsupportedAlgorithm {
                    algorithm: algorithm_id
                })
            );
        }
    }
}

#[test]
fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
    let mut pks_returning_some_key = MockPublicKeyStore::new();
    pks_returning_some_key
        .expect_node_signing_pubkey()
        .return_const(some_public_key_proto());

    let mut sks_returning_wrong_key_type = MockSecretKeyStore::new();
    sks_returning_wrong_key_type
        .expect_get()
        .times(1)
        .return_const(Some(CspSecretKey::TlsEd25519(
            TlsEd25519SecretKeyDerBytes::new(b"dummy".to_vec()),
        )));

    let csp_vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks_returning_some_key)
        .with_node_secret_key_store(sks_returning_wrong_key_type)
        .build();

    let result = csp_vault.sign(AlgorithmId::Ed25519, b"message".to_vec());

    assert_eq!(
        result,
        Err(CspBasicSignatureError::WrongSecretKeyType {
            algorithm: AlgorithmId::Ed25519,
            secret_key_variant: "TlsEd25519".to_string()
        })
    );
}

pub fn generate_key_pair_and_sign_and_verify_message(csp_vault: Arc<dyn CspVault>, message: &[u8]) {
    let (pk_bytes, sign_result) = generate_key_pair_and_sign_message(csp_vault, message.to_vec());
    assert!(sign_result.is_ok());
    let signature = sign_result.expect("Failed to extract the signature");
    let signature_bytes = match signature {
        CspSignature::Ed25519(signature_bytes) => signature_bytes,
        _ => panic!("Wrong CspSignature: {:?}", signature),
    };
    assert!(ed25519::verify(&signature_bytes, message, &pk_bytes).is_ok());
}

pub fn generate_key_pair_and_sign_message(
    csp_vault: Arc<dyn CspVault>,
    message: Vec<u8>,
) -> (PublicKeyBytes, Result<CspSignature, CspBasicSignatureError>) {
    let csp_pk = csp_vault
        .gen_node_signing_key_pair()
        .expect("failed to generate keys");
    let pk_bytes = match csp_pk {
        CspPublicKey::Ed25519(pk_bytes) => pk_bytes,
        _ => panic!("Wrong CspPublicKey: {:?}", csp_pk),
    };
    let sign_result = csp_vault.sign(AlgorithmId::Ed25519, message);
    (pk_bytes, sign_result)
}

fn random_message<R: Rng>(rng: &mut R, msg_len_in_bytes: usize) -> Vec<u8> {
    let msg: Vec<u8> = (0..msg_len_in_bytes).map(|_| rng.gen::<u8>()).collect();
    assert_eq!(msg.len(), msg_len_in_bytes);
    msg
}

fn some_public_key_proto() -> PublicKeyProto {
    PublicKeyProto {
        version: 0,
        algorithm: 1,
        key_value: vec![123; 32],
        proof_data: None,
        timestamp: None,
    }
}
