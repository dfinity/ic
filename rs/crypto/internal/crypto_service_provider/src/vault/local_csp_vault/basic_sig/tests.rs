//! Tests of Basic Signature operations in the CSP vault.
use crate::KeyId;
use crate::imported_test_utils::ed25519::csp_testvec;
use crate::public_key_store::PublicKeySetOnceError;
use crate::public_key_store::PublicKeyStore;
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
use crate::secret_key_store::SecretKeyStoreInsertionError;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::types::{CspPublicKey, CspSecretKey, CspSignature};
use crate::vault::api::PublicKeyStoreCspVault;
use crate::vault::api::SecretKeyStoreCspVault;
use crate::vault::api::{BasicSignatureCspVault, CspBasicSignatureKeygenError};
use crate::vault::api::{CspBasicSignatureError, CspVault};
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::local_csp_vault::basic_sig::node_signing_pk_to_proto;
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
    let io_error = io::Error::other("oh no!");
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

    let result = vault.gen_node_signing_key_pair();

    assert_matches!(
        result,
        Err(CspBasicSignatureKeygenError::TransientInternalError { internal_error })
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

    let (sk, _pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);

    let mut pks = MockPublicKeyStore::new();
    pks.expect_node_signing_pubkey().return_once(|| {
        Some(PublicKeyProto {
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: vec![42; 32],
            ..Default::default()
        })
    });
    let mut sks = MockSecretKeyStore::new();
    sks.expect_get().return_once(|_key_id| Some(sk));

    let csp_vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks)
        .with_node_secret_key_store(sks)
        .build();

    assert_eq!(
        csp_vault.sign(msg).expect("failed to create signature"),
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
fn should_fail_to_sign_with_if_secret_key_is_not_in_store() {
    let mut pks = TempPublicKeyStore::new();
    assert_matches!(
        pks.set_once_node_signing_pubkey(PublicKeyProto {
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: vec![42; 32],
            ..Default::default()
        }),
        Ok(())
    );
    let csp_vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks)
        .build();

    let sign_result = csp_vault.sign(b"msg".to_vec());

    assert_matches!(
        sign_result,
        Err(CspBasicSignatureError::SecretKeyNotFound(_))
    );
}

#[test]
fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
    let mut pks = MockPublicKeyStore::new();
    pks.expect_node_signing_pubkey().returning(|| {
        Some(PublicKeyProto {
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: vec![42; 32],
            ..Default::default()
        })
    });
    let mut sks = MockSecretKeyStore::new();
    sks.expect_get().returning(|_key_id| {
        Some(CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes::new(
            vec![42; 32],
        )))
    });
    let csp_vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks)
        .with_node_secret_key_store(sks)
        .build();

    let result = csp_vault.sign(b"msg".to_vec());

    assert_eq!(
        result,
        Err(CspBasicSignatureError::WrongSecretKeyType {
            secret_key_variant: "TlsEd25519".to_string()
        })
    );
}

#[test]
fn should_fail_to_sign_if_node_signing_public_key_is_not_set() {
    let csp_vault = LocalCspVault::builder_for_test().build();
    let sign_result = csp_vault.sign(b"msg".to_vec());
    assert_matches!(sign_result, Err(CspBasicSignatureError::PublicKeyNotFound));
}

#[test]
fn should_fail_to_sign_if_node_signing_public_key_malformed() {
    let mut pks = TempPublicKeyStore::new();
    assert_matches!(
        pks.set_once_node_signing_pubkey(PublicKeyProto {
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: vec![42; 31], // wrong length
            ..Default::default()
        }),
        Ok(())
    );
    let csp_vault = LocalCspVault::builder_for_test()
        .with_public_key_store(pks)
        .build();

    let sign_result = csp_vault.sign(b"msg".to_vec());

    assert_matches!(
        sign_result,
        Err(CspBasicSignatureError::MalformedPublicKey(_))
    );
}

pub fn generate_key_pair_and_sign_and_verify_message(csp_vault: Arc<dyn CspVault>, message: &[u8]) {
    let (pk_bytes, sign_result) = generate_key_pair_and_sign_message(csp_vault, message.to_vec());
    assert!(sign_result.is_ok());
    let signature = sign_result.expect("Failed to extract the signature");
    let signature_bytes = match signature {
        CspSignature::Ed25519(signature_bytes) => signature_bytes,
        _ => panic!("Wrong CspSignature: {signature:?}"),
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
        _ => panic!("Wrong CspPublicKey: {csp_pk:?}"),
    };
    let sign_result = csp_vault.sign(message);
    (pk_bytes, sign_result)
}

fn random_message<R: Rng>(rng: &mut R, msg_len_in_bytes: usize) -> Vec<u8> {
    let msg: Vec<u8> = (0..msg_len_in_bytes).map(|_| rng.r#gen::<u8>()).collect();
    assert_eq!(msg.len(), msg_len_in_bytes);
    msg
}
