#![allow(clippy::unwrap_used)]
use crate::keygen::utils::node_signing_pk_to_proto;
use crate::types::{CspPublicKey, CspSignature};
use crate::vault::api::{CspBasicSignatureError, CspBasicSignatureKeygenError, CspVault};
use crate::KeyId;
use assert_matches::assert_matches;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_basic_sig_ed25519::types::PublicKeyBytes;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::AlgorithmId;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use strum::IntoEnumIterator;

pub fn should_generate_node_signing_key_pair_and_store_keys(csp_vault: Arc<dyn CspVault>) {
    let gen_key_result = csp_vault
        .gen_node_signing_key_pair()
        .expect("failed creating key pair");

    assert_matches!(gen_key_result, CspPublicKey::Ed25519(_));
    assert!(csp_vault
        .sks_contains(&KeyId::try_from(&gen_key_result).unwrap())
        .is_ok());
    assert_eq!(
        csp_vault
            .current_node_public_keys()
            .expect("missing public keys")
            .node_signing_public_key
            .expect("missing node signing key"),
        node_signing_pk_to_proto(gen_key_result)
    );
}

// The given `csp_vault` is expected to return an AlreadySet error on set_once_node_signing_pubkey
pub fn should_fail_with_internal_error_if_node_signing_key_already_set(
    csp_vault: Arc<dyn CspVault>,
) {
    let result = csp_vault.gen_node_signing_key_pair();

    assert_matches!(result,
        Err(CspBasicSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains("node signing public key already set")
    );
}

pub fn should_fail_with_internal_error_if_node_signing_key_generated_more_than_once(
    csp_vault: Arc<dyn CspVault>,
) {
    assert!(csp_vault.gen_node_signing_key_pair().is_ok());

    let result = csp_vault.gen_node_signing_key_pair();

    assert_matches!(result,
        Err(CspBasicSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains("node signing public key already set")
    );
}

// The given `csp_vault` is expected to return an IO error on set_once_node_signing_pubkey
pub fn should_fail_with_transient_internal_error_if_node_signing_key_persistence_fails(
    csp_vault: Arc<dyn CspVault>,
) {
    let result = csp_vault.gen_node_signing_key_pair();

    assert_matches!(result,
        Err(CspBasicSignatureKeygenError::TransientInternalError { internal_error })
        if internal_error.contains("IO error")
    );
}

pub fn should_sign_verifiably_with_generated_node_signing_key(csp_vault: Arc<dyn CspVault>) {
    let mut rng = reproducible_rng();
    let msg_len_in_bytes = rng.gen_range(0..1024);
    let message = random_message(&mut rng, msg_len_in_bytes);
    generate_key_pair_and_sign_and_verify_message(csp_vault, &message);
}

pub fn should_sign_a_large_hundred_megabytes_message(csp_vault: Arc<dyn CspVault>) {
    const HUNDRED_MEGA_BYTES: usize = 100 * 1024 * 1024;
    let message = vec![0_u8; HUNDRED_MEGA_BYTES];
    generate_key_pair_and_sign_and_verify_message(csp_vault, &message);
}

pub fn generate_key_pair_and_sign_and_verify_message(csp_vault: Arc<dyn CspVault>, message: &[u8]) {
    let (pk_bytes, sign_result) = generate_key_pair_and_sign_message(csp_vault, message);
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
    message: &[u8],
) -> (PublicKeyBytes, Result<CspSignature, CspBasicSignatureError>) {
    let csp_pk = csp_vault
        .gen_node_signing_key_pair()
        .expect("failed to generate keys");
    let pk_bytes = match csp_pk {
        CspPublicKey::Ed25519(pk_bytes) => pk_bytes,
        _ => panic!("Wrong CspPublicKey: {:?}", csp_pk),
    };
    let sign_result = csp_vault.sign(
        AlgorithmId::Ed25519,
        message,
        KeyId::try_from(&csp_pk).unwrap(),
    );
    (pk_bytes, sign_result)
}

fn random_message<R: Rng>(rng: &mut R, msg_len_in_bytes: usize) -> Vec<u8> {
    let msg: Vec<u8> = (0..msg_len_in_bytes).map(|_| rng.gen::<u8>()).collect();
    assert_eq!(msg.len(), msg_len_in_bytes);
    msg
}

pub fn should_not_basic_sign_with_unsupported_algorithm_id(csp_vault: Arc<dyn CspVault>) {
    let public_key = csp_vault
        .gen_node_signing_key_pair()
        .expect("failed to generate keys");

    let msg = "sample message";
    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::Ed25519 {
            let sign_result = csp_vault.sign(
                AlgorithmId::EcdsaP256,
                msg.as_ref(),
                KeyId::try_from(&public_key).unwrap(),
            );
            assert!(sign_result.is_err());
            let err = sign_result.expect_err("Expected an error.");
            match err {
                CspBasicSignatureError::UnsupportedAlgorithm { .. } => {}
                _ => panic!("Expected UnsupportedAlgorithm, got {:?}", err),
            }
        }
    }
}

pub fn should_not_basic_sign_with_non_existent_key(csp_vault: Arc<dyn CspVault>) {
    let mut rng = thread_rng();
    let (_, pk_bytes) = ed25519::keypair_from_rng(&mut rng);

    let key_id = KeyId::try_from(&CspPublicKey::Ed25519(pk_bytes)).unwrap();
    let msg = "some message";
    let sign_result = csp_vault.sign(AlgorithmId::Ed25519, msg.as_ref(), key_id);
    assert!(sign_result.is_err());
}
