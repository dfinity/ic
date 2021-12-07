use crate::keygen::public_key_hash_as_key_id;
use crate::types::{CspPublicKey, CspSignature};
use crate::vault::api::{CspBasicSignatureError, CspBasicSignatureKeygenError, CspVault};
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_types::crypto::AlgorithmId;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use strum::IntoEnumIterator;

pub fn should_generate_ed25519_key_pair(csp_vault: Arc<dyn CspVault>) {
    let gen_key_result = csp_vault.gen_key_pair(AlgorithmId::Ed25519);
    assert!(gen_key_result.is_ok());
    let (key_id, pk) = gen_key_result.expect("Failed to unwrap key_id");
    match pk {
        CspPublicKey::Ed25519(_) => {}
        _ => panic!("Wrong CspPublicKey: {:?}", pk),
    }
    assert_eq!(key_id, public_key_hash_as_key_id(&pk));
}

pub fn should_fail_to_generate_basic_sig_key_for_wrong_algorithm_id(csp_vault: Arc<dyn CspVault>) {
    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::Ed25519 {
            assert_eq!(
                csp_vault.gen_key_pair(algorithm_id).unwrap_err(),
                CspBasicSignatureKeygenError::UnsupportedAlgorithm {
                    algorithm: algorithm_id,
                }
            );
        }
    }
}

pub fn should_sign_and_verify_with_generated_ed25519_key_pair(csp_vault: Arc<dyn CspVault>) {
    let (key_id, csp_pk) = csp_vault
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("failed to generate keys");
    let pk_bytes = match csp_pk {
        CspPublicKey::Ed25519(pk_bytes) => pk_bytes,
        _ => panic!("Wrong CspPublicKey: {:?}", csp_pk),
    };

    let mut rng = thread_rng();
    let msg_len: usize = rng.gen_range(0, 1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    let sign_result = csp_vault.sign(AlgorithmId::Ed25519, &msg, key_id);
    assert!(sign_result.is_ok());
    let signature = sign_result.expect("Failed to extract the signature");
    let signature_bytes = match signature {
        CspSignature::Ed25519(signature_bytes) => signature_bytes,
        _ => panic!("Wrong CspSignature: {:?}", signature),
    };
    assert!(ed25519::verify(&signature_bytes, &msg, &pk_bytes).is_ok());
}

pub fn should_not_basic_sign_with_unsupported_algorithm_id(csp_vault: Arc<dyn CspVault>) {
    let (key_id, _) = csp_vault
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("failed to generate keys");

    let msg = "sample message";
    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::Ed25519 {
            let sign_result = csp_vault.sign(AlgorithmId::EcdsaP256, msg.as_ref(), key_id);
            assert!(sign_result.is_err());
            let err = sign_result.err().expect("Expected an error.");
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

    let key_id = public_key_hash_as_key_id(&CspPublicKey::Ed25519(pk_bytes));
    let msg = "some message";
    let sign_result = csp_vault.sign(AlgorithmId::Ed25519, msg.as_ref(), key_id);
    assert!(sign_result.is_err());
}
