use crate::api::CspSigner;
use crate::keygen::utils::committee_signing_pk_to_proto;
use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::types::CspPublicKey;
use crate::vault::api::{CspMultiSignatureError, CspMultiSignatureKeygenError, CspVault};
use crate::Csp;
use crate::KeyId;
use ic_types::crypto::AlgorithmId;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::sync::Arc;
use strum::IntoEnumIterator;

fn multi_sig_verifier() -> impl CspSigner {
    let dummy_secret_key_store = TempSecretKeyStore::new();
    let dummy_public_key_store = TempPublicKeyStore::new();
    let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
    Csp::of(csprng, dummy_secret_key_store, dummy_public_key_store)
}

pub fn should_generate_committee_signing_key_pair_and_store_keys(csp_vault: Arc<dyn CspVault>) {
    let (pk, pop) = csp_vault
        .gen_committee_signing_key_pair()
        .expect("Failure generating key pair with pop");

    assert!(matches!(pk, CspPublicKey::MultiBls12_381(_)));
    assert!(csp_vault.sks_contains(&KeyId::from(&pk)).is_ok());
    assert_eq!(
        csp_vault
            .current_node_public_keys()
            .expect("missing public keys")
            .committee_signing_public_key
            .expect("missing node signing key"),
        committee_signing_pk_to_proto((pk, pop))
    );
}

// The given `csp_vault` is expected to return an AlreadySet error on set_once_committee_signing_pubkey
pub fn should_fail_with_internal_error_if_committee_signing_key_already_set(
    csp_vault: Arc<dyn CspVault>,
) {
    let result = csp_vault.gen_committee_signing_key_pair();

    assert!(matches!(result,
        Err(CspMultiSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains("committee signing public key already set")
    ));
}

pub fn should_fail_with_internal_error_if_committee_signing_key_generated_more_than_once(
    csp_vault: Arc<dyn CspVault>,
) {
    assert!(csp_vault.gen_committee_signing_key_pair().is_ok());

    let result = csp_vault.gen_committee_signing_key_pair();

    assert!(matches!(result,
        Err(CspMultiSignatureKeygenError::InternalError { internal_error })
        if internal_error.contains("committee signing public key already set")
    ));
}

// The given `csp_vault` is expected to return an IO error on set_once_node_signing_pubkey
pub fn should_fail_with_transient_internal_error_if_committee_signing_key_persistence_fails(
    csp_vault: Arc<dyn CspVault>,
) {
    let result = csp_vault.gen_committee_signing_key_pair();

    assert!(matches!(result,
        Err(CspMultiSignatureKeygenError::TransientInternalError { internal_error })
        if internal_error.contains("IO error")
    ));
}

pub fn should_generate_verifiable_pop(csp_vault: Arc<dyn CspVault>) {
    let (public_key, pop) = csp_vault
        .gen_committee_signing_key_pair()
        .expect("Failed to generate key pair with PoP");

    let verifier = multi_sig_verifier();
    assert!(verifier
        .verify_pop(&pop, AlgorithmId::MultiBls12_381, public_key)
        .is_ok());
}

pub fn should_multi_sign_and_verify_with_generated_key(csp_vault: Arc<dyn CspVault>) {
    let (csp_pub_key, csp_pop) = csp_vault
        .gen_committee_signing_key_pair()
        .expect("failed to generate keys");
    let key_id = KeyId::from(&csp_pub_key);

    let mut rng = thread_rng();
    let msg_len: usize = rng.gen_range(0..1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    let verifier = multi_sig_verifier();
    let sig = csp_vault
        .multi_sign(AlgorithmId::MultiBls12_381, &msg, key_id)
        .expect("failed to generate signature");

    assert!(verifier
        .verify(&sig, &msg, AlgorithmId::MultiBls12_381, csp_pub_key.clone())
        .is_ok());

    assert!(verifier
        .verify_pop(&csp_pop, AlgorithmId::MultiBls12_381, csp_pub_key)
        .is_ok());
}

pub fn should_not_multi_sign_with_unsupported_algorithm_id(csp_vault: Arc<dyn CspVault>) {
    let (csp_pub_key, _csp_pop) = csp_vault
        .gen_committee_signing_key_pair()
        .expect("failed to generate keys");
    let key_id = KeyId::from(&csp_pub_key);

    let msg = [31; 41];

    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::MultiBls12_381 {
            assert_eq!(
                csp_vault
                    .multi_sign(algorithm_id, &msg, key_id)
                    .unwrap_err(),
                CspMultiSignatureError::UnsupportedAlgorithm {
                    algorithm: algorithm_id,
                }
            );
        }
    }
}

pub fn should_not_multi_sign_if_secret_key_in_store_has_wrong_type(csp_vault: Arc<dyn CspVault>) {
    let wrong_csp_pub_key = csp_vault
        .gen_node_signing_key_pair()
        .expect("failed to generate keys");

    let msg = [31; 41];
    let result = csp_vault.multi_sign(
        AlgorithmId::MultiBls12_381,
        &msg,
        KeyId::from(&wrong_csp_pub_key),
    );

    assert_eq!(
        result.unwrap_err(),
        CspMultiSignatureError::WrongSecretKeyType {
            algorithm: AlgorithmId::MultiBls12_381,
            secret_key_variant: "Ed25519".to_string()
        }
    );
}
