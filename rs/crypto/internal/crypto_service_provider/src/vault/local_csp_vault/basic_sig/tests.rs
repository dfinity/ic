//! Tests of Basic Signature operations in the CSP vault.
use crate::imported_test_utils::ed25519::csp_testvec;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::vault::api::{BasicSignatureCspVault, CspBasicSignatureError};
use crate::vault::local_csp_vault::{test_utils::new_csp_vault, LocalCspVault};
use crate::vault::test_utils;
use ic_crypto_internal_test_vectors::ed25519::Ed25519TestVector::RFC8032_ED25519_SHA_ABC;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::NumberOfNodes;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

#[test]
fn should_generate_ed25519_public_key() {
    test_utils::should_generate_ed25519_key_pair(new_csp_vault());
}

#[test]
fn should_fail_to_generate_key_for_wrong_algorithm_id() {
    test_utils::should_fail_to_generate_basic_sig_key_for_wrong_algorithm_id(new_csp_vault());
}

#[test]
fn should_correctly_sign_compared_to_testvec() {
    // Here we only test with a single test vector: an extensive test with the
    // entire test vector suite is done at the crypto lib level.

    let mut rng = thread_rng();

    let key_id = rng.gen::<[u8; 32]>();

    let (sk, _pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);

    let csp_vault = {
        let mut key_store = TempSecretKeyStore::new();

        key_store
            .insert(KeyId::from(key_id), sk, None)
            .expect("failed to insert key into SKS");

        let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
        LocalCspVault::new_for_test(csprng, key_store)
    };

    assert_eq!(
        csp_vault
            .sign(AlgorithmId::Ed25519, &msg, KeyId::from(key_id))
            .expect("failed to create signature"),
        sig
    );
}

#[test]
fn should_sign_verifiably_with_generated_key() {
    test_utils::should_sign_and_verify_with_generated_ed25519_key_pair(new_csp_vault());
}

#[test]
fn should_fail_to_sign_with_unsupported_algorithm_id() {
    test_utils::should_not_basic_sign_with_unsupported_algorithm_id(new_csp_vault());
}

#[test]
fn should_fail_to_sign_with_non_existent_key() {
    test_utils::should_not_basic_sign_with_non_existent_key(new_csp_vault());
}

#[test]
fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
    use crate::vault::api::ThresholdSignatureCspVault;

    let mut rng = thread_rng();

    let csp_vault = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
        LocalCspVault::new_for_test(csprng, key_store)
    };

    let threshold = NumberOfNodes::from(1);
    let (_pub_coeffs, key_ids) = csp_vault
        .threshold_keygen_for_test(AlgorithmId::ThresBls12_381, threshold, &[true])
        .expect("failed to generate threshold sig keys");
    let key_id = key_ids[0].expect("threshold sig key not generated");

    let msg_len: usize = rng.gen_range(0, 1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    let result = csp_vault.sign(AlgorithmId::Ed25519, &msg, key_id);

    assert_eq!(
        result.unwrap_err(),
        CspBasicSignatureError::WrongSecretKeyType {
            algorithm: AlgorithmId::ThresBls12_381
        }
    );
}
