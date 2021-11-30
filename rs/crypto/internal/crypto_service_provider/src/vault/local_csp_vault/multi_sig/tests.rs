//! Tests of Multi-Signature operations in the CSP vault.
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::test_util;
use crate::vault::test_util::SignaturesTrait;
use rand::{thread_rng, CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

#[test]
fn should_generate_key_ok() {
    let csp_vault = csp_vault_with_empty_key_store();
    test_util::should_generate_multi_bls12_381_key_pair(&csp_vault);
}

#[test]
fn should_fail_to_generate_key_for_wrong_algorithm_id() {
    let csp_vault = csp_vault_with_empty_key_store();
    test_util::should_fail_to_generate_multi_sig_key_for_wrong_algorithm_id(&csp_vault);
}

#[test]
fn should_generate_verifiable_pop() {
    let csp_vault = csp_vault_with_empty_key_store();
    test_util::should_generate_verifiable_pop(&csp_vault);
}

#[test]
fn should_multi_sign_and_verify_with_generated_key() {
    let csp_vault = csp_vault_with_empty_key_store();
    test_util::should_multi_sign_and_verify_with_generated_key(&csp_vault);
}

#[test]
fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
    let csp_vault = csp_vault_with_empty_key_store();
    test_util::should_not_multi_sign_with_unsupported_algorithm_id(&csp_vault);
}

#[test]
fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
    let csp_vault = csp_vault_with_empty_key_store();
    test_util::should_not_multi_sign_if_secret_key_in_store_has_wrong_type(&csp_vault);
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, T: SecretKeyStore> SignaturesTrait
    for LocalCspVault<R, S, T>
{
}

fn csp_vault_with_empty_key_store() -> impl SignaturesTrait {
    let key_store = TempSecretKeyStore::new();
    let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
    LocalCspVault::new_for_test(csprng, key_store)
}
