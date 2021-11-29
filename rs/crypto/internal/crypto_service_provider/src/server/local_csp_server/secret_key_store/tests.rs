//! Verifies the implementation of SecretKeyStoreCspVault for LocalCspVault.
use super::*;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::server::test_util;
use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaChaRng;

#[test]
fn key_should_be_present_only_after_generation() {
    let csp_vault1 = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
        LocalCspVault::new_for_test(csprng, key_store)
    };
    let csp_vault2 = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
        LocalCspVault::new_for_test(csprng, key_store)
    };
    test_util::sks_should_contain_keys_only_after_generation(&csp_vault1, &csp_vault2);
}
