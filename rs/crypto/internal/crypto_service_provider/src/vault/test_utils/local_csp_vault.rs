use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
use crate::CspVault;
use crate::LocalCspVault;
use crate::SecretKeyStore;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::sync::Arc;

pub fn new_local_csp_vault() -> Arc<dyn CspVault> {
    let key_store = TempSecretKeyStore::new();
    new_local_csp_vault_with_secret_key_store(key_store)
}

pub fn new_local_csp_vault_with_secret_key_store<S: 'static + SecretKeyStore>(
    secret_key_store: S,
) -> Arc<LocalCspVault<ChaChaRng, S, VolatileSecretKeyStore>> {
    let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
    Arc::new(LocalCspVault::new_for_test(csprng, secret_key_store))
}
