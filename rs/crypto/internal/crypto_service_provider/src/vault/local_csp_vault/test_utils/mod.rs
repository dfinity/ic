pub mod temp_local_csp_server;

use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::vault::api::CspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::sync::Arc;

pub fn new_csp_vault() -> Arc<dyn CspVault> {
    let key_store = TempSecretKeyStore::new();
    let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
    Arc::new(LocalCspVault::new_for_test(csprng, key_store))
}
