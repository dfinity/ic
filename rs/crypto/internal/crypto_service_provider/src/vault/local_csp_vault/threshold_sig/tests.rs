#![allow(clippy::unwrap_used)]
//! Tests for threshold signature implementations

use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::vault::api::CspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::test_utils;
use ic_types::Randomness;
use proptest::prelude::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::sync::Arc;

// Slow tests
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4,
        .. ProptestConfig::default()
    })]

    #[test]
    fn test_threshold_scheme_with_basic_keygen(seed: [u8;32], message in proptest::collection::vec(any::<u8>(), 0..100)) {
        let mut rng = ChaChaRng::from_seed(seed);
        let csp_vault : Arc<dyn CspVault> = {
            let key_store = TempSecretKeyStore::new();
            let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
            let local_csp_server = LocalCspVault::new_for_test(csprng, key_store);
            Arc::new(local_csp_server)
        };
        test_utils::test_threshold_scheme_with_basic_keygen(Randomness::from(rng.gen::<[u8; 32]>()), csp_vault, &message);
    }
}
