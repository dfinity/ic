#![allow(clippy::unwrap_used)]
//! Tests for threshold signature implementations

use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::vault::api::CspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::test_utils;
use ic_crypto_internal_seed::Seed;
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
            let secret_key_store = TempSecretKeyStore::new();
            let public_key_store = TempPublicKeyStore::new();
            let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
            let local_csp_server = LocalCspVault::new_for_test(csprng, secret_key_store, public_key_store);
            Arc::new(local_csp_server)
        };
        test_utils::threshold_sig::test_threshold_scheme_with_basic_keygen(Seed::from_rng(&mut rng), csp_vault, &message);
    }
}
