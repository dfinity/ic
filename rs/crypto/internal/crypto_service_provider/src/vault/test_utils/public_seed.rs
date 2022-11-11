use crate::CspVault;
use ic_crypto_internal_seed::Seed;
use rand::RngCore;
use std::sync::Arc;

pub fn should_generate_particular_seeds(csp_vault: Arc<dyn CspVault>, expected_seeds: Vec<Seed>) {
    let new_seeds_iter = (0..expected_seeds.len()).map(|_| {
        csp_vault
            .new_public_seed()
            .expect("Failed to generate a public seed from the CSP vault")
    });

    // Seed doesn't implement PartialEq, so let's avoid adding it just for a test
    // and instead test the equality of the produced randomness.
    for (new_seed, expected_seed) in new_seeds_iter.zip(expected_seeds) {
        assert_eq!(
            new_seed.into_rng().next_u64(),
            expected_seed.into_rng().next_u64()
        );
    }
}
