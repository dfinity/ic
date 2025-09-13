use crate::LocalCspVault;
use crate::vault::api::PublicRandomSeedGenerator;
use ic_crypto_internal_seed::Seed;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn should_generate_correct_public_seeds() {
    let mut csprng = ChaCha20Rng::from_seed(reproducible_rng().r#gen::<[u8; 32]>());
    let vault = LocalCspVault::builder_for_test()
        .with_rng(csprng.clone())
        .build_into_arc();
    let expected_seeds: Vec<_> = (0..10)
        .map(|_| {
            let intermediate_seed: [u8; 32] = csprng.r#gen();
            Seed::from_bytes(&intermediate_seed)
        })
        .collect();

    let new_seeds_iter = (0..expected_seeds.len()).map(|_| {
        vault
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
