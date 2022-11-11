use crate::vault::test_utils::local_csp_vault::new_local_csp_vault_with_csprng;
use crate::vault::test_utils::public_seed::should_generate_particular_seeds;
use ic_crypto_internal_seed::Seed;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn local_csp_vault_should_generate_correct_public_seeds() {
    let mut csprng = ChaCha20Rng::from_seed(thread_rng().gen::<[u8; 32]>());
    let vault = new_local_csp_vault_with_csprng(csprng.clone());
    let expected_seeds: Vec<_> = (0..10)
        .map(|_| {
            let intermediate_seed: [u8; 32] = csprng.gen();
            let rng_for_seed_generation = &mut ChaCha20Rng::from_seed(intermediate_seed);
            Seed::from_rng(rng_for_seed_generation)
        })
        .collect();
    should_generate_particular_seeds(vault, expected_seeds);
}
