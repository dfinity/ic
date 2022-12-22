use crate::vault::test_utils::public_seed::should_generate_particular_seeds;
use crate::LocalCspVault;
use ic_crypto_internal_seed::Seed;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn local_csp_vault_should_generate_correct_public_seeds() {
    let mut csprng = ChaCha20Rng::from_seed(thread_rng().gen::<[u8; 32]>());
    let vault = LocalCspVault::builder()
        .with_rng(csprng.clone())
        .build_into_arc();
    let expected_seeds: Vec<_> = (0..10)
        .map(|_| {
            let intermediate_seed: [u8; 32] = csprng.gen();
            Seed::from_bytes(&intermediate_seed)
        })
        .collect();
    should_generate_particular_seeds(vault, expected_seeds);
}
