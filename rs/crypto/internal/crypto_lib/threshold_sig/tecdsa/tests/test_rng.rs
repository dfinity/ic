use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub fn test_rng() -> ChaCha20Rng {
    let mut thread_rng = rand::thread_rng();
    let seed = thread_rng.gen::<u64>();
    println!("RNG seed {}", seed);
    ChaCha20Rng::seed_from_u64(seed)
}
