use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub fn reproducible_rng() -> impl Rng + CryptoRng {
    let mut thread_rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    thread_rng.fill(&mut bytes);
    println!("Copy the seed below to reproduce the failed test.");
    println!("let seed: [u8; 32] = {:?};", &bytes);
    ChaCha20Rng::from_seed(bytes)
}
