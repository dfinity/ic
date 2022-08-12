use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::utils::RAND_ChaCha20;
use miracl_core::rand::RAND;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn should_generate_chacha20_random_bytes() {
    let seed: [u8; 32] = [42; 32];
    let mut rand_chacha20 = RAND_ChaCha20::new(seed);
    let mut chacha20_rng = ChaCha20Rng::from_seed(seed);

    const STREAM_SIZE: usize = 1024;
    // The number of stream bytes consumed per each `getbyte()`- call.
    const STEP_SIZE: usize = 4;
    let mut chacha20_bytes: [u8; STREAM_SIZE] = [0; STREAM_SIZE];
    chacha20_rng.fill_bytes(&mut chacha20_bytes);

    for i in 0..STREAM_SIZE / STEP_SIZE {
        let got_byte = rand_chacha20.getbyte();
        assert_eq!(
            chacha20_bytes[i * STEP_SIZE],
            got_byte,
            "failed on {}-th call",
            i
        );
    }
}
