use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
use rand::RngCore;

#[test]
fn no_trivial_output() {
    let rng = &mut reproducible_rng();
    let mut bytes = [0_u8; 16];
    rng.fill_bytes(&mut bytes);
    // bytes is not a zero-initialized string after filling it with random bytes
    assert_ne!(&bytes, &[0_u8; 16]);
    // next random `u64` is not a zero-initialized `u64`
    // remark: generating a random `0u64` is unlikely (Pr = 1 / 2^64)
    assert_ne!(rng.next_u64(), 0);
}

#[test]
fn outputs_are_distinct() {
    const NUM_OUTPUTS: usize = 1000;
    let rng = &mut reproducible_rng();
    let mut outputs = std::collections::HashSet::<[u8; 16]>::new();

    for _ in 0..NUM_OUTPUTS {
        let mut random_bytes = [0_u8; 16];
        rng.fill_bytes(&mut random_bytes);
        let no_collision = outputs.insert(random_bytes);
        assert!(
            no_collision,
            "generated random_bytes={random_bytes:?} twice"
        );
    }
}

#[test]
fn rand_0_8_and_rand_0_10_traits_produce_the_same_output() {
    let seed = [42_u8; 32];
    let rng_0_8 = &mut ReproducibleRng::from_seed_for_debugging(seed);
    let rng_0_10 = &mut ReproducibleRng::from_seed_for_debugging(seed);

    assert_eq!(
        draw_through_rand_0_8(rng_0_8),
        draw_through_rand_0_10(rng_0_10)
    );
}

#[test]
fn alternating_between_rand_0_8_and_rand_0_10_traits_continues_one_output_stream() {
    let seed = [42_u8; 32];
    let rng_0_8 = &mut ReproducibleRng::from_seed_for_debugging(seed);
    let rng_alternating = &mut ReproducibleRng::from_seed_for_debugging(seed);

    let expected = [
        draw_through_rand_0_8(rng_0_8),
        draw_through_rand_0_8(rng_0_8),
    ]
    .concat();
    let alternating = [
        draw_through_rand_0_8(rng_alternating),
        draw_through_rand_0_10(rng_alternating),
    ]
    .concat();

    assert_eq!(alternating, expected);
}

/// Lengths of the byte strings that `draw_through_rand_0_8` and
/// `draw_through_rand_0_10` request between words. Some are not multiples of
/// the word size, and together they cross ChaCha block boundaries.
const FILL_LENGTHS: [usize; 4] = [1, 7, 64, 203];

/// Draws words and byte strings through rand 0.8's `RngCore`.
fn draw_through_rand_0_8<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Vec<u8> {
    let mut output = Vec::new();
    for len in FILL_LENGTHS {
        output.extend_from_slice(&rand::RngCore::next_u32(rng).to_le_bytes());
        output.extend_from_slice(&rand::RngCore::next_u64(rng).to_le_bytes());
        let mut bytes = vec![0_u8; len];
        rand::RngCore::fill_bytes(rng, &mut bytes);
        output.extend_from_slice(&bytes);
    }
    output
}

/// Draws the same sequence as `draw_through_rand_0_8` through rand 0.10's `Rng`.
fn draw_through_rand_0_10<R: rand_0_10::CryptoRng>(rng: &mut R) -> Vec<u8> {
    let mut output = Vec::new();
    for len in FILL_LENGTHS {
        output.extend_from_slice(&rand_0_10::Rng::next_u32(rng).to_le_bytes());
        output.extend_from_slice(&rand_0_10::Rng::next_u64(rng).to_le_bytes());
        let mut bytes = vec![0_u8; len];
        rand_0_10::Rng::fill_bytes(rng, &mut bytes);
        output.extend_from_slice(&bytes);
    }
    output
}
