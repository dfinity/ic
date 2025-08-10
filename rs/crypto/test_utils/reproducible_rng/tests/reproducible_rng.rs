use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::RngCore;

#[test]
fn no_trivial_output() {
    let rng = &mut reproducible_rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    // bytes is not a zero-initialized string after filling it with random bytes
    assert_ne!(&bytes, &[0u8; 16]);
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
        let mut random_bytes = [0u8; 16];
        rng.fill_bytes(&mut random_bytes);
        let no_collision = outputs.insert(random_bytes);
        assert!(
            no_collision,
            "generated random_bytes={random_bytes:?} twice"
        );
    }
}
