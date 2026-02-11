use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

macro_rules! window_extraction_works_correctly_init {
    ( $( $window_size:expr_2021 ),* ) => {
        #[test]
        /// Tests the window extraction, i.e., extraction of a bit substring, from a scalar.
        /// Exhaustively tests all possible values for 2 bytes.
        fn window_extraction_works_correctly() {
            const SCALAR_BIT_LEN: usize = 16;
            let extract_bit = |byte: u8, offset: usize| (byte >> offset) & 1;
            // extract bits sequentially - which is simpler to implement and less error-prone - and compare to the actual implementation
            let extract_bits = |bytes: &[u8], offset: usize, window_size: usize| {
                let mut result = extract_bit(bytes[offset / 8], 8 - (offset % 8) - 1);
                for i in 1..window_size {
                    result |= extract_bit(bytes[(offset + i) / 8], (offset + i) % 8) << i;
                }
                result
            };
            for scalar in 0..1u32 << SCALAR_BIT_LEN {
                $(
                for bit_offset in 0..SCALAR_BIT_LEN - $window_size {
                    let expected = extract_bits(&scalar.to_be_bytes(), bit_offset, $window_size);
                    let computed = crate::WindowInfo::<$window_size>::extract(&scalar.to_be_bytes(), bit_offset / $window_size);
                    assert_eq!(expected, computed);
                }
            )*
            }
        }
    };
}

// initialize the test for all input bit-lengths
window_extraction_works_correctly_init![1, 2, 3, 4, 5, 6, 7, 8];

#[test]
fn random_bit_indices_works_correctly() {
    const SCALAR_FLOORED_BIT_LENGTH: u8 = 254;
    const BATCH_SIZE: usize = 10;
    let rng = &mut reproducible_rng();

    assert_eq!(
        crate::Scalar::random_bit_indices(rng, 0, SCALAR_FLOORED_BIT_LENGTH),
        vec![0u8; 0]
    );

    for num_true_bits in 1..=SCALAR_FLOORED_BIT_LENGTH {
        for _ in 0..BATCH_SIZE {
            let mut random_indices =
                crate::Scalar::random_bit_indices(rng, num_true_bits, SCALAR_FLOORED_BIT_LENGTH);

            assert_eq!(random_indices.len(), num_true_bits as usize);

            if num_true_bits > 10 {
                // no trivial/default-initialized output:
                // probability of getting 0..num_true_bits
                // = $1 / \prod_{i=1}^{num_true_bits} (SCALAR_FLOORED_BIT_LENGTH - i + 1)$
                // = 2^-79.6 for `num_true_bits=10` and decreases further with
                // larger `num_true_bits`
                let mut seq_indices: Vec<u8> = Vec::with_capacity(num_true_bits as usize);
                seq_indices.extend(0..num_true_bits);
                assert_ne!(random_indices, seq_indices);
                assert_ne!(random_indices, vec![0; num_true_bits as usize]);
            }

            // each index must be in range
            for i in random_indices.iter() {
                assert!(*i < SCALAR_FLOORED_BIT_LENGTH);
            }

            // check that all indices are unique
            random_indices.sort_unstable();
            let all_unique = random_indices.windows(2).all(|x| x[0] != x[1]);
            assert!(all_unique);
        }
    }
}

#[test]
fn random_bit_indices_works_correctly_for_overflowing_amount() {
    const SCALAR_FLOORED_BIT_LENGTH: u8 = 254;
    let rng1 = &mut ChaCha20Rng::from_seed([0; 32]);
    let rng2 = &mut ChaCha20Rng::from_seed([0; 32]);

    // `Scalar::random_bit_indices` for an overflowing `amount` should fall back
    // to the maximum value of `amount`, i.e., `SCALAR_FLOORED_BIT_LENGTH`, and
    // produce the same result for the same RNG (seed).
    assert_eq!(
        crate::Scalar::random_bit_indices(
            rng1,
            SCALAR_FLOORED_BIT_LENGTH,
            SCALAR_FLOORED_BIT_LENGTH,
        ),
        crate::Scalar::random_bit_indices(
            rng2,
            SCALAR_FLOORED_BIT_LENGTH + 1,
            SCALAR_FLOORED_BIT_LENGTH,
        )
    );
}

#[test]
fn random_sparse_scalar_works_correctly_for_overflowing_num_bits() {
    const SCALAR_FLOORED_BIT_LENGTH: u8 = 254;
    let rng1 = &mut ChaCha20Rng::from_seed([0; 32]);
    let rng2 = &mut ChaCha20Rng::from_seed([0; 32]);

    // `Scalar::random_sparse` for an overflowing `num_bits` should fall back to
    // `SCALAR_FLOORED_BIT_LENGTH`, and produce the same result for the same RNG
    // (seed).
    assert_eq!(
        crate::Scalar::random_sparse(rng1, SCALAR_FLOORED_BIT_LENGTH),
        crate::Scalar::random_sparse(rng2, SCALAR_FLOORED_BIT_LENGTH + 1)
    );
}

#[test]
fn random_sparse_scalars_have_correct_hamming_weight() {
    const SCALAR_FLOORED_BIT_LENGTH: u8 = 254;
    const BATCH_SIZE: usize = 10;
    let rng = &mut reproducible_rng();

    for num_true_bits in 1..SCALAR_FLOORED_BIT_LENGTH {
        let scalars = crate::Scalar::batch_sparse_random(rng, BATCH_SIZE, num_true_bits);

        for s in scalars {
            let hamming_weight = s
                .serialize()
                .iter()
                .fold(0, |accum, byte| accum + byte.count_ones() as u8);
            assert_eq!(hamming_weight, num_true_bits);
        }
    }
}
