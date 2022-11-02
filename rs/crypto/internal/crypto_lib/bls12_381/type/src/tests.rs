macro_rules! window_extraction_works_correctly_init {
    ( $( $window_size:expr ),* ) => {
        #[test]
        /// Tests the window extraction, i.e., extraciton of a bit substring, from a scalar.
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
