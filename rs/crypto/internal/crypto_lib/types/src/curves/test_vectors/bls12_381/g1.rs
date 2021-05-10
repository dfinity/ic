#![allow(clippy::unwrap_used)]
//! Test vectors for the serial representation of BLS12-381 G1
//!
//! Spec:
//! * Latest: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/?include_text=1#ddSearchMenu:~:text=introduce%20the%20parameters%20of%20the%20Barreto%2DLynn%2DScott
//! * Version 8: https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-08#page-17

/// The chosen generator for the G1 group.
///
/// Note: This matches `x=0x17f1d3..` in the spec, with flag bits added to the
/// first byte.
pub const GENERATOR: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
/// The additive identity, also known as zero.
pub const INFINITY: &str = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
/// Powers of 2: `g1_generator * {1, 2, 4, 8, ...}`
pub const POWERS_OF_2: &[&str] = &[
    GENERATOR,
    "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
    "ac9b60d5afcbd5663a8a44b7c5a02f19e9a77ab0a35bd65809bb5c67ec582c897feb04decc694b13e08587f3ff9b5b60",
    "a85ae765588126f5e860d019c0e26235f567a9c0c0b2d8ff30f3e8d436b1082596e5e7462d20f5be3764fd473e57f9cf",
    "a73eb991aa22cdb794da6fcde55a427f0a4df5a4a70de23a988b5e5fc8c4d844f66d990273267a54dd21579b7ba6a086",
    "a72841987e4f219d54f2b6a9eac5fe6e78704644753c3579e776a3691bc123743f8c63770ed0f72a71e9e964dbf58f43",
];
/// Positive numbers: `g1_generator * {1,2,3,4,...}`
pub const POSITIVE_NUMBERS: &[&str] = &[
    GENERATOR,
    "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
    "89ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224",
    "ac9b60d5afcbd5663a8a44b7c5a02f19e9a77ab0a35bd65809bb5c67ec582c897feb04decc694b13e08587f3ff9b5b60",
    "b0e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc",
];
/// Negative numbers: `g1_generator * {-1, -2, -3, -4, ...}`
pub const NEGATIVE_NUMBERS: &[&str] = &[
    "b7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    "8572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
    "a9ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224",
    "8c9b60d5afcbd5663a8a44b7c5a02f19e9a77ab0a35bd65809bb5c67ec582c897feb04decc694b13e08587f3ff9b5b60",
    "90e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curves::bls12_381::G2;
    const FINITE_TEST_VECTORS: &[&[&str]] = &[POSITIVE_NUMBERS, POWERS_OF_2, NEGATIVE_NUMBERS];

    #[test]
    fn flags_have_weight_1_and_do_not_overlap() {
        fn weight(byte: u8) -> u8 {
            let mut ans: u8 = (byte & 0x55) + ((byte >> 1) & 0x55);
            ans = (ans & 0x33) + ((ans >> 2) & 0x33);
            (ans & 0x0f) + ((ans >> 4) & 0x0f)
        }
        assert_eq!(weight(G2::COMPRESSED_FLAG), 1);
        assert_eq!(weight(G2::INFINITY_FLAG), 1);
        assert_eq!(weight(G2::SIGN_FLAG), 1);
        assert_eq!(weight(G2::NON_FLAG_BITS), 5);
        assert_eq!(
            weight(G2::COMPRESSED_FLAG | G2::INFINITY_FLAG | G2::SIGN_FLAG | G2::NON_FLAG_BITS),
            8
        );
    }

    #[test]
    fn compression_flag_is_set_for_test_vectors() {
        for hex in FINITE_TEST_VECTORS
            .iter()
            .flat_map(|x| x.iter())
            .chain([INFINITY].iter())
        {
            assert_eq!(
                hex::decode(hex).unwrap()[G2::FLAG_BYTE_OFFSET] & G2::COMPRESSED_FLAG,
                G2::COMPRESSED_FLAG
            );
        }
    }

    #[test]
    fn infinity_flag_is_set_for_infinity() {
        assert_eq!(
            hex::decode(INFINITY).unwrap()[G2::FLAG_BYTE_OFFSET] & G2::INFINITY_FLAG,
            G2::INFINITY_FLAG
        );
    }
    #[test]
    fn infinity_flag_is_not_set_for_finite_values() {
        for hex in FINITE_TEST_VECTORS.iter().flat_map(|x| x.iter()) {
            assert_eq!(
                hex::decode(hex).unwrap()[G2::FLAG_BYTE_OFFSET] & G2::INFINITY_FLAG,
                0
            );
        }
    }
    #[test]
    fn sign_flag_distinguishes_negative_from_positive() {
        for (negative, positive) in NEGATIVE_NUMBERS.iter().zip(POSITIVE_NUMBERS) {
            let positive = hex::decode(positive).unwrap();
            let mut negated_negative = hex::decode(negative).unwrap();
            negated_negative[G2::FLAG_BYTE_OFFSET] ^= G2::SIGN_FLAG;
            assert_eq!(negated_negative, positive);
        }
    }
}
