#![allow(clippy::unwrap_used)]
//! Test vectors for the serial representation of BLS12-381 G2
//!
//! Spec:
//! * Latest: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/?include_text=1#ddSearchMenu:~:text=introduce%20the%20parameters%20of%20the%20Barreto%2DLynn%2DScott
//! * Version 8: https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-08#page-17

/// The chosen generator for the G2 group.
///
/// Note: This matches `x'_1 || x'_0` in the spec, with flag bits added to the
/// first byte.
pub const GENERATOR: &str = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
/// The additive identity, also known as zero.
pub const INFINITY: &str = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
/// Powers of 2: `g2_generator * [1, 2, 4, 8, ..., 256]`
pub const POWERS_OF_2: &[&str] = &[
    GENERATOR,
    "aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053",
    "870227d3f13684fdb7ce31b8065ba3acb35f7bde6fe2ddfefa359f8b35d08a9ab9537b43e24f4ffb720b5a0bda2a82f20e7a30979a8853a077454eb63b8dcee75f106221b262886bb8e01b0abb043368da82f60899cc1412e33e4120195fc557",
    "92be651a5fa620340d418834526d37a8c932652345400b4cd9d43c8f41c080f41a6d9558118ebeab9d4268bb73e850e102142a58bae275564a6d63cb6bd6266ca66bef07a6ab8ca37b9d0ba2d4effbccfd89c169649f7d0e8a3eb006846579ad",
    "a70401d9bba01c0445e0a682406b099f21d16d9c348cc97156769084055ca328a145c134b8c8b58f019d62882b2965de1800ecc167bb714100f31e7610cd3fd010ca299b394c01b1a89afd11b051e92989f6336db5e6d3212f6b04673526d839",
    "ac1bcdf2034a7d577355b280f431cf2bf2cb5e955915904766a52d57b3aca6e8c4c96af35382e0c63687f4a77724012b0f22d7c4d43cbb513893e53e6cf995c70e4f5fa7c5b6f167838b217825d3d2dadab5f07764ef69d346f2dc97c231a3f6",
    "b6480241fab3ca8ec408219988d8dce6180dbed76fd5e9b84fdb42d73759ea991f179a40566038c1ec6cbbd2d16745390254b59e8676796a65a52610b9c88e366f9dbf7fdbdd5983a4e0b691a3c310f8eb5d2bc1177833bdfa1c1b42cacb953f",
    "afc5f85e7adc6cea5b3792af7c9fa9d3acc465e3785f40654292be3a09dfd2f266bc765fcfe8da55e948c2312ec571d211f6a8f78fa020f9ea41dc9c2b54e1037c77f59dcb9058a1f7ff95a0102d30b7ad18e0ada1dee28bc05183abf87cdb1e",
    "82f7f6cc00b080cb3a7f8976c44d1987fd36a8334db831be269c6f6144c392b54bb934313d5fc832ec41d2f9a4b7ea910412f6b2e37effc7e16d566d6f831572411d130eee4c15d82aa29e44cb4db9b5eb8c08b0ae158cde970d9d29ba368780",
];
/// Positive numbers: `g2_generator * [1, 2, 3, ..., 9]`
pub const POSITIVE_NUMBERS: &[&str] = &[
    GENERATOR,
    "aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053",
    "89380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae",
    "870227d3f13684fdb7ce31b8065ba3acb35f7bde6fe2ddfefa359f8b35d08a9ab9537b43e24f4ffb720b5a0bda2a82f20e7a30979a8853a077454eb63b8dcee75f106221b262886bb8e01b0abb043368da82f60899cc1412e33e4120195fc557",
    "80fb837804dba8213329db46608b6c121d973363c1234a86dd183baff112709cf97096c5e9a1a770ee9d7dc641a894d60411a5de6730ffece671a9f21d65028cc0f1102378de124562cb1ff49db6f004fcd14d683024b0548eff3d1468df2688",
    "83f4b4e761936d90fd5f55f99087138a07a69755ad4a46e4dd1c2cfe6d11371e1cc033111a0595e3bba98d0f538db45119e384121b7d70927c49e6d044fd8517c36bc6ed2813a8956dd64f049869e8a77f7e46930240e6984abe26fa6a89658f",
    "8d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c",
    "92be651a5fa620340d418834526d37a8c932652345400b4cd9d43c8f41c080f41a6d9558118ebeab9d4268bb73e850e102142a58bae275564a6d63cb6bd6266ca66bef07a6ab8ca37b9d0ba2d4effbccfd89c169649f7d0e8a3eb006846579ad",
    "ac48e0d4f9404ae0a7f10774c55a9e838bb09d3bae85b5eaa6b16b0f4dc2354368117f3799c37f3f7126d8b54d3f8393018405e4b67f957b6465ead9f5afc47832d45643dc3aa03af7314c6cf980fa23dd3bb8db3358693ad06011f6a6b1a5ff",
];
/// Negative numbers: `g2_generator * [-1, -2, -3, ..., -9]`
pub const NEGATIVE_NUMBERS: &[&str] = &[
    "b3e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
    "8a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053",
    "a9380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae",
    "a70227d3f13684fdb7ce31b8065ba3acb35f7bde6fe2ddfefa359f8b35d08a9ab9537b43e24f4ffb720b5a0bda2a82f20e7a30979a8853a077454eb63b8dcee75f106221b262886bb8e01b0abb043368da82f60899cc1412e33e4120195fc557",
    "a0fb837804dba8213329db46608b6c121d973363c1234a86dd183baff112709cf97096c5e9a1a770ee9d7dc641a894d60411a5de6730ffece671a9f21d65028cc0f1102378de124562cb1ff49db6f004fcd14d683024b0548eff3d1468df2688",
    "a3f4b4e761936d90fd5f55f99087138a07a69755ad4a46e4dd1c2cfe6d11371e1cc033111a0595e3bba98d0f538db45119e384121b7d70927c49e6d044fd8517c36bc6ed2813a8956dd64f049869e8a77f7e46930240e6984abe26fa6a89658f",
    "ad0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c",
    "b2be651a5fa620340d418834526d37a8c932652345400b4cd9d43c8f41c080f41a6d9558118ebeab9d4268bb73e850e102142a58bae275564a6d63cb6bd6266ca66bef07a6ab8ca37b9d0ba2d4effbccfd89c169649f7d0e8a3eb006846579ad",
    "8c48e0d4f9404ae0a7f10774c55a9e838bb09d3bae85b5eaa6b16b0f4dc2354368117f3799c37f3f7126d8b54d3f8393018405e4b67f957b6465ead9f5afc47832d45643dc3aa03af7314c6cf980fa23dd3bb8db3358693ad06011f6a6b1a5ff",
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
