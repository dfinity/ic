//! Test vectors for ECDSA signatures using curve secp256k1.
use crate::unhex::*;
use strum_macros::EnumIter;

pub struct SigVerTestVector {
    pub msg: Vec<u8>,
    pub q_x: Vec<u8>,
    pub q_y: Vec<u8>,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub is_valid: bool,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter)]
pub enum Secp256k1Sha256SigVerTestVector {
    // https://crypto.stackexchange.com/questions/41316/complete-set-of-test-vectors-for-ecdsa-secp256k1
    STACK_OVERFLOW_41316,
    MESSAGE_SIGNATURE_MISMATCH,
    R_S_SWAPPED,
}

pub fn crypto_lib_sig_ver_testvec(test_vec: Secp256k1Sha256SigVerTestVector) -> SigVerTestVector {
    match test_vec {
            Secp256k1Sha256SigVerTestVector::STACK_OVERFLOW_41316 => SigVerTestVector {
                msg: hex_to_byte_vec(
                    "4d61617274656e20426f64657765732067656e6572617465642074686973207465737420766563746f72206f6e20323031362d31312d3038",
                    // Hash should be "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a"
                ),
                q_x: hex_to_byte_vec(
                    "779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd",
                ),
                q_y: hex_to_byte_vec(
                    "e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
                ),
                r: hex_to_byte_vec("241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795"),
                s: hex_to_byte_vec("021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e"),
                is_valid: true,
            },
            Secp256k1Sha256SigVerTestVector::R_S_SWAPPED => SigVerTestVector {
                msg: hex_to_byte_vec(
                    "4d61617274656e20426f64657765732067656e6572617465642074686973207465737420766563746f72206f6e20323031362d31312d3038",
                ),
                q_x: hex_to_byte_vec(
                    "779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd",
                ),
                q_y: hex_to_byte_vec(
                    "e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
                ),
                r: hex_to_byte_vec("021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e"),
                s: hex_to_byte_vec("241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795"),
                is_valid: false,
            },
            Secp256k1Sha256SigVerTestVector::MESSAGE_SIGNATURE_MISMATCH => SigVerTestVector {
                msg: hex_to_byte_vec(
                    "",
                ),
                q_x: hex_to_byte_vec(
                    "779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd",
                ),
                q_y: hex_to_byte_vec(
                    "e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
                ),
                r: hex_to_byte_vec("241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795"),
                s: hex_to_byte_vec("021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e"),
                is_valid: false,
            },
        }
}
