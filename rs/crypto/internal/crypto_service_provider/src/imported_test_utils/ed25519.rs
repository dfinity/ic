//! Ed25519 test vectors

use crate::types::{CspPublicKey, CspSecretKey, CspSignature};
use ic_crypto_internal_test_vectors::ed25519::*;
use ic_crypto_internal_test_vectors::unhex::hex_to_byte_vec;

/// TODO(CRP-995): This function is only used for testing and should be removed
pub fn csp_testvec(
    test_vec: Ed25519TestVector,
) -> (CspSecretKey, CspPublicKey, Vec<u8>, CspSignature) {
    match test_vec {
        Ed25519TestVector::RFC8032_ED25519_1 => {
            let sk = CspSecretKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_1_SK);
            let pk = CspPublicKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_1_PK);
            let msg = hex_to_byte_vec(TESTVEC_RFC8032_ED25519_1_MSG);
            let sig = CspSignature::ed25519_from_hex(TESTVEC_RFC8032_ED25519_1_SIG);
            (sk, pk, msg, sig)
        }
        Ed25519TestVector::RFC8032_ED25519_SHA_ABC => {
            let sk = CspSecretKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_SK);
            let pk = CspPublicKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_PK);
            let msg = hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_MSG);
            let sig = CspSignature::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_SIG);
            (sk, pk, msg, sig)
        }
        Ed25519TestVector::MESSAGE_LEN_256_BIT_STABILITY_1 => {
            let sk = CspSecretKey::ed25519_from_hex(TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_1_SK);
            let pk = CspPublicKey::ed25519_from_hex(TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_1_PK);
            let msg = hex_to_byte_vec(TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_1_MSG);
            let sig = CspSignature::ed25519_from_hex(TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_1_SIG);
            (sk, pk, msg, sig)
        }
        Ed25519TestVector::MESSAGE_LEN_256_BIT_STABILITY_2 => {
            let sk = CspSecretKey::ed25519_from_hex(TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_2_SK);
            let pk = CspPublicKey::ed25519_from_hex(TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_2_PK);
            let msg = hex_to_byte_vec(TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_2_MSG);
            let sig = CspSignature::ed25519_from_hex(TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_2_SIG);
            (sk, pk, msg, sig)
        }
        _ => unimplemented!("not implemented because currently not used"),
    }
}
