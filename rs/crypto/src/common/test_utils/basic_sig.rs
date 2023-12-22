//! The test vectors contained in this module are intended for
//! stability/consistency tests only. They do not represent official or
//! standardized test vectors.
use super::*;
use ic_crypto_internal_csp_test_utils::types::{csp_pk_ed25519_from_hex, csp_sk_ed25519_from_hex};
use ic_crypto_internal_test_vectors::ed25519 as ed25519_test_vectors;
use ic_crypto_internal_test_vectors::unhex::hex_to_byte_vec;

pub fn testvec(
    test_vec: TestVector,
) -> (
    CspSecretKey,
    CspPublicKey,
    SignableMock,
    BasicSigOf<SignableMock>,
) {
    match test_vec {
        TestVector::ED25519_STABILITY_1 => {
            let sk =
                csp_sk_ed25519_from_hex(ed25519_test_vectors::TESTVEC_RFC8032_ED25519_SHA_ABC_SK);
            let pk =
                csp_pk_ed25519_from_hex(ed25519_test_vectors::TESTVEC_RFC8032_ED25519_SHA_ABC_PK);
            let msg = hex_to_byte_vec(ed25519_test_vectors::TESTVEC_RFC8032_ED25519_SHA_ABC_MSG);
            let msg = SignableMock::new(msg);
            let sig_with_domain_separation = BasicSigOf::new(BasicSig(hex_to_byte_vec(
                ed25519_test_vectors::TESTVEC_ED25519_STABILITY_1_SIG,
            )));

            (sk, pk, msg, sig_with_domain_separation)
        }
        TestVector::ED25519_STABILITY_2 => {
            let sk = csp_sk_ed25519_from_hex(ed25519_test_vectors::TESTVEC_RFC8032_ED25519_1_SK);
            let pk = csp_pk_ed25519_from_hex(ed25519_test_vectors::TESTVEC_RFC8032_ED25519_1_PK);
            let msg = hex_to_byte_vec(ed25519_test_vectors::TESTVEC_RFC8032_ED25519_1_MSG);
            let msg = SignableMock::new(msg);
            let sig_with_domain_separation = BasicSigOf::new(BasicSig(hex_to_byte_vec(
                ed25519_test_vectors::TESTVEC_ED25519_STABILITY_2_SIG,
            )));
            (sk, pk, msg, sig_with_domain_separation)
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter)]
pub enum TestVector {
    ED25519_STABILITY_1,
    ED25519_STABILITY_2,
}
