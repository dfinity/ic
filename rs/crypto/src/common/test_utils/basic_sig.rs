//! The test vectors contained in this module are intended for
//! stability/consistency tests only. They do not represent official or
//! standardized test vectors.
use super::*;
use ic_crypto_internal_csp::imported_test_utils::ed25519::csp_testvec;
use ic_crypto_internal_test_vectors::basic_sig as basic_sig_test_vectors;
use ic_crypto_internal_test_vectors::ed25519 as ed25519_test_vectors;

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
            let (sk, pk, msg, _sig_without_domain_separation) =
                csp_testvec(ed25519_test_vectors::Ed25519TestVector::RFC8032_ED25519_SHA_ABC);
            let msg = SignableMock::new(msg);
            let sig_with_domain_separation = BasicSigOf::new(BasicSig(hex_to_byte_vec(
                basic_sig_test_vectors::TESTVEC_ED25519_STABILITY_1_SIG,
            )));

            (sk, pk, msg, sig_with_domain_separation)
        }
        TestVector::ED25519_STABILITY_2 => {
            let (sk, pk, msg, _sig_without_domain_separation) =
                csp_testvec(ed25519_test_vectors::Ed25519TestVector::RFC8032_ED25519_1);
            let msg = SignableMock::new(msg);
            let sig_with_domain_separation = BasicSigOf::new(BasicSig(hex_to_byte_vec(
                basic_sig_test_vectors::TESTVEC_ED25519_STABILITY_2_SIG,
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
