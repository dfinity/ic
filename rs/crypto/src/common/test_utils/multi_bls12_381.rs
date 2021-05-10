//! The test vectors contained in this module are intended for
//! stability/consistency tests only. They do not represent official or
//! standardized test vectors.
use super::*;
use ic_crypto_internal_test_vectors::multi_bls12_381::*;

pub fn testvec(
    test_vec: MultiBls12381TestVector,
) -> (
    CspSecretKey,
    CspPublicKey,
    CspPop,
    SignableMock,
    IndividualMultiSigOf<SignableMock>,
) {
    match test_vec {
        MultiBls12381TestVector::STABILITY_1 => {
            let sk = CspSecretKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_SK);
            let pk = CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_PK);
            let pop = CspPop::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_POP);
            let msg = SignableMock::new(TESTVEC_MULTI_BLS12_381_1_MSG.as_bytes().to_vec());
            let sig = IndividualMultiSigOf::new(IndividualMultiSig(hex_to_byte_vec(
                TESTVEC_MULTI_BLS12_381_1_SIG,
            )));
            (sk, pk, pop, msg, sig)
        }
        MultiBls12381TestVector::STABILITY_2 => {
            let sk = CspSecretKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_2_SK);
            let pk = CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_2_PK);
            let pop = CspPop::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_2_POP);
            let msg = SignableMock::new(TESTVEC_MULTI_BLS12_381_2_MSG.as_bytes().to_vec());
            let sig = IndividualMultiSigOf::new(IndividualMultiSig(hex_to_byte_vec(
                TESTVEC_MULTI_BLS12_381_2_SIG,
            )));
            (sk, pk, pop, msg, sig)
        }
        MultiBls12381TestVector::STABILITY_3 => {
            let sk = CspSecretKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_3_SK);
            let pk = CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_3_PK);
            let pop = CspPop::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_3_POP);
            let msg = SignableMock::new(TESTVEC_MULTI_BLS12_381_3_MSG.as_bytes().to_vec());
            let sig = IndividualMultiSigOf::new(IndividualMultiSig(hex_to_byte_vec(
                TESTVEC_MULTI_BLS12_381_3_SIG,
            )));
            (sk, pk, pop, msg, sig)
        }
        MultiBls12381TestVector::STABILITY_4 => {
            let sk = CspSecretKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_4_SK);
            let pk = CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_4_PK);
            let pop = CspPop::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_4_POP);
            let msg = SignableMock::new(TESTVEC_MULTI_BLS12_381_4_MSG.as_bytes().to_vec());
            let sig = IndividualMultiSigOf::new(IndividualMultiSig(hex_to_byte_vec(
                TESTVEC_MULTI_BLS12_381_4_SIG,
            )));
            (sk, pk, pop, msg, sig)
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter)]
pub enum MultiBls12381TestVector {
    STABILITY_1,
    STABILITY_2,
    STABILITY_3,
    STABILITY_4,
}
