#![allow(clippy::unwrap_used)]
//! Tests for external and generic conversions
use super::*;
use ic_interfaces::crypto::CryptoHashableTestDummy;
use ic_types::crypto::CombinedThresholdSigOf;
use ic_types::crypto::{CombinedMultiSig, CombinedThresholdSig, IndividualMultiSig};

#[test]
fn should_obtain_threshold_sig_share_of_from_csp_signature() {
    let sig_bytes = [42; threshold_types::IndividualSignatureBytes::SIZE];
    let csp_sig = individual_csp_threshold_sig(sig_bytes);

    let sig_share: ThresholdSigShareOf<CryptoHashableTestDummy> =
        ThresholdSigShareOf::try_from(csp_sig).unwrap();

    assert_eq!(sig_share.get().0, sig_bytes.to_vec());
}

#[test]
fn should_not_obtain_threshold_sig_share_of_from_csp_signature_if_csp_sig_type_does_not_match() {
    let sig_bytes = [42; threshold_types::CombinedSignatureBytes::SIZE];
    let csp_sig = combined_csp_threshold_sig(sig_bytes);

    let result: CryptoResult<ThresholdSigShareOf<CryptoHashableTestDummy>> =
        ThresholdSigShareOf::try_from(csp_sig);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: sig_bytes.as_ref().to_owned(),
            internal_error: "Not an individual threshold signature".to_string(),
        }
    );
}

#[test]
fn should_obtain_combined_threshold_sig_of_from_csp_signature() {
    let sig_bytes = [42; threshold_types::CombinedSignatureBytes::SIZE];
    let csp_sig = combined_csp_threshold_sig(sig_bytes);

    let sig_share: CombinedThresholdSigOf<CryptoHashableTestDummy> =
        CombinedThresholdSigOf::try_from(csp_sig).unwrap();

    assert_eq!(sig_share.get().0, sig_bytes.to_vec());
}

#[test]
fn should_not_obtain_combined_threshold_sig_of_from_csp_signature_if_csp_sig_type_does_not_match() {
    let sig_bytes = [42; threshold_types::IndividualSignatureBytes::SIZE];
    let csp_sig = individual_csp_threshold_sig(sig_bytes);

    let result: CryptoResult<CombinedThresholdSigOf<CryptoHashableTestDummy>> =
        CombinedThresholdSigOf::try_from(csp_sig);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: sig_bytes.as_ref().to_owned(),
            internal_error: "Not a combined threshold signature".to_string(),
        }
    );
}

#[test]
fn should_convert_threshold_sig_share_of_to_csp_signature() {
    let sig_bytes = [42; threshold_types::IndividualSignatureBytes::SIZE];
    let sig_share: ThresholdSigShareOf<CryptoHashableTestDummy> =
        ThresholdSigShareOf::new(ThresholdSigShare(sig_bytes.to_vec()));

    let csp_sig = CspSignature::try_from(&sig_share).unwrap();

    match csp_sig {
        CspSignature::ThresBls12_381(ThresBls12_381_Signature::Individual(csp_sig_bytes)) => {
            assert_eq!(&sig_bytes[..], &csp_sig_bytes.0[..])
        }
        _ => panic!("CSP signature has wrong type."),
    }
}

#[test]
fn should_fail_to_convert_threshold_sig_share_of_to_csp_signature_if_wrong_size() {
    const WRONG_SIZE: usize = threshold_types::IndividualSignatureBytes::SIZE + 1;
    let sig_bytes = [42; WRONG_SIZE];
    let sig_share: ThresholdSigShareOf<CryptoHashableTestDummy> =
        ThresholdSigShareOf::new(ThresholdSigShare(sig_bytes.to_vec()));

    assert!(CspSignature::try_from(&sig_share)
        .unwrap_err()
        .is_malformed_signature());
}

#[test]
fn should_convert_combined_threshold_sig_of_to_csp_signature() {
    let sig_bytes = [42; threshold_types::CombinedSignatureBytes::SIZE];
    let combined_sig: CombinedThresholdSigOf<CryptoHashableTestDummy> =
        CombinedThresholdSigOf::new(CombinedThresholdSig(sig_bytes.to_vec()));

    let csp_sig = CspSignature::try_from(&combined_sig).unwrap();

    match csp_sig {
        CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(csp_sig_bytes)) => {
            assert_eq!(&sig_bytes[..], &csp_sig_bytes.0[..])
        }
        _ => panic!("CSP signature has wrong type."),
    }
}

#[test]
fn should_fail_to_convert_combined_threshold_sig_of_to_csp_signature_if_wrong_size() {
    const WRONG_SIZE: usize = threshold_types::CombinedSignatureBytes::SIZE + 1;
    let sig_bytes = [42; WRONG_SIZE];
    let combined_sig: CombinedThresholdSigOf<CryptoHashableTestDummy> =
        CombinedThresholdSigOf::new(CombinedThresholdSig(sig_bytes.to_vec()));

    assert!(CspSignature::try_from(&combined_sig)
        .unwrap_err()
        .is_malformed_signature());
}

#[test]
fn should_convert_individual_multi_sig_of_to_csp_signature() {
    let sig_bytes = [42; multi_types::IndividualSignatureBytes::SIZE];
    let sig_share: IndividualMultiSigOf<CryptoHashableTestDummy> =
        IndividualMultiSigOf::new(IndividualMultiSig(sig_bytes.to_vec()));

    let csp_sig = CspSignature::try_from(&sig_share).unwrap();

    match csp_sig {
        CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(csp_sig_bytes)) => {
            assert_eq!(&sig_bytes[..], &csp_sig_bytes.0[..])
        }
        _ => panic!("CSP signature has wrong type."),
    }
}

#[test]
fn should_fail_to_convert_individual_multi_sig_of_to_csp_signature_if_wrong_size() {
    const WRONG_SIZE: usize = multi_types::IndividualSignatureBytes::SIZE + 1;
    let sig_bytes = [42; WRONG_SIZE];
    let sig_share: IndividualMultiSigOf<CryptoHashableTestDummy> =
        IndividualMultiSigOf::new(IndividualMultiSig(sig_bytes.to_vec()));

    assert!(CspSignature::try_from(&sig_share)
        .unwrap_err()
        .is_malformed_signature());
}

#[test]
fn should_convert_combined_multi_sig_of_to_csp_signature() {
    let sig_bytes = [42; multi_types::CombinedSignatureBytes::SIZE];
    let combined_sig: CombinedMultiSigOf<CryptoHashableTestDummy> =
        CombinedMultiSigOf::new(CombinedMultiSig(sig_bytes.to_vec()));

    let csp_sig = CspSignature::try_from(&combined_sig).unwrap();

    match csp_sig {
        CspSignature::MultiBls12_381(MultiBls12_381_Signature::Combined(csp_sig_bytes)) => {
            assert_eq!(&sig_bytes[..], &csp_sig_bytes.0[..])
        }
        _ => panic!("CSP signature has wrong type."),
    }
}

#[test]
fn should_fail_to_convert_combined_multi_sig_of_to_csp_signature_if_wrong_size() {
    const WRONG_SIZE: usize = multi_types::CombinedSignatureBytes::SIZE + 1;
    let sig_bytes = [42; WRONG_SIZE];
    let combined_sig: CombinedMultiSigOf<CryptoHashableTestDummy> =
        CombinedMultiSigOf::new(CombinedMultiSig(sig_bytes.to_vec()));

    assert!(CspSignature::try_from(&combined_sig)
        .unwrap_err()
        .is_malformed_signature());
}

fn individual_csp_threshold_sig(
    signature_bytes: [u8; threshold_types::IndividualSignatureBytes::SIZE],
) -> CspSignature {
    CspSignature::ThresBls12_381(ThresBls12_381_Signature::Individual(
        threshold_types::IndividualSignatureBytes(signature_bytes),
    ))
}

fn combined_csp_threshold_sig(
    signature_bytes: [u8; threshold_types::CombinedSignatureBytes::SIZE],
) -> CspSignature {
    CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(
        threshold_types::CombinedSignatureBytes(signature_bytes),
    ))
}
