//! Test multisignature type conversions
use super::super::arbitrary;
use super::{
    CombinedSignature, CombinedSignatureBytes, IndividualSignature, IndividualSignatureBytes, Pop,
    PopBytes, PublicKey, PublicKeyBytes, SecretKeyBytes,
};
use ic_crypto_internal_test_vectors::unhex::{hex_to_48_bytes, hex_to_96_bytes};
use ic_types::crypto::CryptoError;
use proptest::prelude::*;
use std::convert::{TryFrom, TryInto};

// Slow tests
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 5,
        .. ProptestConfig::default()
    })]

    #[test]
    fn secret_key_serde(key in arbitrary::secret_key()) {
        let bytes: SecretKeyBytes = key.into();
        assert_eq!(key, bytes.into());
    }
    #[test]
    fn public_key_serde(key in arbitrary::public_key()) {
        let bytes: PublicKeyBytes = key.into();
        assert_eq!(Ok(key), bytes.try_into());
    }
    #[test]
    fn individual_signature_serde(signature in arbitrary::individual_signature()) {
        let bytes: IndividualSignatureBytes = signature.into();
        assert_eq!(Ok(signature), bytes.try_into());
    }
    #[test]
    fn pop_serde(pop in arbitrary::pop()) {
        let bytes: PopBytes = pop.into();
        assert_eq!(Ok(pop), bytes.try_into());
    }
    #[test]
    fn combined_signature_serde(signature in arbitrary::combined_signature()) {
        let bytes: CombinedSignatureBytes = signature.into();
        assert_eq!(Ok(signature), bytes.try_into());
    }
    #[test]
    fn signature_bulk_conversion(signatures in proptest::collection::vec(arbitrary::individual_signature(), 0..10)) {
        let bytes: Vec<IndividualSignatureBytes> = signatures.iter().cloned().map(|signature| signature.into()).collect();
        let reconstructed_signatures: Result<Vec<IndividualSignature>, CryptoError> = bytes.into_iter().map(|bytes| bytes.try_into()).collect();
        assert_eq!(Ok(signatures), reconstructed_signatures);
    }
    #[test]
    fn pop_bulk_conversion(pops in proptest::collection::vec(arbitrary::pop(), 0..10)) {
        let bytes: Vec<PopBytes> = pops.iter().cloned().map(|pop| pop.into()).collect();
        let reconstructed_pops: Result<Vec<Pop>, CryptoError> = bytes.into_iter().map(|bytes| bytes.try_into()).collect();
        assert_eq!(Ok(pops), reconstructed_pops);
    }

    #[test]
    fn secret_key_base64_serde(key in arbitrary::secret_key()) {
        let bytes = SecretKeyBytes::from(key);
        let base64: String = bytes.into();
        assert_eq!(Ok(bytes), SecretKeyBytes::try_from(&base64));
    }
    #[test]
    fn public_key_base64_serde(key in arbitrary::public_key()) {
        let bytes = PublicKeyBytes::from(key);
        let base64: String = bytes.into();
        assert_eq!(Ok(bytes), PublicKeyBytes::try_from(&base64));
    }
    #[test]
    fn individual_signature_base64_serde(signature in arbitrary::individual_signature()) {
        let bytes: IndividualSignatureBytes = signature.into();
        let base64: String = bytes.into();
        assert_eq!(Ok(bytes), (&base64).try_into());
    }
    #[test]
    fn pop_base64_serde(pop in arbitrary::pop()) {
        let bytes: PopBytes = pop.into();
        let base64: String = bytes.into();
        assert_eq!(Ok(bytes), (&base64).try_into());
    }
    #[test]
    fn combined_signature_base64_serde(signature in arbitrary::combined_signature()) {
        let bytes: CombinedSignatureBytes = signature.into();
        let base64: String = bytes.into();
        assert_eq!(Ok(bytes), (&base64).try_into());
    }
}

#[test]
fn conversion_to_public_key_fails_gracefully() {
    let bad_point = PublicKeyBytes(hex_to_96_bytes("bbf62cf8f448af4fa2071cc31fcdbe56172d90b2a466ef0a66f3f72c063f4d29192f5f19b5ee7118ad2de65da489efac0366758ddfd009fe07afb6d02c0d201b337d0276d68e04c6c56f531a428c27abb94baaf388d36ecce932843b8ecd9042"));
    let converted: Result<PublicKey, _> = bad_point.try_into();
    assert!(converted.is_err());
}
#[test]
fn conversion_to_individual_signature_fails_gracefully() {
    let bad_point = IndividualSignatureBytes(hex_to_48_bytes("100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000"));
    let converted: Result<IndividualSignature, _> = bad_point.try_into();
    assert!(converted.is_err());
}
#[test]
fn conversion_to_pop_fails_gracefully() {
    let bad_point = PopBytes(hex_to_48_bytes("100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000"));
    let converted: Result<Pop, _> = bad_point.try_into();
    assert!(converted.is_err());
}
#[test]
fn conversion_to_combined_signature_fails_gracefully() {
    let bad_point = CombinedSignatureBytes(hex_to_48_bytes("100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000"));
    let converted: Result<CombinedSignature, _> = bad_point.try_into();
    assert!(converted.is_err());
}

#[test]
fn base64_decoding_secret_key_fails_gracefully() {
    let bad_base64 = "leNiiKeMW5l8UQUf=SrVRevJbAFoQafWg4X09pBCcI2cP5kKTmW/j97hGyCX5PtXrB+0HKj/rmJ8r4uiapMNZt3ecy4aQTELqJl/2f2UKV+uyFNrjt4WuP7NOlt89SXua".to_string();
    let converted = SecretKeyBytes::try_from(&bad_base64);
    assert!(converted.is_err());
}
#[test]
fn base64_decoding_public_key_fails_gracefully() {
    let bad_base64 = "leNiiKeMW5l8UQUf=SrVRevJbAFoQafWg4X09pBCcI2cP5kKTmW/j97hGyCX5PtXrB+0HKj/rmJ8r4uiapMNZt3ecy4aQTELqJl/2f2UKV+uyFNrjt4WuP7NOlt89SXua".to_string();
    let converted = PublicKeyBytes::try_from(&bad_base64);
    assert!(converted.is_err());
}
#[test]
fn base64_decoding_individual_signature_fails_gracefully() {
    let bad_base64 =
        "teqGKFhRgvLZe9oKkvdkaegg7kMpL=De6fmp7YEUav8t6hrXLWEEezYo2lfCA6pEa".to_string();
    let converted = IndividualSignatureBytes::try_from(&bad_base64);
    assert!(converted.is_err());
}
#[test]
fn base64_decoding_pop_fails_gracefully() {
    let bad_base64 =
        "teqGKFhRgvLZe9oKkvdkaegg7kMpL=De6fmp7YEUav8t6hrXLWEEezYo2lfCA6pEa".to_string();
    let converted = PopBytes::try_from(&bad_base64);
    assert!(converted.is_err());
}
#[test]
fn base64_decoding_combined_signature_fails_gracefully() {
    let bad_base64 =
        "teqGKFhRgvLZe9oKkvdkaegg7kMpLDe6fmp7YEUav8t6=hrXLWEEezYo2lfCA6pEa".to_string();
    let converted = CombinedSignatureBytes::try_from(&bad_base64);
    assert!(converted.is_err());
}

#[test]
fn decoding_wrong_length_secret_key_fails_gracefully() {
    let bad_value = "lUn1Nh1inf3zBhf3okqo/q7vyNhKcEnHwJ0dLqMatUk1poY5rf80rBJOunirUU3zAJF96i/cLCzoD3wEvGusbr2OqO+zFI143BCwCo1OGhgEULSqvRm6kxGigqPhp+Ma".to_string();
    let converted = SecretKeyBytes::try_from(&bad_value);
    assert!(converted.is_err());
}
#[test]
fn decoding_wrong_length_public_key_fails_gracefully() {
    let bad_value = "Zm9vYmFzcgo=".to_string();
    let converted = PublicKeyBytes::try_from(&bad_value);
    assert!(converted.is_err());
}
#[test]
fn decoding_wrong_length_individual_signature_fails_gracefully() {
    let bad_value = "Zm9vYmFzcgo=".to_string();
    let converted = IndividualSignatureBytes::try_from(&bad_value);
    assert!(converted.is_err());
}
#[test]
fn decoding_wrong_length_pop_fails_gracefully() {
    let bad_value = "Zm9vYmFzcgo=".to_string();
    let converted = PopBytes::try_from(&bad_value);
    assert!(converted.is_err());
}
#[test]
fn decoding_wrong_length_combined_signature_fails_gracefully() {
    let bad_value = "Zm9vYmFzcgo=".to_string();
    let converted = CombinedSignatureBytes::try_from(&bad_value);
    assert!(converted.is_err());
}
