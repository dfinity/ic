//! Test multisignature type conversions
use super::super::arbitrary;
use super::{
    CombinedSignature, CombinedSignatureBytes, IndividualSignature, IndividualSignatureBytes, Pop,
    PopBytes, PublicKey, PublicKeyBytes, SecretKey, SecretKeyBytes,
};
use ic_crypto_internal_test_vectors::unhex::{hex_to_48_bytes, hex_to_96_bytes};
use ic_types::crypto::CryptoError;
use proptest::prelude::*;
use std::convert::TryFrom;

// Slow tests
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 5,
        .. ProptestConfig::default()
    })]

    #[test]
    fn secret_key_serde_roundtrip(key in arbitrary::secret_key()) {
        let bytes = SecretKeyBytes::from(&key);
        assert_eq!(key, SecretKey::from(&bytes));
    }
    #[test]
    fn public_key_serde_roundtrip(key in arbitrary::public_key()) {
        let bytes = PublicKeyBytes::from(&key);
        assert_eq!(Ok(key), PublicKey::try_from(&bytes));
    }
    #[test]
    fn individual_signature_serde_roundtrip(signature in arbitrary::individual_signature()) {
        let bytes = IndividualSignatureBytes::from(&signature);
        assert_eq!(Ok(signature), IndividualSignature::try_from(&bytes));
    }
    #[test]
    fn pop_serde_roundtrip(pop in arbitrary::pop()) {
        let bytes = PopBytes::from(&pop);
        assert_eq!(Ok(pop), Pop::try_from(&bytes));
    }
    #[test]
    fn combined_signature_serde_roundtrip(signature in arbitrary::combined_signature()) {
        let bytes = CombinedSignatureBytes::from(&signature);
        assert_eq!(Ok(signature), CombinedSignature::try_from(&bytes));
    }
    #[test]
    fn signature_bulk_conversion_roundtrip(signatures in proptest::collection::vec(arbitrary::individual_signature(), 0..10)) {
        let bytes = signatures.iter().map(IndividualSignatureBytes::from);
        let reconstructed_signatures: Result<Vec<IndividualSignature>, CryptoError> = bytes.map(|bytes| IndividualSignature::try_from(&bytes)).collect();
        assert_eq!(Ok(signatures), reconstructed_signatures);
    }
    #[test]
    fn pop_bulk_conversion_roundtrip(pops in proptest::collection::vec(arbitrary::pop(), 0..10)) {
        let bytes = pops.iter().map(PopBytes::from);
        let reconstructed_pops: Result<Vec<Pop>, CryptoError> = bytes.map(|bytes| Pop::try_from(&bytes)).collect();
        assert_eq!(Ok(pops), reconstructed_pops);
    }
}

#[test]
fn conversion_to_public_key_fails_gracefully() {
    let bad_point = PublicKeyBytes(hex_to_96_bytes(
        "bbf62cf8f448af4fa2071cc31fcdbe56172d90b2a466ef0a66f3f72c063f4d29192f5f19b5ee7118ad2de65da489efac0366758ddfd009fe07afb6d02c0d201b337d0276d68e04c6c56f531a428c27abb94baaf388d36ecce932843b8ecd9042",
    ));
    let converted: Result<PublicKey, _> = PublicKey::try_from(&bad_point);
    assert!(converted.is_err());
}
#[test]
fn conversion_to_individual_signature_fails_gracefully() {
    let bad_point = IndividualSignatureBytes(hex_to_48_bytes(
        "100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000",
    ));
    let converted: Result<IndividualSignature, _> = IndividualSignature::try_from(&bad_point);
    assert!(converted.is_err());
}
#[test]
fn conversion_to_pop_fails_gracefully() {
    let bad_point = PopBytes(hex_to_48_bytes(
        "100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000",
    ));
    let converted: Result<Pop, _> = Pop::try_from(&bad_point);
    assert!(converted.is_err());
}
#[test]
fn conversion_to_combined_signature_fails_gracefully() {
    let bad_point = CombinedSignatureBytes(hex_to_48_bytes(
        "100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000",
    ));
    let converted: Result<CombinedSignature, _> = CombinedSignature::try_from(&bad_point);
    assert!(converted.is_err());
}
