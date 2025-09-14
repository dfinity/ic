//! Tests for threshold type conversions

use super::*;
use crate::test_utils::malformed_secret_threshold_key_test_vectors;
use proptest::prelude::*;

use crate::types::arbitrary::threshold_sig_public_key_bytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::{
    PublicKeyBytes, ThresholdSigPublicKeyBytesConversionError,
};

proptest! {
    /// Verifies that parsing and serializing PublicKeyBytes returns the initial value.
    #[test]
    fn proptest_public_key_parsing_and_serialising_should_be_inverse(public_key_bytes in threshold_sig_public_key_bytes()) {
        let parsed = PublicKey::try_from(&public_key_bytes).expect("Could not parse bytes");
        let serialised = PublicKeyBytes::from(parsed); // Consuming exercises both serialisation methods.
        assert_eq!(public_key_bytes, serialised, "Parsing followed by serailizing produced a value different from the starting value.");
    }

    /// Verifies that parsing and serializing PublicKeyBytes returns the initial value.
    ///
    /// Note: The default arbitrary strategy produces both valid and invalid bytes so we have to filter out the invalid.
    #[test]
    fn proptest_secret_key_parsing_and_serialising_should_be_inverse(secret_key_bytes: SecretKeyBytes) {
        match SecretKey::try_from(&secret_key_bytes) { Ok(parsed) => {
          let serialised = SecretKeyBytes::from(parsed); // Consuming exercises both serialisation methods.
          assert_eq!(secret_key_bytes, serialised, "Parsing followed by serailizing produced a value different from the starting value.");
        } _ => {
          prop_assume!(false);
        }}
    }

    /// Verifies that parsing and serializing IndividualSignatureBytes returns the initial value.
    #[test]
    fn proptest_individual_signature_parsing_and_serialising_should_be_inverse(signature_bytes: IndividualSignatureBytes) {
        let parsed = IndividualSignature::try_from(&signature_bytes).expect("Could not parse bytes");
        let serialised = IndividualSignatureBytes::from(parsed); // Consuming exercises both serialisation methods.
        assert_eq!(signature_bytes, serialised, "Parsing followed by serailizing produced a value different from the starting value.");
    }

    /// Verifies that parsing and serializing CombinedSignatureBytes returns the initial value.
    #[test]
    fn proptest_combined_signature_parsing_and_serialising_should_be_inverse(signature_bytes: CombinedSignatureBytes) {
        let parsed = CombinedSignature::try_from(&signature_bytes).expect("Could not parse bytes");
        let serialised = CombinedSignatureBytes::from(parsed); // Consuming exercises both serialisation methods.
        assert_eq!(signature_bytes, serialised, "Parsing followed by serailizing produced a value different from the starting value.");
    }
}

/// Verifies that parsing an invalid public key returns an error.
///
/// The first byte of a public key should contain nothing but a single sign bit;
/// an invalid public key is constructed by choosing another value for this
/// byte.
#[test]
fn test_invalid_public_key_fails_to_parse() {
    let invalid_public_key = PublicKeyBytes([0xCC; 96]);
    match PublicKey::try_from(&invalid_public_key) {
        Err(ThresholdSigPublicKeyBytesConversionError::Malformed { .. }) => (),
        other => panic!("Expected a ThresholdSigPublicKeyBytes::Malformed error.  Got: {other:?}"),
    }
}

/// Verifies that parsing an invalid secret key returns an error.
///
/// The secret key is a number modulo a fixed N.  Larger numbers are invalid, so
/// we choose a larger value.
#[test]
fn test_invalid_secret_key_fails_to_parse() {
    for (value, valid, name) in malformed_secret_threshold_key_test_vectors() {
        let bytes = SecretKeyBytes(
            ic_crypto_secrets_containers::SecretArray::new_and_dont_zeroize_argument(&value),
        );
        let secret_key = SecretKey::try_from(&bytes);
        match (valid, secret_key) {
            (false, Err(ClibThresholdSignError::MalformedSecretKey { .. })) => (),
            (true, Ok(_)) => (),
            (false, other) => {
                panic!("Expected a MalformedSecretKey error for {name}.  Got: {other:?}")
            }
            (true, other) => panic!("Failed to parse valid secret key {name}: {other:?}"),
        }
    }
}

/// Verifies that parsing an invalid individual signature returns an error.
///
/// The first byte of a signature should contain nothing but a single sign bit;
/// an invalid signature is constructed by choosing another value for this
/// byte.
#[test]
fn test_invalid_individual_signature_fails_to_parse() {
    let invalid_individual_signature = IndividualSignatureBytes([0xCC; 48]);
    match IndividualSignature::try_from(&invalid_individual_signature) {
        Err(CryptoError::MalformedSignature { .. }) => (),
        other => panic!("Expected a MalformedSignature error.  Got: {other:?}"),
    }
}

/// Verifies that parsing an invalid combined signature returns an error.
///
/// The first byte of a signature should contain nothing but a single sign bit;
/// an invalid signature is constructed by choosing another value for this
/// byte.
#[test]
fn test_invalid_combined_signature_fails_to_parse() {
    let invalid_combined_signature = CombinedSignatureBytes([0xCC; 48]);
    match CombinedSignature::try_from(&invalid_combined_signature) {
        Err(CryptoError::MalformedSignature { .. }) => (),
        other => panic!("Expected a MalformedSignature error.  Got: {other:?}"),
    }
}
