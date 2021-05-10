//! Tests for threshold type conversions

use super::*;
use crate::test_utils::malformed_secret_threshold_key_test_vectors;
use proptest::prelude::*;

const SNOWMAN: &str = "☃";
const SNOWCODE: &str = "4piD";
use crate::types::arbitrary::threshold_sig_public_key_bytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::{
    PublicKeyBytes, ThresholdSigPublicKeyBytesConversionError,
};

proptest! {
    /// Verifies that parsing and serializing PublicKeyBytes returns the initial value.
    #[test]
    #[allow(clippy::unnecessary_operation)] // Clippy believes that these tests are unnecessary.
    fn proptest_public_key_parsing_and_serialising_should_be_inverse(public_key_bytes in threshold_sig_public_key_bytes()) {
        let parsed = PublicKey::try_from(&public_key_bytes).expect("Could not parse bytes");
        let serialised = PublicKeyBytes::from(parsed); // Consuming exercises both serialisation methods.
        assert_eq!(public_key_bytes, serialised, "Parsing followed by serailizing produced a value different from the starting value.");
    }

    /// Verifies that parsing and serializing PublicKeyBytes returns the initial value.
    ///
    /// Note: The default arbitrary strategy produces both valid and invalid bytes so we have to filter out the invalid.
    #[test]
    #[allow(clippy::unnecessary_operation)] // Clippy believes that these tests are unnecessary.
    fn proptest_secret_key_parsing_and_serialising_should_be_inverse(secret_key_bytes: SecretKeyBytes) {
        if let Ok(parsed) = SecretKey::try_from(&secret_key_bytes) {
          let serialised = SecretKeyBytes::from(parsed); // Consuming exercises both serialisation methods.
          assert_eq!(secret_key_bytes, serialised, "Parsing followed by serailizing produced a value different from the starting value.");
        } else {
          prop_assume!(false);
        }
    }

    /// Verifies that parsing and serializing IndividualSignatureBytes returns the initial value.
    #[test]
    #[allow(clippy::unnecessary_operation)] // Clippy believes that these tests are unnecessary.
    fn proptest_individual_signature_parsing_and_serialising_should_be_inverse(signature_bytes: IndividualSignatureBytes) {
        let parsed = IndividualSignature::try_from(&signature_bytes).expect("Could not parse bytes");
        let serialised = IndividualSignatureBytes::from(parsed); // Consuming exercises both serialisation methods.
        assert_eq!(signature_bytes, serialised, "Parsing followed by serailizing produced a value different from the starting value.");
    }

    /// Verifies that parsing and serializing CombinedSignatureBytes returns the initial value.
    #[test]
    #[allow(clippy::unnecessary_operation)] // Clippy believes that these tests are unnecessary.
    fn proptest_combined_signature_parsing_and_serialising_should_be_inverse(signature_bytes: CombinedSignatureBytes) {
        let parsed = CombinedSignature::try_from(&signature_bytes).expect("Could not parse bytes");
        let serialised = CombinedSignatureBytes::from(parsed); // Consuming exercises both serialisation methods.
        assert_eq!(signature_bytes, serialised, "Parsing followed by serailizing produced a value different from the starting value.");
    }

    /// Verifies that stringifying SecretKeyBytes and paring them again yields the original.
    #[test]
    #[allow(clippy::unnecessary_operation)] // Clippy believes that these tests are unnecessary.
    fn proptest_secret_key_stringifying_and_parsing_should_be_inverse(secret_key: SecretKeyBytes) {
        let string = String::from(secret_key);
        let parsed = SecretKeyBytes::try_from(&string).expect("Failed to parse stringified secret key");
        assert_eq!(secret_key, parsed, "Stringifying followed by parsing produced a value different from the starting value.");
    }

    /// Verifies that stringifying PublicKeyBytes and paring them again yields the original.
    #[test]
    #[allow(clippy::unnecessary_operation)] // Clippy believes that these tests are unnecessary.
    fn proptest_public_key_stringifying_and_parsing_should_be_inverse(public_key in threshold_sig_public_key_bytes()) {
        let string = String::from(public_key);
        let parsed = PublicKeyBytes::try_from(&string).expect("Failed to parse stringified public key");
        assert_eq!(public_key, parsed, "Stringifying followed by parsing produced a value different from the starting value.");
    }

    /// Verifies that stringifying IndividualSignatureBytes and paring them again yields the original.
    #[test]
    #[allow(clippy::unnecessary_operation)] // Clippy believes that these tests are unnecessary.
    fn proptest_individual_signature_stringifying_and_parsing_should_be_inverse(signature: IndividualSignatureBytes) {
        let string = String::from(signature);
        let parsed = IndividualSignatureBytes::try_from(&string).expect("Failed to parse stringified signature");
        assert_eq!(signature, parsed, "Stringifying followed by parsing produced a value different from the starting value.");
    }

    /// Verifies that stringifying CombinedSignatureBytes and paring them again yields the original.
    #[test]
    #[allow(clippy::unnecessary_operation)] // Clippy believes that these tests are unnecessary.
    fn proptest_combined_signature_stringifying_and_parsing_should_be_inverse(signature: CombinedSignatureBytes) {
        let string = String::from(signature);
        let parsed = CombinedSignatureBytes::try_from(&string).expect("Failed to parse stringified signature");
        assert_eq!(signature, parsed, "Stringifying followed by parsing produced a value different from the starting value.");
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
        other => panic!(
            "Expected a ThresholdSigPublicKeyBytes::Malformed error.  Got: {:?}",
            other
        ),
    }
}

/// Verifies that parsing an invalid secret key returns an error.
///
/// The secret key is a number modulo a fixed N.  Larger numbers are invalid, so
/// we choose a larger value.
#[test]
fn test_invalid_secret_key_fails_to_parse() {
    for (value, valid, name) in malformed_secret_threshold_key_test_vectors() {
        let bytes = SecretKeyBytes(value);
        let secret_key = SecretKey::try_from(&bytes);
        match (valid, secret_key) {
            (false, Err(ClibThresholdSignError::MalformedSecretKey { .. })) => (),
            (true, Ok(_)) => (),
            (false, other) => panic!(
                "Expected a MalformedSecretKey error for {}.  Got: {:?}",
                name, other
            ),
            (true, other) => panic!("Failed to parse valid secret key {}: {:?}", name, other),
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
        other => panic!("Expected a MalformedSignature error.  Got: {:?}", other),
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
        other => panic!("Expected a MalformedSignature error.  Got: {:?}", other),
    }
}

/// Verifies that parsing invalid base64 SecretKeyBytes fails
#[test]
fn test_snowman_is_not_valid_secret_key() {
    match SecretKeyBytes::try_from(SNOWMAN) {
        Err(CryptoError::MalformedSecretKey { .. }) => (),
        other => panic!("Expected a MalformedSecretKey error.  Got: {:?}", other),
    }
}

/// Verifies that parsing invalid base64 SecretKeyBytes fails
#[test]
fn test_base64_snowman_is_not_valid_secret_key() {
    match SecretKeyBytes::try_from(SNOWCODE) {
        Err(CryptoError::MalformedSecretKey { .. }) => (),
        other => panic!("Expected a MalformedSecretKey error.  Got: {:?}", other),
    }
}

/// Verifies that parsing invalid base64 PublicKeyBytes fails
#[test]
fn test_snowman_is_not_valid_public_key() {
    match PublicKeyBytes::try_from(SNOWMAN) {
        Err(ThresholdSigPublicKeyBytesConversionError::Malformed { .. }) => (),
        other => panic!(
            "Expected a ThresholdSigPublicKeyBytes::Malformed error.  Got: {:?}",
            other
        ),
    }
}

/// Verifies that parsing invalid base64 PublicKeyBytes fails
#[test]
fn test_base64_snowman_is_not_valid_public_key() {
    match PublicKeyBytes::try_from(SNOWCODE) {
        Err(ThresholdSigPublicKeyBytesConversionError::Malformed { .. }) => (),
        other => panic!(
            "Expected a ThresholdSigPublicKeyBytes::Malformed error.  Got: {:?}",
            other
        ),
    }
}

/// Verifies that parsing invalid base64 IndividualSignatureBytes fails
#[test]
fn test_snowman_is_not_valid_individual_signature() {
    match IndividualSignatureBytes::try_from(SNOWMAN) {
        Err(CryptoError::MalformedSignature { .. }) => (),
        other => panic!(
            "Expected a MalformedIndividualSignature error.  Got: {:?}",
            other
        ),
    }
}

/// Verifies that parsing invalid base64 IndividualSignatureBytes fails
#[test]
fn test_base64_snowman_is_not_valid_individual_signature() {
    match IndividualSignatureBytes::try_from(SNOWCODE) {
        Err(CryptoError::MalformedSignature { .. }) => (),
        other => panic!(
            "Expected a MalformedIndividualSignature error.  Got: {:?}",
            other
        ),
    }
}

/// Verifies that parsing invalid base64 CombinedSignatureBytes fails
#[test]
fn test_snowman_is_not_valid_combined_signature() {
    match CombinedSignatureBytes::try_from(SNOWMAN) {
        Err(CryptoError::MalformedSignature { .. }) => (),
        other => panic!(
            "Expected a MalformedCombinedSignature error.  Got: {:?}",
            other
        ),
    }
}

/// Verifies that parsing invalid base64 CombinedSignatureBytes fails
#[test]
fn test_base64_snowman_is_not_valid_combined_signature() {
    match CombinedSignatureBytes::try_from(SNOWCODE) {
        Err(CryptoError::MalformedSignature { .. }) => (),
        other => panic!(
            "Expected a MalformedCombinedSignature error.  Got: {:?}",
            other
        ),
    }
}
