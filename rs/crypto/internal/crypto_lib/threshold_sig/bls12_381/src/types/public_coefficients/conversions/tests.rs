//! Tests for PublicCoefficients conversions

use super::super::arbitrary::arbitrary_public_coefficient_bytes;
use super::*;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use proptest::prelude::*;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

/// Demonstrates that size error conversion works without panicking
#[test]
fn invalid_size_conversion_should_work() {
    let too_big: u64 = 0xffff_ffff_ffff_ffff;
    let result = u32::try_from(too_big).map_err(invalid_size);
    match result {
        Err(CryptoError::InvalidArgument { .. }) => (),
        other => panic!("Expected InvalidArgument.  Got: {:?}", other),
    }
}

/// Verifies that the size of PublicCoefficients is measured correctly
#[test]
fn public_coefficients_size_should_be_correct() {
    let mut public_keys = Vec::new();
    for size in 0_u32..10 {
        let public_coefficients = PublicCoefficients {
            coefficients: public_keys.iter().map(|key| PublicKey(*key)).collect(),
        };
        assert_eq!(
            NumberOfNodes::try_from(&public_coefficients).expect("Invalid size"),
            NumberOfNodes::from(size)
        );
        public_keys.push(G2Projective::generator());
    }
}

/// Verifies that the size of PublicCoefficientsBytes is measured correctly
#[test]
fn public_coefficients_bytes_size_should_be_correct() {
    let mut public_keys = Vec::new();
    for size in 0_u32..10 {
        let public_coefficients = PublicCoefficientsBytes {
            coefficients: public_keys.clone(),
        };
        assert_eq!(
            try_number_of_nodes_from_pub_coeff_bytes(&public_coefficients).expect("Invalid size"),
            NumberOfNodes::from(size)
        );
        public_keys.push(PublicKeyBytes([0u8; PublicKeyBytes::SIZE]));
    }
}

/// Verifies that public coefficients derived from a polynomial are correct.
///
/// Assuming that `public_key_from_secret_key` is implemented correctly there is
/// not much to check apart from length.
#[test]
fn public_coefficients_from_polynomial_should_be_correct() {
    let mut rng = ChaChaRng::from_seed([1u8; 32]);
    for size in 0_usize..10 {
        let polynomial = Polynomial::random(size, &mut rng);
        let public_coefficients = PublicCoefficients::from(polynomial);
        assert_eq!(size, public_coefficients.coefficients.len());
    }
}

#[test]
fn public_key_for_public_coefficients_should_be_correct() {
    let mut test_vectors: Vec<(PublicCoefficients, G2Projective)> = vec![(
        PublicCoefficients {
            coefficients: Vec::new(),
        },
        G2Projective::identity(),
    )];
    let mut rng = ChaChaRng::from_seed([1u8; 32]);
    for _ in 0..3 {
        let polynomial = Polynomial::random(5, &mut rng);
        let public_coefficients = PublicCoefficients::from(&polynomial);
        let public_key = public_key_from_secret_key(&polynomial.coefficients[0]);
        test_vectors.push((public_coefficients, public_key.0));
    }
    for (public_coefficients, expected_public_key) in test_vectors {
        let public_key = PublicKey::from(&public_coefficients);
        assert_eq!(expected_public_key, public_key.0);
    }
}
/// Verifies that the public key for empty public coefficients is zero
#[test]
fn public_key_for_empty_public_coefficients_should_be_zero() {
    let public_coefficients = PublicCoefficients {
        coefficients: Vec::new(),
    };
    let public_key = PublicKey::from(&public_coefficients);
    assert_eq!(G2Projective::identity(), public_key.0);
}

/// Verifies that the public key for non-empty public coefficients is the first
/// coefficient
#[test]
fn public_key_for_non_empty_public_coefficients_should_be_correct() {
    let mut rng = ChaChaRng::from_seed([1u8; 32]);
    let polynomial = Polynomial::random(5, &mut rng);
    let public_coefficients = PublicCoefficients::from(&polynomial);
    let public_key = PublicKey::from(&public_coefficients);
    assert_eq!(public_coefficients.coefficients[0], public_key);
}

/// Verifies that a malformed zero'th public coefficient yields an error, not a
/// public key.
#[test]
fn public_key_from_public_coefficients_should_return_malformed_error() {
    let malformed_public_key_bytes = PublicKeyBytes([5u8; PublicKeyBytes::SIZE]);
    assert!(
        PublicKey::try_from(&malformed_public_key_bytes).is_err(),
        "Test error: Bytes are not malformed"
    );
    let malformed_public_coefficients = PublicCoefficientsBytes {
        coefficients: vec![malformed_public_key_bytes],
    };
    assert!(
        PublicKey::try_from(&malformed_public_coefficients).is_err(),
        "Expected an error when parsing malformed public coefficients"
    );
}

/// Verifies that empty public coefficients yield the zero public key.
#[test]
fn public_key_from_empty_public_coefficients_bytes_should_be_zero() {
    let public_coefficients_bytes = PublicCoefficientsBytes {
        coefficients: Vec::new(),
    };
    assert_eq!(
        PublicKey::try_from(&public_coefficients_bytes),
        Ok(PublicKey(G2Projective::identity()))
    );
}

/// Verifies that the PublicKeyBytes for non-empty PublicCoefficientsBytes is
/// the first coefficient
#[test]
fn public_key_bytes_for_non_empty_public_coefficients_bytes_should_be_correct() {
    let pk_0 = PublicKeyBytes([9u8; PublicKeyBytes::SIZE]);
    let pk_1 = PublicKeyBytes([11u8; PublicKeyBytes::SIZE]);
    let pk_2 = PublicKeyBytes([27u8; PublicKeyBytes::SIZE]);
    let public_coefficients_bytes = PublicCoefficientsBytes {
        coefficients: vec![pk_0, pk_1, pk_2],
    };
    let public_key_bytes = pub_key_bytes_from_pub_coeff_bytes(&public_coefficients_bytes);
    assert_eq!(pk_0, public_key_bytes);
}

/// Verifies that converting malformed PublicCoefficientsBytes to
/// PublicCoefficients results in an error
#[test]
fn malformed_public_coefficients_bytes_should_fail_to_parse() {
    let malformed_public_key_bytes = PublicKeyBytes([5u8; PublicKeyBytes::SIZE]);
    assert!(
        PublicKey::try_from(&malformed_public_key_bytes).is_err(),
        "Test error: Bytes are not malformed"
    );
    let malformed_public_coefficients = PublicCoefficientsBytes {
        coefficients: vec![malformed_public_key_bytes],
    };
    assert!(
        PublicCoefficients::try_from(&malformed_public_coefficients).is_err(),
        "Expected an error when parsing malformed public coefficients"
    );
}

/// Verifies that stringifying and parsing PublicCoefficientsBytes yields the
/// original
fn test_stringifying_and_parsing_public_coefficients_should_produce_original(
    public_coefficients: PublicCoefficientsBytes,
) {
    let string = String::from(public_coefficients.clone());
    let parsed = PublicCoefficientsBytes::try_from(string.as_str());
    assert_eq!(
        Ok(public_coefficients),
        parsed,
        "String form does not parse to original: '{}'",
        string
    );
}

/// Verifies that parsing an invalid PublicCoefficientsBytes string returns an
/// error
#[test]
fn test_parsing_invalid_public_coefficients_string_should_produce_error() {
    let string = "base 64 has no spaces";
    let parsed = PublicCoefficientsBytes::try_from(string);
    assert!(parsed.is_err(), "{}", string);
}

proptest! {
    #[test]
    fn proptest_stringifying_and_parsing_public_coefficients_should_produce_original_new (public_coefficients in arbitrary_public_coefficient_bytes(0,5)) {
         test_stringifying_and_parsing_public_coefficients_should_produce_original(public_coefficients);
    }
}
