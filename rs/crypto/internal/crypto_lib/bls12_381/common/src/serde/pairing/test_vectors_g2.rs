//! Verify that the pairing serialisation adheres to the standard
use super::{g2_from_bytes, g2_to_bytes};
use bls12_381::G2Projective;
use ic_crypto_internal_types::curves::bls12_381::conversions::g2_bytes_from_vec;
use ic_crypto_internal_types::curves::test_vectors::bls12_381 as test_vectors;
use std::ops::{AddAssign, SubAssign};

/// Verifies that conversions between a value and a test vector work as
/// expected.
fn g2_serde_should_be_correct(hex_test_vector: &str, value: G2Projective, test_name: &str) {
    let serialised = g2_to_bytes(&value);
    assert_eq!(
        hex_test_vector,
        hex::encode(&serialised[..]),
        "Serialisation does not match for {}",
        test_name
    );
    let bytes = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let bytes = &g2_bytes_from_vec(&bytes);
    let parsed = g2_from_bytes(bytes).expect("Failed to parse test vector");
    assert_eq!(
        parsed, value,
        "Parsed value does not match for {}",
        test_name
    );
}

#[test]
fn g2_serde_should_match_identity_test_vector() {
    g2_serde_should_be_correct(
        test_vectors::g2::INFINITY,
        G2Projective::identity(),
        "Number 0 (infinity)",
    );
}

#[test]
fn g2_serde_should_match_generator_test_vector() {
    g2_serde_should_be_correct(
        test_vectors::g2::GENERATOR,
        G2Projective::generator(),
        "Number 1 (generator)",
    );
}

#[test]
fn powers_of_2_should_be_correct() {
    test_vectors::g2::POWERS_OF_2.iter().enumerate().fold(
        G2Projective::generator(),
        |value, (index, test_vector)| {
            g2_serde_should_be_correct(test_vector, value, &format!("Number {}", 1 << index));
            let mut double = value;
            double.add_assign(&value);
            double
        },
    );
}

#[test]
fn positive_numbers_should_be_correct() {
    test_vectors::g2::POSITIVE_NUMBERS.iter().enumerate().fold(
        G2Projective::identity(),
        |mut value, (index, test_vector)| {
            value.add_assign(&G2Projective::generator());
            g2_serde_should_be_correct(test_vector, value, &format!("Number {}", index + 1));
            value
        },
    );
}

#[test]
fn negative_numbers_should_be_correct() {
    test_vectors::g2::NEGATIVE_NUMBERS.iter().enumerate().fold(
        G2Projective::identity(),
        |mut value, (index, test_vector)| {
            value.sub_assign(&G2Projective::generator());
            g2_serde_should_be_correct(
                test_vector,
                value,
                &format!("Number {}", -(index as i64 + 1)),
            );
            value
        },
    );
}
