//! Verify that the MIRACL serialisation adheres to the standard
use crate::{miracl_fr_from_bytes, miracl_fr_to_bytes};
use ic_crypto_internal_types::curves::bls12_381::conversions::fr_bytes_from_vec;
use ic_crypto_internal_types::curves::test_vectors::bls12_381 as test_vectors;
use miracl_core_bls12381::bls12381::{big::BIG, rom::CURVE_ORDER};

/// Copy a BIG, reduced modulo the curve order
fn reduced_mod(value: &BIG) -> BIG {
    let mut value = BIG::new_big(value);
    value.rmod(&BIG::new_ints(&CURVE_ORDER));
    value
}

/// Compares values
fn is_equal(left: &BIG, right: &BIG) -> bool {
    // Copy the data
    let mut right = BIG::new_big(right);
    // Subtract left from right and check that the result is zero
    right.sub(left);
    right.iszilch()
}

/// Verifies that conversions between a value and a test vector work as
/// expected.
///
/// Note that when serialising and parsing, the result should be the same as the
/// original reduced mod the size of the field.
fn fr_serde_should_be_correct(hex_test_vector: &str, value: &BIG, test_name: &str) {
    let serialised = miracl_fr_to_bytes(value).0;
    assert_eq!(
        hex_test_vector,
        hex::encode(&serialised[..]),
        "Serialisation does not match for {}",
        test_name
    );
    let bytes = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let bytes = fr_bytes_from_vec(&bytes);
    let parsed = miracl_fr_from_bytes(bytes).expect("Failed to parse test vector");
    let value_reduced = reduced_mod(value);
    assert!(
        is_equal(&value_reduced, &parsed),
        "Parsed value does not match for {}",
        test_name,
    );
}

/// The number 1
fn zero() -> BIG {
    let mut value = BIG::new();
    value.zero();
    value
}

#[test]
fn fr_serde_should_match_zero_test_vector() {
    let value = zero();
    assert!(value.iszilch(), "Test failed to create a zero for MIRACL");
    fr_serde_should_be_correct(test_vectors::fr::ZERO, &value, "Number 0");
}

/// The number 1
fn one() -> BIG {
    let mut value = BIG::new();
    value.one();
    value
}

#[test]
fn fr_serde_should_match_one_test_vector() {
    let value = one();
    assert!(
        value.isunity(),
        "Test failed to create a number one for MIRACL"
    );
    fr_serde_should_be_correct(test_vectors::fr::ONE, &value, "Number 1");
}

#[test]
fn powers_of_2_should_be_correct() {
    test_vectors::fr::POWERS_OF_2
        .iter()
        .enumerate()
        .fold(one(), |value, (index, test_vector)| {
            fr_serde_should_be_correct(test_vector, &value, &format!("Number {}", 1 << index));
            let mut double = value;
            double.add(&value);
            double
        });
}

#[test]
fn positive_numbers_should_be_correct() {
    test_vectors::fr::POSITIVE_NUMBERS.iter().enumerate().fold(
        zero(),
        |mut value, (index, test_vector)| {
            value.add(&one());
            fr_serde_should_be_correct(test_vector, &value, &format!("Number {}", index + 1));
            value
        },
    );
}

#[test]
fn modulus_should_serialise_as_zero() {
    fr_serde_should_be_correct(
        test_vectors::fr::ZERO,
        &BIG::new_ints(&CURVE_ORDER),
        "Modulus",
    );
}

#[test]
fn modulus_plus_one_should_serialise_as_one() {
    let mut value = BIG::new_ints(&CURVE_ORDER);
    value.add(&one());
    fr_serde_should_be_correct(test_vectors::fr::ONE, &value, "Modulus+1");
}

#[test]
fn fr_serde_should_match_mod_minus_one_test_vector() {
    let mut value = BIG::new_ints(&CURVE_ORDER);
    value.sub(&one());
    let mut plus_one = one();
    plus_one.add(&value);
    assert!(
        is_equal(&reduced_mod(&plus_one), &zero()),
        "Value was not mod minus one"
    );
    fr_serde_should_be_correct(test_vectors::fr::MODULUS_MINUS_ONE, &value, "Number 1");
}

#[test]
fn modulus_and_larger_should_fail_to_parse() {
    let test_values = [
        ("MODULUS", test_vectors::fr::MODULUS),
        ("MODULUS_PLUS_ONE", test_vectors::fr::MODULUS_PLUS_ONE),
        ("MINUS_ONE", test_vectors::fr::MINUS_ONE),
    ];
    for (name, hex_test_vector) in &test_values {
        let bytes = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
        let bytes = fr_bytes_from_vec(&bytes);
        if miracl_fr_from_bytes(bytes).is_ok() {
            panic!("Should fail to parse {}", name);
        }
    }
}
