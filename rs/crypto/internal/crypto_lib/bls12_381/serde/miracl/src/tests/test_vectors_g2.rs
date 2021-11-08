//! Verify that the MIRACL serialisation adheres to the standard
use crate::{miracl_g2_from_bytes, miracl_g2_to_bytes};
use ic_crypto_internal_types::curves::bls12_381::conversions::g2_bytes_from_vec;
use ic_crypto_internal_types::curves::bls12_381::G2;
use ic_crypto_internal_types::curves::test_vectors::bls12_381 as test_vectors;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::fp2::FP2;
use miracl_core::bls12381::rom::CURVE_ORDER;

/// When much of this was written, ECP lacked Debug, pretty-printing,
/// and Eq, and Miracl's `.equals` took mutable arguments.

/// Verifies that conversions between a value and a test vector work as
/// expected.
fn g2_serde_should_be_correct(hex_test_vector: &str, value: &ECP2, test_name: &str) {
    let serialised = miracl_g2_to_bytes(value).0;
    assert_eq!(
        hex_test_vector,
        hex::encode(&serialised[..]),
        "Serialisation does not match for {}",
        test_name
    );
    let bytes = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let bytes = g2_bytes_from_vec(&bytes);
    let parsed = miracl_g2_from_bytes(&bytes).expect("Failed to parse test vector");
    assert!(
        parsed.equals(value),
        "Parsed value does not match for {} {}",
        test_name,
        {
            let mut neg = parsed;
            neg.neg();
            if neg.equals(value) {
                "due to sign error"
            } else {
                ""
            }
        }
    );
}

/// Verifies that `ECP2::new()` returns inf.
///
/// The current implementation of `ECP2::new()` returns inf, however this is not
/// guaranteed in any way and there is no documented contract that this will
/// always be so.
#[test]
fn g2_new_is_assumed_to_be_inf() {
    assert!(ECP2::new().is_infinity());
}

#[test]
fn g2_serde_should_match_identity_test_vector() {
    g2_serde_should_be_correct(
        test_vectors::g2::INFINITY,
        &ECP2::new(),
        "Number 0 (infinity)",
    );
}

#[test]
fn g2_throws_error_if_compressed_flag_unset() {
    use ic_crypto_internal_types::curves::bls12_381::G2 as G2Bytes;
    let mut bytes =
        g2_bytes_from_vec(&hex::decode(test_vectors::g2::GENERATOR).expect("hex::decode failed"));
    bytes[G2Bytes::FLAG_BYTE_OFFSET] &= !G2Bytes::COMPRESSED_FLAG;
    assert!(miracl_g2_from_bytes(&bytes).is_err());
}

#[test]
fn g2_generator_should_match_test_vector() {
    g2_serde_should_be_correct(
        test_vectors::g2::GENERATOR,
        &ECP2::generator(),
        "Number 1 (generator)",
    );
}

#[test]
fn powers_of_2_should_be_correct() {
    test_vectors::g2::POWERS_OF_2.iter().enumerate().fold(
        ECP2::generator(),
        |value, (index, test_vector)| {
            g2_serde_should_be_correct(test_vector, &value, &format!("Number {}", 1 << index));
            let mut double = value.clone();
            double.add(&value);
            double
        },
    );
}

#[test]
fn positive_numbers_should_be_correct() {
    test_vectors::g2::POSITIVE_NUMBERS.iter().enumerate().fold(
        ECP2::new(),
        |mut value, (index, test_vector)| {
            value.add(&ECP2::generator());
            g2_serde_should_be_correct(test_vector, &value, &format!("Number {}", index + 1));
            value
        },
    );
}

#[test]
fn negative_numbers_should_be_correct() {
    test_vectors::g2::NEGATIVE_NUMBERS.iter().enumerate().fold(
        ECP2::new(),
        |mut value, (index, test_vector)| {
            value.sub(&ECP2::generator());
            g2_serde_should_be_correct(
                test_vector,
                &value,
                &format!("Number {}", -(index as i64 + 1)),
            );
            value
        },
    );
}

#[test]
fn infinity_without_the_infinity_bit_should_fail_to_parse() {
    let hex_test_vector = test_vectors::g2::INFINITY;
    let infinity = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let mut bytes = g2_bytes_from_vec(&infinity);
    bytes[G2::FLAG_BYTE_OFFSET] &= !G2::INFINITY_FLAG;
    if miracl_g2_from_bytes(&bytes).is_ok() {
        panic!("Should not be able to parse infinity without the infinity bit:\n Infinity: {}\n Unset:    {}", hex_test_vector, hex::encode(&bytes[..]));
    }
}

#[test]
fn finite_value_with_the_infinity_bit_should_fail_to_parse() {
    let hex_test_vector = test_vectors::g2::GENERATOR;
    let bytes = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let mut bytes = g2_bytes_from_vec(&bytes);
    bytes[G2::FLAG_BYTE_OFFSET] |= G2::INFINITY_FLAG;
    if miracl_g2_from_bytes(&bytes).is_ok() {
        panic!(
            "A finite value should not be able to parse as infinity:\n {}",
            hex::encode(&bytes[..])
        );
    }
}

#[test]
fn too_large_x1_should_fail_to_parse() {
    let hex_test_vector = test_vectors::g2::GENERATOR;
    let bytes = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let mut bytes = g2_bytes_from_vec(&bytes);
    // Set X to -1
    bytes[G2::FLAG_BYTE_OFFSET] |= G2::NON_FLAG_BITS;
    for byte in bytes[1..10].iter_mut() {
        *byte = 0xff;
    }
    if miracl_g2_from_bytes(&bytes).is_ok() {
        panic!(
            "Should not be able to parse when X is too large: {}",
            hex::encode(&bytes[..])
        );
    }
}

#[test]
fn too_large_x0_should_fail_to_parse() {
    let hex_test_vector = test_vectors::g2::GENERATOR;
    let bytes = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let mut bytes = g2_bytes_from_vec(&bytes);
    // Set X to -1
    for byte in bytes[10..].iter_mut() {
        *byte = 0xff;
    }
    if miracl_g2_from_bytes(&bytes).is_ok() {
        panic!(
            "Should not be able to parse when X is too large: {}",
            hex::encode(&bytes[..])
        );
    }
}

#[test]
fn miracl_g2_from_bytes_checks_subgroup_order() {
    use crate::miracl_g2_from_bytes_unchecked;
    // BLS12-381 uses Y^2 = X^3 + 4.
    // For G2, we twist: Y^2 = X^3 + 4(1 + i).
    // This has a point with X = 2, which happens to be outside the subgroup.
    let p = ECP2::new_fp2(&FP2::new_int(2), 1);
    assert!(!p.is_infinity(), "BUG! Unable to find G2 point with X = 2");
    let subgroup_order = BIG::new_ints(&CURVE_ORDER);
    assert!(
        !p.mul(&subgroup_order).is_infinity(),
        "BUG! P is in subgroup"
    );
    let bad_g2 = miracl_g2_to_bytes(&p);
    let unchecked = miracl_g2_from_bytes_unchecked(bad_g2.as_bytes())
        .expect("BUG! cannot deserialize what was just serialized");
    assert!(
        !unchecked.mul(&subgroup_order).is_infinity(),
        "BUG! deserilized P lies in subgroup"
    );
    let checked = miracl_g2_from_bytes(bad_g2.as_bytes());
    assert!(
        !checked.is_ok(),
        "Deserializing a point outside subgroup should fail"
    );
}
