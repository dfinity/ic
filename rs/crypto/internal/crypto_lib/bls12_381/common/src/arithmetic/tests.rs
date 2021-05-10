//! Tests for arithmetic operations on BLS12-381 types

use super::*;
use crate::test_utils::{uint_to_fr, uint_to_g2};
use pairing::bls12_381::G2;
use proptest::prelude::*;

/// Verifies that `scalar_multiply(G(n), f) == G(n * f)`
///
/// Note: The element and factor are limited to u16 so that the product cen be
/// represented as u32.
fn test_scalar_multiply(element_as_uint: u16, factor_as_uint: u16) {
    let element_as_uint = element_as_uint as u32;
    let factor_as_uint = factor_as_uint as u32;
    let expected_as_uint = element_as_uint * factor_as_uint;

    let element = uint_to_g2(element_as_uint);
    let factor = uint_to_fr(factor_as_uint);
    let expected = uint_to_g2(expected_as_uint);
    let actual = scalar_multiply(element, factor);
    assert_eq!(
        expected, actual,
        "Scalar multiplication failed: G({}) * {} != G({})",
        element_as_uint, factor_as_uint, expected_as_uint
    );
}

/// Verifies that summing group elements works as expected
fn test_sum(elements_as_uint: &[u16]) {
    let elements: Vec<G2> = elements_as_uint
        .iter()
        .map(|element| uint_to_g2(*element as u32))
        .collect();
    let sum_as_uint = elements_as_uint
        .iter()
        .fold(0u32, |sum, next| sum + *next as u32);
    let expected = uint_to_g2(sum_as_uint);
    let actual = sum(&elements);
    assert_eq!(
        expected, actual,
        "Sum failed: sum({:?}) != {}",
        elements_as_uint, sum_as_uint
    );
}

proptest! {

    /// Verifies that `scalar_multiply(G(n), f) == G(n * f)`
    #[test]
    fn proptest_scalar_multiply( element: u16, factor: u16 ) {
        test_scalar_multiply(element, factor);
    }

    /// Verifies that summing elements of G2 works
    #[test]
    fn proptest_sum(elements in proptest::collection::vec(any::<u16>(), 0..10)) {
        test_sum(&elements);
    }
}
