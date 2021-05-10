//! Tests for polynomial ops

use super::*;
use crate::types::public_coefficients::tests::uints_to_polynomial;
use ic_crypto_internal_bls12381_common::test_utils::uint_to_fr;

#[test]
fn test_polynomial_sum() {
    let test_vectors: Vec<(Vec<Vec<u32>>, Vec<u32>, String)> = vec![
        (
            vec![],
            vec![],
            "Summing no vectors yields the empty polynomial".to_string(),
        ),
        (
            vec![vec![1, 2, 3]],
            vec![1, 2, 3],
            "Summing one vector leaves it unchanged".to_string(),
        ),
        (
            vec![vec![1, 2, 3], vec![5, 7, 11]],
            vec![6, 9, 14],
            "Two vectors".to_string(),
        ),
        (
            vec![vec![1, 2, 0]],
            vec![1, 2],
            "Trailing zeros are truncated".to_string(),
        ),
        (
            vec![vec![], vec![1], vec![1, 1], vec![1, 1, 1]],
            vec![3, 2, 1],
            "Increasing vector lengths".to_string(),
        ),
        (
            vec![vec![1, 1, 1], vec![1, 1], vec![1], vec![]],
            vec![3, 2, 1],
            "Decreasing vector lengths".to_string(),
        ),
    ];
    for (int_vectors, expected_int_sum, test_vector_name) in test_vectors {
        let vectors: Vec<Polynomial> = int_vectors
            .iter()
            .map(|uints| uints_to_polynomial(uints))
            .collect();
        let expected_sum = uints_to_polynomial(&expected_int_sum);
        let actual_sum = Polynomial::sum(vectors.iter());
        assert_eq!(
            expected_sum, actual_sum,
            "Test vector failed: {}",
            test_vector_name
        );
    }
}

struct AdditionTestVector {
    value: Vec<u32>,
    addend: Vec<u32>,
    sum: Vec<u32>,
    name: String,
}

fn addition_test_vectors() -> Vec<AdditionTestVector> {
    vec![
        AdditionTestVector {
            value: vec![],
            addend: vec![],
            sum: vec![],
            name: "Empty vector summation".to_string(),
        },
        AdditionTestVector {
            value: vec![1],
            addend: vec![],
            sum: vec![1],
            name: "Adding the identity".to_string(),
        },
        AdditionTestVector {
            value: vec![],
            addend: vec![2],
            sum: vec![2],
            name: "Adding to the identity".to_string(),
        },
        AdditionTestVector {
            value: vec![1, 2, 3],
            addend: vec![4, 5, 6],
            sum: vec![5, 7, 9],
            name: "Adding a polynomial of the same order".to_string(),
        },
        AdditionTestVector {
            value: vec![1, 2],
            addend: vec![4, 5, 6],
            sum: vec![5, 7, 6],
            name: "Adding a polynomial of greater order".to_string(),
        },
        AdditionTestVector {
            value: vec![1, 2, 3],
            addend: vec![4, 5],
            sum: vec![5, 7, 3],
            name: "Adding a polynomial of lesser order".to_string(),
        },
    ]
}

#[test]
fn test_polynomial_add() {
    for test_vector in addition_test_vectors() {
        let value =
            uints_to_polynomial(&test_vector.value) + &uints_to_polynomial(&test_vector.addend);
        let expected = uints_to_polynomial(&test_vector.sum);
        assert_eq!(expected, value, "Test vector failed: {}", test_vector.name);
    }
}

#[test]
fn test_polynomial_subtract() {
    for test_vector in addition_test_vectors() {
        let value =
            uints_to_polynomial(&test_vector.sum) - &uints_to_polynomial(&test_vector.addend);
        let expected = uints_to_polynomial(&test_vector.value);
        assert_eq!(expected, value, "Test vector failed: {}", test_vector.name);
    }
}

struct MultiplicationTestVector {
    value: Vec<u32>,
    factor: Vec<u32>,
    product: Vec<u32>,
    name: String,
}

fn multiplication_test_vectors() -> Vec<MultiplicationTestVector> {
    vec![
        MultiplicationTestVector {
            value: vec![],
            factor: vec![],
            product: vec![],
            name: "Empty vector multiplication".to_string(),
        },
        MultiplicationTestVector {
            value: vec![1],
            factor: vec![],
            product: vec![],
            name: "Right multiply by zero".to_string(),
        },
        MultiplicationTestVector {
            value: vec![],
            factor: vec![2],
            product: vec![],
            name: "Left multiply by zero".to_string(),
        },
        MultiplicationTestVector {
            value: vec![1],
            factor: vec![1, 3, 6],
            product: vec![1, 3, 6],
            name: "Left multiply by one".to_string(),
        },
        MultiplicationTestVector {
            value: vec![4, 8, 1],
            factor: vec![1],
            product: vec![4, 8, 1],
            name: "Right multiply by one".to_string(),
        },
        MultiplicationTestVector {
            value: vec![1, 1],
            factor: vec![2, 4, 5],
            product: vec![2, 6, 9, 5],
            name: "Normal mutiplication".to_string(),
        },
    ]
}

#[test]
fn test_polynomial_multiplication() {
    for test_vector in multiplication_test_vectors() {
        let value =
            uints_to_polynomial(&test_vector.value) * uints_to_polynomial(&test_vector.factor);
        let expected = uints_to_polynomial(&test_vector.product);
        assert_eq!(expected, value, "Test vector failed: {}", test_vector.name);
    }
}

fn constant_addition_test_vectors() -> Vec<(Vec<u32>, u32, Vec<u32>, String)> {
    vec![
        (vec![], 0, vec![], "All zero".to_string()),
        (vec![], 9, vec![9], "Empty vector".to_string()),
        (
            vec![1, 2, 4],
            0,
            vec![1, 2, 4],
            "Adding the identity".to_string(),
        ),
        (
            vec![1, 3, 9],
            3,
            vec![4, 3, 9],
            "Adding a constant".to_string(),
        ),
    ]
}

#[test]
fn test_constant_addition() {
    for (int_value, int_addition, combined_int, test_vector_name) in
        constant_addition_test_vectors()
    {
        let value = uints_to_polynomial(&int_value) + uint_to_fr(int_addition);
        let expected = uints_to_polynomial(&combined_int);
        assert_eq!(expected, value, "Test vector failed: {}", test_vector_name);
    }
}

#[test]
fn test_constant_subtraction() {
    for (int_value, int_addition, combined_int, test_vector_name) in
        constant_addition_test_vectors()
    {
        let value = uints_to_polynomial(&combined_int) - uint_to_fr(int_addition);
        let expected = uints_to_polynomial(&int_value);
        assert_eq!(expected, value, "Test vector failed: {}", test_vector_name);
    }
}

fn constant_multiplication_test_vectors() -> Vec<(Vec<u32>, u32, Vec<u32>, String)> {
    vec![
        (vec![], 0, vec![], "All zero".to_string()),
        (vec![], 9, vec![], "Empty vector".to_string()),
        (vec![1, 2, 4], 0, vec![], "Factor zero".to_string()),
        (
            vec![1, 0, 9],
            3,
            vec![3, 0, 27],
            "Normal factor".to_string(),
        ),
    ]
}

#[test]
fn test_constant_multiplication() {
    for (int_value, int_factor, combined_int, test_vector_name) in
        constant_multiplication_test_vectors()
    {
        let value = &uints_to_polynomial(&int_value) * uint_to_fr(int_factor);
        let expected = uints_to_polynomial(&combined_int);
        assert_eq!(expected, value, "Test vector failed: {}", test_vector_name);
    }
}
