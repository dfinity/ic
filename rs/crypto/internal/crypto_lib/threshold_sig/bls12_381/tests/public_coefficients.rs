//! Verify that public_coefficients does indeed fix the public keys of
//! participants.

use ic_crypto_internal_bls12_381_type::Polynomial;
use ic_crypto_internal_bls12_381_type::{G2Affine, NodeIndex, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::types::{
    PublicCoefficients, PublicKey, ThresholdError,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;
use std::ops::MulAssign;

fn uint_to_g2(num: u32) -> G2Affine {
    (G2Affine::generator() * Scalar::from_u32(num)).to_affine()
}

/// Polynomial evaluation for small polynomials; this will overflow and panic if
/// used for large values.
fn evaluate_integer_polynomial(x: u32, polynomial: &[u32]) -> u32 {
    let mut ans = 0u32;
    let mut power = 1u32;
    for coefficient in polynomial {
        ans += power * coefficient;
        power *= x;
    }
    ans
}

fn test_integer_polynomial_evaluation_is_correct(x: u32, polynomial: &[u32], y: u32) {
    assert_eq!(
        evaluate_integer_polynomial(x, polynomial),
        y,
        "Expected f({x:?})={y:?} for polynomial with coefficients {polynomial:?}"
    );
}
#[test]
fn integer_polynomial_evaluation_is_correct() {
    test_integer_polynomial_evaluation_is_correct(0, &[], 0);
    test_integer_polynomial_evaluation_is_correct(1, &[], 0);
    test_integer_polynomial_evaluation_is_correct(0, &[0, 1, 2], 0);
    test_integer_polynomial_evaluation_is_correct(1, &[0, 1, 2], 3);
    test_integer_polynomial_evaluation_is_correct(2, &[0, 1, 2], 10);
    test_integer_polynomial_evaluation_is_correct(0, &[1, 3, 5], 1);
}

pub fn uints_to_polynomial(integer_coefficients: &[u32]) -> Polynomial {
    let v: Vec<Scalar> = integer_coefficients
        .iter()
        .cloned()
        .map(Scalar::from_u32)
        .collect();

    Polynomial::new(v)
}

pub fn uints_to_public_coefficients(integer_coefficients: &[u32]) -> PublicCoefficients {
    PublicCoefficients {
        coefficients: integer_coefficients
            .iter()
            .cloned()
            .map(uint_to_g2)
            .map(PublicKey)
            .collect(),
    }
}

mod public_coefficients {
    //! Third parties should be able to verify that the public part of a key
    //! share is indeed consistent with the commitment. Additionally, the
    //! share holder should be able to verify that their secret key matches the
    //! public key assigned to them.
    //!
    //! Graphically, these are the edges that need to be validated, and the
    //! system works when the two paths yield the same result:
    //!
    //! Polynomial ---> PublicCoefficients
    //!    |                |
    //!    |                |
    //!    v                v
    //! SecretKey ------> PublicKey

    use super::*;

    /// Given a polynomial, verify that the public_coefficients are calculated
    /// correctly:
    fn test_public_coefficients_are_correct(integer_coefficients: &[u32]) {
        let polynomial = uints_to_polynomial(integer_coefficients);
        let public_coefficients = uints_to_public_coefficients(integer_coefficients);
        assert_eq!(PublicCoefficients::from(polynomial), public_coefficients);
    }
    #[test]
    fn public_coefficients_are_correct() {
        test_public_coefficients_are_correct(&[]);
        test_public_coefficients_are_correct(&[1, 7, 2, 3, 0, 5, 6, 4, 1, 3, 2, 9]);
    }

    /// Given a polynomial, verify that keys are generated correctly
    fn test_key_is_correct(x: u32, integer_coefficients: &[u32]) {
        let polynomial = uints_to_polynomial(integer_coefficients);
        let secret_key = polynomial.evaluate_at(&Scalar::from_u32(x));
        let y = evaluate_integer_polynomial(x, integer_coefficients);
        assert_eq!(secret_key, Scalar::from_u32(y));
    }
    #[test]
    fn key_is_correct() {
        test_key_is_correct(3, &[1, 2, 3, 4, 5]);
        test_key_is_correct(9, &[5, 0, 7, 11]);
        test_key_is_correct(9, &[]);
    }

    /// Given public_coefficients, verify that public keys are computed
    /// correctly
    fn test_public_key_from_public_coefficients_are_correct(x: u32, integer_coefficients: &[u32]) {
        let public_coefficients = uints_to_public_coefficients(integer_coefficients);
        let y = evaluate_integer_polynomial(x, integer_coefficients);
        let public_key = uint_to_g2(y);
        assert_eq!(
            public_coefficients
                .evaluate_at(&Scalar::from_u32(x))
                .to_affine(),
            public_key
        );
    }
    #[test]
    fn public_key_from_public_coefficients_are_correct() {
        test_public_key_from_public_coefficients_are_correct(3, &[1, 2, 3, 4, 5]);
        test_public_key_from_public_coefficients_are_correct(9, &[5, 0, 7, 11]);
    }

    #[test]
    fn test_polynomial_summation_is_correct() {
        assert_eq!(
            uints_to_polynomial(&[1, 3, 5]) + uints_to_polynomial(&[10, 20, 30]),
            uints_to_polynomial(&[11, 23, 35])
        );
    }

    #[test]
    #[allow(clippy::identity_op)]
    fn test_lagrange_coefficients_are_correct() {
        let x_values = [0, 2, 3, 6];

        let lagrange_coefficients: Vec<Scalar> = {
            // The lagrange coefficient numerators and denominators:
            let as_integers = [
                (3 * 4 * 7, (3 - 1) * (4 - 1) * (7 - 1)),
                (1 * 4 * 7, (1 - 3) * (4 - 3) * (7 - 3)),
                (1 * 3 * 7, (1 - 4) * (3 - 4) * (7 - 4)),
                (1 * 3 * 4, (1 - 7) * (3 - 7) * (4 - 7)),
            ];
            let as_fr: Vec<(Scalar, Scalar)> = as_integers
                .iter()
                .map(|(numerator, denominator)| {
                    (Scalar::from_i32(*numerator), Scalar::from_i32(*denominator))
                })
                .collect();
            let divided: Vec<Scalar> = as_fr
                .iter()
                .map(|(numerator, denominator)| {
                    let mut ans = numerator.clone();
                    let inv = denominator.inverse().expect("No inverse");
                    ans.mul_assign(&inv);
                    ans
                })
                .collect();
            divided
        };
        let observed = PublicCoefficients::lagrange_coefficients_at_zero(&x_values)
            .expect("Cannot fail because all the x values are distinct");
        assert_eq!(lagrange_coefficients[..], observed[..]);
    }

    #[test]
    fn test_lagrange_coefficients_at_zero_rejects_duplicate_points() {
        let rng = &mut reproducible_rng();

        for num_coefficients in 1..50 {
            let mut inputs = vec![];

            let dup_r = rng.r#gen::<NodeIndex>();

            inputs.push(dup_r);

            for _i in 0..=num_coefficients {
                let r = rng.r#gen::<NodeIndex>();
                inputs.push(r);
            }
            inputs.push(dup_r);

            assert_eq!(
                PublicCoefficients::lagrange_coefficients_at_zero(&inputs),
                Err(ThresholdError::DuplicateX)
            );
            assert!(PublicCoefficients::lagrange_coefficients_at_zero(&inputs[1..]).is_ok());
        }
    }

    #[test]
    fn test_public_interpolation_is_correct() {
        let polynomial = [2, 4, 9];
        let x_5 = (4, uint_to_g2(evaluate_integer_polynomial(5, &polynomial)));
        let x_3 = (2, uint_to_g2(evaluate_integer_polynomial(3, &polynomial)));
        let x_8 = (7, uint_to_g2(evaluate_integer_polynomial(8, &polynomial)));
        let random_points = [x_5, x_3, x_8];
        let interpolated_polynomial_at_0 =
            PublicCoefficients::interpolate_g2(&random_points).expect("Failed to interpolate");
        assert_eq!(interpolated_polynomial_at_0.to_affine(), uint_to_g2(2));
    }
}
