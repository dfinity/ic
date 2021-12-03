use tecdsa::*;

#[test]
fn poly_a_constant_poly_is_constant() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        let constant = EccScalar::random(curve, &mut rng)?;
        let poly = Polynomial::new(curve, vec![constant])?;

        for _trial in 0..100 {
            // For a constant polynomial, no matter where we evaluate
            // the result is the constant.
            let r = EccScalar::random(curve, &mut rng)?;
            assert_eq!(poly.evaluate_at(&r)?, constant);
        }
    }

    Ok(())
}

#[test]
fn poly_simple_polynomial_x_1() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    // Test the behavior of evaluating polynomial x+1

    for curve in EccCurveType::all() {
        let zero = EccScalar::zero(curve);
        let one = EccScalar::one(curve);
        let poly = Polynomial::new(curve, vec![one, one])?;

        assert_eq!(poly.evaluate_at(&zero)?, one);

        for _trial in 0..100 {
            let r = EccScalar::random(curve, &mut rng)?;
            let r_plus_1 = r.add(&one)?;
            assert_eq!(poly.evaluate_at(&r)?, r_plus_1);
        }
    }

    Ok(())
}

#[test]
fn poly_simple_polynomial_x2_x_1() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    // Test the behavior of evaluating polynomial x^2+x+1

    for curve in EccCurveType::all() {
        let zero = EccScalar::zero(curve);
        let one = EccScalar::one(curve);
        let poly = Polynomial::new(curve, vec![one, one, one])?;

        assert_eq!(poly.evaluate_at(&zero)?, one);

        for _trial in 0..100 {
            let r = EccScalar::random(curve, &mut rng)?;
            let r2 = r.mul(&r)?;
            let r2_plus_r_plus1 = r2.add(&r)?.add(&one)?;

            assert_eq!(poly.evaluate_at(&r)?, r2_plus_r_plus1);
        }
    }

    Ok(())
}

#[test]
fn poly_interpolate_works() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 0..50 {
            let poly = Polynomial::random(curve, num_coefficients, &mut rng)?;

            let mut samples = Vec::with_capacity(num_coefficients);
            for _i in 0..num_coefficients {
                let r = EccScalar::random(curve, &mut rng)?;
                let p_r = poly.evaluate_at(&r)?;
                samples.push((r, p_r));
            }
            assert_eq!(samples.len(), num_coefficients);

            let interp = Polynomial::interpolate(curve, &samples)?;
            assert_eq!(poly, interp);
        }
    }

    Ok(())
}

#[test]
fn poly_interpolate_fails_if_insufficient_points() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 1..50 {
            let poly = Polynomial::random(curve, num_coefficients, &mut rng)?;

            let mut samples = Vec::with_capacity(num_coefficients - 1);
            for _i in 0..num_coefficients - 1 {
                let r = EccScalar::random(curve, &mut rng)?;
                let p_r = poly.evaluate_at(&r)?;
                samples.push((r, p_r));
            }

            match Polynomial::interpolate(curve, &samples) {
                Err(e) => assert_eq!(e, ThresholdEcdsaError::InterpolationError),
                Ok(p) => assert_ne!(p, poly),
            }
        }
    }

    Ok(())
}

#[test]
fn poly_interpolate_is_resilient_to_duplicate_points() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 0..50 {
            let poly = Polynomial::random(curve, num_coefficients, &mut rng)?;

            let mut samples = vec![];

            let dup_r = EccScalar::random(curve, &mut rng)?;
            let dup_p_r = poly.evaluate_at(&dup_r)?;

            for _i in 0..=num_coefficients {
                samples.push((dup_r, dup_p_r));
            }

            for _i in 0..=num_coefficients {
                let r = EccScalar::random(curve, &mut rng)?;
                let p_r = poly.evaluate_at(&r)?;
                samples.push((r, p_r));
                samples.push((dup_r, dup_p_r));
            }

            let interp = Polynomial::interpolate(curve, &samples)?;

            assert_eq!(poly, interp);
        }
    }

    Ok(())
}

#[test]
fn poly_interpolate_is_resilient_to_low_x_points() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 0..50 {
            let poly = Polynomial::random(curve, num_coefficients, &mut rng)?;
            assert_eq!(poly.non_zero_coefficients(), num_coefficients);

            let one = EccScalar::one(curve);
            let mut x = EccScalar::zero(curve);

            let mut samples = vec![];

            for _i in 0..=num_coefficients {
                let p_x = poly.evaluate_at(&x)?;
                samples.push((x, p_x));
                x = x.add(&one)?;
            }

            let interp = Polynomial::interpolate(curve, &samples)?;
            assert_eq!(poly, interp);
        }
    }

    Ok(())
}

#[test]
fn poly_threshold_secret_sharing() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        let zero = EccScalar::zero(curve);
        let secret = EccScalar::random(curve, &mut rng)?;

        for num_coefficients in 1..50 {
            let poly = Polynomial::random_with_constant(secret, num_coefficients, &mut rng)?;
            assert_eq!(poly.non_zero_coefficients(), num_coefficients);

            let mut shares = Vec::with_capacity(num_coefficients + 1);
            for _i in 0..num_coefficients + 1 {
                let r = EccScalar::random(curve, &mut rng)?;
                let p_r = poly.evaluate_at(&r)?;
                shares.push((r, p_r));
            }

            let interp = Polynomial::interpolate(curve, &shares)?;
            assert_eq!(interp.evaluate_at(&zero)?, secret);
        }
    }

    Ok(())
}

#[test]
fn poly_get_coeff() -> ThresholdEcdsaResult<()> {
    let curve = EccCurveType::K256;
    let num_coefficients = 5;

    let coeffs = vec![
        EccScalar::from_u64(curve, 1),
        EccScalar::from_u64(curve, 2),
        EccScalar::from_u64(curve, 3),
        EccScalar::from_u64(curve, 4),
        EccScalar::from_u64(curve, 5),
    ];

    let poly = Polynomial::new(curve, coeffs.clone())?;

    for i in 0..num_coefficients {
        assert!(poly.get_coefficients(i).is_err());
    }

    for i in num_coefficients..(num_coefficients * 2) {
        let c = poly.get_coefficients(i).unwrap();
        assert_eq!(c.len(), i);

        for (i, c) in c.iter().enumerate() {
            if i < num_coefficients {
                assert_eq!(*c, coeffs[i]);
            } else {
                assert!(c.is_zero());
            }
        }
    }

    Ok(())
}

#[test]
fn poly_simple_commitments() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 1..50 {
            let poly = Polynomial::random(curve, num_coefficients, &mut rng)?;
            let _commitment = SimpleCommitment::create(&poly, num_coefficients)?;
        }
    }

    Ok(())
}

#[test]
fn poly_pedersen_commitments() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 1..50 {
            let poly_a = Polynomial::random(curve, num_coefficients, &mut rng)?;
            let poly_b = Polynomial::random(curve, num_coefficients, &mut rng)?;
            let commitment_ab = PedersenCommitment::create(&poly_a, &poly_b, num_coefficients)?;
            let commitment_ba = PedersenCommitment::create(&poly_b, &poly_a, num_coefficients)?;

            assert_ne!(commitment_ab, commitment_ba);
        }
    }

    Ok(())
}

#[test]
#[allow(clippy::identity_op)]
fn poly_lagrange_coefficients_at_zero_are_correct() {
    let curve = EccCurveType::K256;

    fn int_to_scalars(curve: EccCurveType, x: &[i64]) -> Vec<EccScalar> {
        x.iter().map(|x| EccScalar::from_i64(curve, *x)).collect()
    }

    let x_values = int_to_scalars(curve, &[2, 3, 4, 7]);

    let lagrange_numerators = int_to_scalars(curve, &[3 * 4 * 7, 2 * 4 * 7, 2 * 3 * 7, 2 * 3 * 4]);

    let lagrange_denominators = int_to_scalars(
        curve,
        &[
            (3 - 2) * (4 - 2) * (7 - 2),
            (2 - 3) * (4 - 3) * (7 - 3),
            (2 - 4) * (3 - 4) * (7 - 4),
            (2 - 7) * (3 - 7) * (4 - 7),
        ],
    );

    let computed = lagrange_numerators
        .iter()
        .zip(lagrange_denominators)
        .map(|(numerator, denominator)| numerator.mul(&denominator.invert().unwrap()).unwrap())
        .collect::<Vec<EccScalar>>();

    let observed = lagrange_coefficients_at_zero(&x_values)
        .expect("Failed even though coordinates were distinct");

    assert_eq!(computed, observed);
}

#[test]
fn poly_point_interpolation_at_zero() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        let g = EccCurve::new(curve).generator_g()?;

        for num_coefficients in 1..30 {
            let sk = EccScalar::random(curve, &mut rng)?;
            let pk = g.scalar_mul(&sk)?;

            let poly = Polynomial::random_with_constant(sk, num_coefficients, &mut rng)?;

            let mut samples = Vec::with_capacity(num_coefficients);

            for _i in 0..num_coefficients {
                let x = EccScalar::random(curve, &mut rng)?;
                let p_x = poly.evaluate_at(&x)?;
                let g_p_x = g.scalar_mul(&p_x)?;
                samples.push((x, g_p_x));
            }

            let g0 = EccPoint::interpolation_at_zero(&samples)?;
            assert_eq!(g0, pk);
        }
    }

    Ok(())
}

#[test]
fn poly_point_interpolation_at_zero_rejects_duplicates() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        let g = EccCurve::new(curve).generator_g()?;

        for num_coefficients in 1..10 {
            let sk = EccScalar::random(curve, &mut rng)?;
            let poly = Polynomial::random_with_constant(sk, num_coefficients, &mut rng)?;

            let mut samples = Vec::with_capacity(num_coefficients);

            let dup_x = EccScalar::random(curve, &mut rng)?;
            let dup_g_p_x = g.scalar_mul(&poly.evaluate_at(&dup_x)?)?;

            samples.push((dup_x, dup_g_p_x));

            for _i in 0..num_coefficients {
                let x = EccScalar::random(curve, &mut rng)?;
                let g_p_x = g.scalar_mul(&poly.evaluate_at(&x)?)?;
                samples.push((x, g_p_x));
            }

            samples.push((dup_x, dup_g_p_x));

            assert!(EccPoint::interpolation_at_zero(&samples).is_err());
        }
    }

    Ok(())
}

#[test]
fn poly_point_interpolation_at_zero_fails_with_insufficient_shares() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        let g = EccCurve::new(curve).generator_g()?;

        for num_coefficients in 1..20 {
            let sk = EccScalar::random(curve, &mut rng)?;
            let pk = g.scalar_mul(&sk)?;

            let poly = Polynomial::random_with_constant(sk, num_coefficients, &mut rng)?;
            let mut samples = Vec::with_capacity(num_coefficients - 1);

            for _i in 0..num_coefficients - 1 {
                let x = EccScalar::random(curve, &mut rng)?;
                let g_p_x = g.scalar_mul(&poly.evaluate_at(&x)?)?;
                samples.push((x, g_p_x));
            }

            // Interpolation fails to recover the correct value with insufficient values
            match EccPoint::interpolation_at_zero(&samples) {
                Err(e) => assert_eq!(e, ThresholdEcdsaError::InterpolationError),
                Ok(pt) => assert_ne!(pt, pk),
            }
        }
    }

    Ok(())
}

#[test]
fn polynomial_should_redact_logs() -> Result<(), ThresholdEcdsaError> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        let constant = EccScalar::random(curve, &mut rng)?;
        let poly = Polynomial::new(curve, vec![constant])?;
        let log = format!("{:?}", poly);
        assert_eq!(
            format!("Polynomial {{curve: {:?}, coefficients: REDACTED}}", curve),
            log
        );
    }

    Ok(())
}

#[test]
fn commitment_opening_should_redact_logs() -> Result<(), ThresholdEcdsaError> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        let scalar = EccScalar::random(curve, &mut rng)?;
        let opening = CommitmentOpening::Simple(scalar);
        let log = format!("{:?}", opening);
        assert_eq!(
            format!("CommitmentOpening::Simple({:?}(REDACTED))", curve),
            log
        );
    }

    Ok(())
}
