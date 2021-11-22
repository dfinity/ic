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

            let mut samples = Vec::with_capacity(num_coefficients + 1);
            for _i in 0..=num_coefficients {
                let r = EccScalar::random(curve, &mut rng)?;
                let p_r = poly.evaluate_at(&r)?;
                samples.push((r, p_r));
            }

            let interp = Polynomial::interpolate(curve, &samples)?;
            assert_eq!(poly, interp);
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
            let _commitment = SimpleCommitment::new(&poly, num_coefficients)?;
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
            let commitment_ab = PedersenCommitment::new(&poly_a, &poly_b, num_coefficients)?;
            let commitment_ba = PedersenCommitment::new(&poly_b, &poly_a, num_coefficients)?;

            assert_ne!(commitment_ab, commitment_ba);
        }
    }

    Ok(())
}
