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
        for degree in 0..50 {
            let poly = Polynomial::random(curve, degree, &mut rng)?;

            let mut samples = Vec::with_capacity(degree + 1);
            for _i in 0..=degree {
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
        for degree in 0..50 {
            let poly = Polynomial::random(curve, degree, &mut rng)?;

            let mut samples = vec![];

            let dup_r = EccScalar::random(curve, &mut rng)?;
            let dup_p_r = poly.evaluate_at(&dup_r)?;

            for _i in 0..=degree {
                samples.push((dup_r, dup_p_r));
            }

            for _i in 0..=degree {
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
        for degree in 0..50 {
            let poly = Polynomial::random(curve, degree, &mut rng)?;

            let one = EccScalar::one(curve);
            let mut x = EccScalar::zero(curve);

            let mut samples = vec![];

            for _i in 0..=degree {
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

        for degree in 0..50 {
            let poly = Polynomial::random_with_constant(secret, degree, &mut rng)?;

            let mut shares = Vec::with_capacity(degree + 1);
            for _i in 0..degree + 1 {
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
