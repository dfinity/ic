use ic_crypto_internal_threshold_sig_canister_threshold_sig::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;

#[test]
fn poly_zero_times_zero_is_zero() -> CanisterThresholdResult<()> {
    for curve in EccCurveType::all() {
        let zero = EccScalar::zero(curve);

        for coeffs in 0..10 {
            let zpoly = Polynomial::new(curve, vec![zero.clone(); coeffs])?;
            assert!(zpoly.is_zero());
            let zpoly2 = zpoly.mul(&zpoly)?;
            assert!(zpoly2.is_zero());
        }
    }

    Ok(())
}

#[test]
fn poly_a_constant_poly_is_constant() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let constant = EccScalar::random(curve, rng);
        let poly = Polynomial::new(curve, vec![constant.clone()])?;

        for _trial in 0..100 {
            // For a constant polynomial, no matter where we evaluate
            // the result is the constant.
            let r = EccScalar::random(curve, rng);
            assert_eq!(poly.evaluate_at(&r)?, constant);
        }
    }

    Ok(())
}

#[test]
fn poly_simple_polynomial_x_1() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    // Test the behavior of evaluating polynomial x+1

    for curve in EccCurveType::all() {
        let zero = EccScalar::zero(curve);
        let one = EccScalar::one(curve);
        let poly = Polynomial::new(curve, vec![one.clone(), one.clone()])?;

        assert_eq!(poly.evaluate_at(&zero)?, one);

        for _trial in 0..100 {
            let r = EccScalar::random(curve, rng);
            let r_plus_1 = r.add(&one)?;
            assert_eq!(poly.evaluate_at(&r)?, r_plus_1);
        }
    }

    Ok(())
}

#[test]
fn poly_simple_polynomial_x2_x_1() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    // Test the behavior of evaluating polynomial x^2+x+1

    for curve in EccCurveType::all() {
        let zero = EccScalar::zero(curve);
        let one = EccScalar::one(curve);
        let poly = Polynomial::new(curve, vec![one.clone(), one.clone(), one.clone()])?;

        assert_eq!(poly.evaluate_at(&zero)?, one);

        for _trial in 0..100 {
            let r = EccScalar::random(curve, rng);
            let r2 = r.mul(&r)?;
            let r2_plus_r_plus1 = r2.add(&r)?.add(&one)?;

            assert_eq!(poly.evaluate_at(&r)?, r2_plus_r_plus1);
        }
    }

    Ok(())
}

#[test]
fn poly_interpolate_works() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 0..50 {
            let poly = Polynomial::random(curve, num_coefficients, rng);

            let mut samples = Vec::with_capacity(num_coefficients);
            for _i in 0..num_coefficients {
                let r = EccScalar::random(curve, rng);
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
fn poly_interpolate_fails_if_insufficient_points() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 1..50 {
            let poly = Polynomial::random(curve, num_coefficients, rng);

            let mut samples = Vec::with_capacity(num_coefficients - 1);
            for _i in 0..num_coefficients - 1 {
                let r = EccScalar::random(curve, rng);
                let p_r = poly.evaluate_at(&r)?;
                samples.push((r, p_r));
            }

            match Polynomial::interpolate(curve, &samples) {
                Err(e) => assert_eq!(e, CanisterThresholdError::InterpolationError),
                Ok(p) => assert_ne!(p, poly),
            }
        }
    }

    Ok(())
}

#[test]
fn poly_interpolate_errors_on_duplicate_inputs() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 0..50 {
            let poly = Polynomial::random(curve, num_coefficients, rng);

            let mut samples = vec![];

            let dup_r = EccScalar::random(curve, rng);
            let dup_p_r = poly.evaluate_at(&dup_r)?;

            for _i in 0..=num_coefficients {
                samples.push((dup_r.clone(), dup_p_r.clone()));
            }

            for _i in 0..=num_coefficients {
                let r = EccScalar::random(curve, rng);
                let p_r = poly.evaluate_at(&r)?;
                samples.push((r, p_r));
                samples.push((dup_r.clone(), dup_p_r.clone()));
            }

            assert!(Polynomial::interpolate(curve, &samples).is_err());
        }
    }

    Ok(())
}

#[test]
fn poly_interpolate_is_resilient_to_low_x_points() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 0..50 {
            let poly = Polynomial::random(curve, num_coefficients, rng);
            assert_eq!(poly.non_zero_coefficients(), num_coefficients);

            let one = EccScalar::one(curve);
            let mut x = EccScalar::zero(curve);

            let mut samples = vec![];

            for _i in 0..=num_coefficients {
                let p_x = poly.evaluate_at(&x)?;
                samples.push((x.clone(), p_x));
                x = x.add(&one)?;
            }

            let interp = Polynomial::interpolate(curve, &samples)?;
            assert_eq!(poly, interp);
        }
    }

    Ok(())
}

#[test]
fn poly_threshold_secret_sharing() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let zero = EccScalar::zero(curve);
        let secret = EccScalar::random(curve, rng);

        for num_coefficients in 1..50 {
            let poly = Polynomial::random_with_constant(&secret, num_coefficients, rng)?;
            assert_eq!(poly.non_zero_coefficients(), num_coefficients);

            let mut shares = Vec::with_capacity(num_coefficients + 1);
            for _i in 0..num_coefficients + 1 {
                let r = EccScalar::random(curve, rng);
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
fn poly_simple_commitments() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 1..50 {
            let poly = Polynomial::random(curve, num_coefficients, rng);
            let _commitment = SimpleCommitment::create(&poly, num_coefficients)?;
        }
    }

    Ok(())
}

#[test]
fn poly_pedersen_commitments() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 1..50 {
            let poly_a = Polynomial::random(curve, num_coefficients, rng);
            let poly_b = Polynomial::random(curve, num_coefficients, rng);
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

    fn int_to_scalars(curve: EccCurveType, ints: &[i64]) -> Vec<EccScalar> {
        let mut scalars = Vec::with_capacity(ints.len());
        for i in ints {
            let s = EccScalar::from_u64(curve, i.unsigned_abs());
            scalars.push(if i.is_negative() { s.negate() } else { s });
        }
        scalars
    }

    let x_values = [1, 2, 3, 6];

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

    let zero = EccScalar::zero(curve);

    let observed = LagrangeCoefficients::at_value(&zero, &x_values)
        .expect("Failed even though coordinates were distinct")
        .coefficients()
        .to_vec();

    assert_eq!(computed, observed);
}

fn interpolation_at_zero(x: &[NodeIndex], y: &[EccPoint]) -> CanisterThresholdResult<EccPoint> {
    let curve_type = y[0].curve_type();
    let coefficients = LagrangeCoefficients::at_zero(curve_type, x)?;
    coefficients.interpolate_point(y)
}

fn random_node_indexes(count: usize) -> Vec<NodeIndex> {
    let rng = &mut reproducible_rng();

    let mut set = std::collections::BTreeSet::new();

    while set.len() != count {
        let r = rng.r#gen::<NodeIndex>();
        set.insert(r);
    }

    set.iter().cloned().collect()
}

#[test]
fn poly_point_interpolation_at_zero() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 1..30 {
            let sk = EccScalar::random(curve, rng);
            let pk = EccPoint::mul_by_g(&sk);

            let poly = Polynomial::random_with_constant(&sk, num_coefficients, rng)?;

            let x = random_node_indexes(num_coefficients);
            let mut y = Vec::with_capacity(num_coefficients);

            for r in &x {
                let p_r = poly.evaluate_at(&EccScalar::from_node_index(curve, *r))?;
                let mut g_p_r = EccPoint::mul_by_g(&p_r);
                g_p_r.precompute(EccPoint::DEFAULT_LUT_WINDOW_SIZE)?;
                y.push(g_p_r);
            }

            let g0 = interpolation_at_zero(&x, &y)?;
            assert_eq!(g0, pk);
        }
    }

    Ok(())
}

#[test]
fn poly_point_interpolation_at_value() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 1..30 {
            let value = EccScalar::random(curve, rng);

            let poly = Polynomial::random(curve, num_coefficients, rng);

            let x = random_node_indexes(num_coefficients);
            let mut y = Vec::with_capacity(num_coefficients);

            for r in &x {
                let p_r = poly.evaluate_at(&EccScalar::from_node_index(curve, *r))?;
                let mut g_p_r = EccPoint::mul_by_g(&p_r);
                g_p_r.precompute(EccPoint::DEFAULT_LUT_WINDOW_SIZE)?;
                y.push(g_p_r);
            }

            let coefficients = LagrangeCoefficients::at_value(&value, &x)?;

            assert_eq!(
                coefficients.interpolate_point(&y)?,
                EccPoint::mul_by_g(&poly.evaluate_at(&value)?)
            );
        }
    }

    Ok(())
}

#[test]
fn poly_scalar_interpolation_at_value() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 1..30 {
            let value = EccScalar::random(curve, rng);

            let poly = Polynomial::random(curve, num_coefficients, rng);

            let x = random_node_indexes(num_coefficients);
            let mut y = Vec::with_capacity(num_coefficients);

            for r in &x {
                let p_r = poly.evaluate_at(&EccScalar::from_node_index(curve, *r))?;
                y.push(p_r);
            }

            let coefficients = LagrangeCoefficients::at_value(&value, &x)?;

            assert_eq!(
                coefficients.interpolate_scalar(&y)?,
                poly.evaluate_at(&value)?
            );
        }
    }

    Ok(())
}

#[test]
fn poly_point_interpolation_at_zero_rejects_duplicates() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 1..10 {
            let sk = EccScalar::random(curve, rng);
            let poly = Polynomial::random_with_constant(&sk, num_coefficients, rng)?;

            let mut x = random_node_indexes(num_coefficients);
            let mut y = Vec::with_capacity(num_coefficients + 1);

            x.push(x[rng.r#gen::<usize>() % x.len()]);

            for r in &x {
                let mut g_p_r =
                    EccPoint::mul_by_g(&poly.evaluate_at(&EccScalar::from_node_index(curve, *r))?);
                g_p_r.precompute(EccPoint::DEFAULT_LUT_WINDOW_SIZE)?;
                y.push(g_p_r);
            }

            assert!(interpolation_at_zero(&x, &y).is_err());
        }
    }

    Ok(())
}

#[test]
fn poly_point_interpolation_at_zero_fails_with_insufficient_shares() -> CanisterThresholdResult<()>
{
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        for num_coefficients in 2..20 {
            let sk = EccScalar::random(curve, rng);
            let pk = EccPoint::mul_by_g(&sk);

            let poly = Polynomial::random_with_constant(&sk, num_coefficients, rng)?;
            let x = random_node_indexes(num_coefficients - 1);
            let mut y = Vec::with_capacity(num_coefficients - 1);

            for r in &x {
                let mut g_p_r =
                    EccPoint::mul_by_g(&poly.evaluate_at(&EccScalar::from_node_index(curve, *r))?);
                g_p_r.precompute(EccPoint::DEFAULT_LUT_WINDOW_SIZE)?;
                y.push(g_p_r);
            }

            // Interpolation fails to recover the correct value with insufficient values
            match interpolation_at_zero(&x, &y) {
                Err(e) => assert_eq!(e, CanisterThresholdError::InterpolationError),
                Ok(pt) => assert_ne!(pt, pk),
            }
        }
    }

    Ok(())
}

#[test]
fn polynomial_should_redact_logs() -> Result<(), CanisterThresholdError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let constant = EccScalar::random(curve, rng);
        let poly = Polynomial::new(curve, vec![constant])?;
        let log = format!("{poly:?}");
        assert_eq!(
            format!("Polynomial {{curve: {curve:?}, coefficients: REDACTED}}"),
            log
        );
    }

    Ok(())
}

#[test]
fn commitment_opening_should_redact_logs() -> Result<(), CanisterThresholdError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let scalar = EccScalar::random(curve, rng);
        let opening = CommitmentOpening::Simple(scalar);
        let log = format!("{opening:?}");
        assert_eq!(
            format!("CommitmentOpening::Simple({curve:?}(REDACTED))"),
            log
        );
    }

    Ok(())
}

#[test]
fn simple_commitment_stable_representation_is_stable() {
    fn simple_commitment_bytes(curve: EccCurveType, sz: usize) -> Vec<u8> {
        let rng = &mut Seed::from_bytes(&vec![42; sz]).into_rng();

        let polynomial = Polynomial::random(curve, sz, rng);

        let opening =
            SimpleCommitment::create(&polynomial, sz).expect("SimpleCommitment::create failed");

        let opening = PolynomialCommitment::Simple(opening);
        opening.stable_representation()
    }

    assert_eq!(
        hex::encode(simple_commitment_bytes(EccCurveType::K256, 1)),
        "53010269a513d6375661fb245a5b66206a85671568178e0608b4585bee50542be4999a"
    );
    assert_eq!(
        hex::encode(simple_commitment_bytes(EccCurveType::K256, 2)),
        "5301034af5f78220f96e265d9c93af4463b7b91a2dc1ef1db105913cb85024c697f79c036ac66cf30781414b2cb7e4e5ee13885e3d6c8049f2cf623f2d24f37de1d08432"
    );

    assert_eq!(
        hex::encode(simple_commitment_bytes(EccCurveType::P256, 1)),
        "5302027996e5e935a3e833b61251b232b629defc6120a469fb3fa3f1815491c4ec820c"
    );
    assert_eq!(
        hex::encode(simple_commitment_bytes(EccCurveType::P256, 2)),
        "530203d0cbae46273bf136b2a34fb9962ac837a46493ffc9142119584d929a0fac488c030a2d9528db1d50193c868cd77f991b6bfa25daa82fedd9fb6406df46c229577f\
        "
    );
}

#[test]
fn pedersen_commitment_stable_representation_is_stable() {
    fn pedersen_commitment_bytes(curve: EccCurveType, sz: usize) -> Vec<u8> {
        let rng = &mut Seed::from_bytes(&vec![42; sz]).into_rng();

        let polynomial = Polynomial::random(curve, sz, rng);
        let mask = Polynomial::random(curve, sz, rng);

        let opening = PedersenCommitment::create(&polynomial, &mask, sz)
            .expect("PedersenCommitment::create failed");

        let opening = PolynomialCommitment::Pedersen(opening);
        opening.stable_representation()
    }

    assert_eq!(
        hex::encode(pedersen_commitment_bytes(EccCurveType::K256, 1)),
        "500103e4febce7716f1f46b4c3ce26332c71ac013d901bf214bcf04a02c331ac9df8fb"
    );
    assert_eq!(
        hex::encode(pedersen_commitment_bytes(EccCurveType::K256, 2)),
        "500103dcd8d3bf27056abab419a773e1eb8f066968a427af43148595b105d2875b8804036bcc68f6a1547bdc684a95e8dde462891e130fd35bf79911e0f503a6469cb08f"
    );

    assert_eq!(
        hex::encode(pedersen_commitment_bytes(EccCurveType::P256, 1)),
        "5002032f7131615a8e025949ccce43d18ac5f76aaabc7d2c86139fb1499d4271af2996"
    );
    assert_eq!(
        hex::encode(pedersen_commitment_bytes(EccCurveType::P256, 2)),
        "500202e48822b0cd88327b344f4064467a221c60e012b572f8ade76391696468b1dda203a251d2fb0a33059bc78738379aa0b4cba4b26e87e6a95362a303153d7d3988b6"
    );
}
