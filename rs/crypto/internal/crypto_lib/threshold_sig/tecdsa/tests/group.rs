use ic_crypto_internal_threshold_sig_ecdsa::*;

#[test]
fn hash_to_scalar_is_deterministic() -> ThresholdEcdsaResult<()> {
    let input = "test input string".as_bytes();
    let domain_separator = "domain sep".as_bytes();

    for curve_type in EccCurveType::all() {
        let s1 = EccScalar::hash_to_scalar(curve_type, input, domain_separator)?;
        let s2 = EccScalar::hash_to_scalar(curve_type, input, domain_separator)?;

        assert_eq!(hex::encode(s1.serialize()), hex::encode(s2.serialize()));
    }

    Ok(())
}

#[test]
fn hash_to_scalar_p256_has_fixed_output() -> ThresholdEcdsaResult<()> {
    let curve_type = EccCurveType::P256;
    let input = "known answer test input".as_bytes();
    let domain_separator = "domain sep".as_bytes();

    let s = EccScalar::hash_to_scalar(curve_type, input, domain_separator)?;

    assert_eq!(
        hex::encode(s.serialize()),
        "8bfdfb742b025311d5e80a5070e2d074ea03c363d16cd3548debc3a408729d37"
    );

    Ok(())
}

#[test]
fn hash_to_scalar_k256_has_fixed_output() -> ThresholdEcdsaResult<()> {
    let curve_type = EccCurveType::K256;
    let input = "known answer test input".as_bytes();
    let domain_separator = "domain sep".as_bytes();

    let s = EccScalar::hash_to_scalar(curve_type, input, domain_separator)?;

    assert_eq!(
        hex::encode(s.serialize()),
        "3670f931a6cbff777594bf1488812b63895dfe5df9814584dfd231f69a66541a"
    );

    Ok(())
}

#[test]
fn generator_h_has_expected_value() -> ThresholdEcdsaResult<()> {
    for curve_type in EccCurveType::all() {
        let h = EccPoint::generator_h(curve_type)?;

        let input = "h";
        let dst = format!("ic-crypto-tecdsa-{}-generator-h", curve_type);

        let h2p = EccPoint::hash_to_point(curve_type, input.as_bytes(), dst.as_bytes())?;

        assert_eq!(h, h2p);
    }
    Ok(())
}

#[test]
fn k256_wide_reduce_scalar_expected_value() -> ThresholdEcdsaResult<()> {
    // Checked using Python
    let wide_input = hex::decode("5465872a72824a73539f16e825035c403a2596407116900d47141fca8cbfd9a638af75a71310b08fe6351dd302b820c86b15e71ea73c78c876c1f88338a0").unwrap();

    let scalar = EccScalar::from_bytes_wide(EccCurveType::K256, &wide_input)?;

    assert_eq!(
        hex::encode(scalar.serialize()),
        "5bc912d1f858a44805b5bcf9809751eb7ca8cd5efe9b9bef62374b55a857ba1b"
    );

    Ok(())
}

#[test]
fn p256_wide_reduce_scalar_expected_value() -> ThresholdEcdsaResult<()> {
    // Checked using Python
    let wide_input = hex::decode("5465872a72824a73539f16e825035c403a2596407116900d47141fca8cbfd9a638af75a71310b08fe6351dd302b820c86b15e71ea73c78c876c1f88338a0").unwrap();

    let scalar = EccScalar::from_bytes_wide(EccCurveType::P256, &wide_input)?;

    assert_eq!(
        hex::encode(scalar.serialize()),
        "87b5343f875ced075916b4d84e1642aebe8784bd914295c51e484d133595b57e"
    );

    Ok(())
}

#[test]
fn test_scalar_negate() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve in EccCurveType::all() {
        let zero = EccScalar::zero(curve);

        for _trial in 0..100 {
            let random = EccScalar::random(curve, &mut rng)?;
            let n_random = random.negate();
            let should_be_zero = random.add(&n_random)?;
            assert_eq!(should_be_zero, zero);
            assert!(should_be_zero.is_zero());

            let should_be_zero = n_random.add(&random)?;
            assert_eq!(should_be_zero, zero);
            assert!(should_be_zero.is_zero());
        }
    }

    Ok(())
}

#[test]
fn test_point_mul_by_node_index() -> ThresholdEcdsaResult<()> {
    for curve in EccCurveType::all() {
        let g = EccPoint::generator_g(curve)?;

        for node_index in 0..300 {
            let g_ni = g.mul_by_node_index(node_index)?;

            let scalar = EccScalar::from_node_index(curve, node_index);
            let g_s = g.scalar_mul(&scalar)?;

            assert_eq!(g_s, g_ni);
        }
    }

    Ok(())
}
