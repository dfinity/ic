use hex_literal::hex;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{Rng, RngCore};

#[test]
fn not_affected_by_point_serialization_bug() -> CanisterThresholdResult<()> {
    // Repro of https://github.com/RustCrypto/elliptic-curves/issues/529
    let curve = EccCurveType::K256;

    let pts = [
        "024b395881d9965c4621459ad2ec12716fa7f669b6108ad3b8b82b91644fb44808",
        "02e77d7b458fb3a2df7d201806e8e1dbce8c1138303156c43398ac62891c43e3cc",
        "02f973e12be0ea160cc82c16563753749b5e6590d22a0b9ab16cd48b9bd951b167",
    ];

    for pt in pts {
        let bytes = hex::decode(pt).unwrap();
        let pt = EccPoint::deserialize(curve, &bytes)?;
        let pt_bytes = pt.serialize();

        assert_eq!(bytes, pt_bytes);
    }

    Ok(())
}

#[test]
fn ed25519_rejects_non_canonical_points() {
    /// The 26 non-canonical points of Ed25519
    ///
    /// Ed25519 has a set of points which are considered valid but are not
    /// the canonical encoding of the point. That is, implementations should
    /// never generate them, but are expected to parse them.
    ///
    /// We expect that all peers in the protocol behave correctly and do not
    /// ever produce a non-canonical point encoding. Given this, we reject
    /// such points immediately.
    ///
    /// See <https://hdevalence.ca/blog/2020-10-04-its-25519am> and
    /// <https://eprint.iacr.org/2020/1244.pdf> for more background
    /// on non-canonical points in Ed25519.
    ///
    /// This list of point encodings was generated using a test in ed25519-zebra
    /// <https://github.com/ZcashFoundation/ed25519-zebra/blob/main/tests/util/mod.rs#L81-L155>
    const NON_CANONICAL_POINTS: [[u8; 32]; 26] = [
        hex!("0100000000000000000000000000000000000000000000000000000000000080"),
        hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ];

    for pt in NON_CANONICAL_POINTS {
        assert!(EccPoint::deserialize(EccCurveType::Ed25519, &pt).is_err());
    }
}

#[test]
fn ed25519_rejects_non_canonical_points_search() {
    /*
    Due to the structure of Ed25519 point encoding, all non-canonical points
    are of the form

    XX00...00YY (exactly 1 of these)

    or

    XXFF...FFYY (exactly 25 of these)

    To test our check, we simply enumerate all such possible point encodings,
    then verify that either the encoding is rejected, or else that the encoding
    is canonical (ie that re-encoding the point results in the originally provided input)
     */

    fn is_rejected_or_canonical(bytes: &[u8; 32]) -> bool {
        match EccPoint::deserialize(EccCurveType::Ed25519, bytes) {
            Ok(pt) => pt.serialize() == bytes,
            _ => true,
        }
    }

    let mut pt_00 = [0u8; 32];
    let mut pt_ff = [0xFFu8; 32];

    for x in 0u8..=255 {
        for y in 0u8..=255 {
            pt_00[0] = x;
            pt_00[31] = y;

            assert!(
                is_rejected_or_canonical(&pt_00),
                "Accepted non-canonical {}",
                hex::encode(pt_00)
            );

            pt_ff[0] = x;
            pt_ff[31] = y;

            assert!(
                is_rejected_or_canonical(&pt_ff),
                "Accepted non-canonical {}",
                hex::encode(pt_ff)
            );
        }
    }
}

#[test]
fn verify_serialization_round_trips_correctly() -> CanisterThresholdResult<()> {
    fn assert_serialization_round_trips(pt: EccPoint) {
        let curve_type = pt.curve_type();
        let b = pt.serialize();

        assert_eq!(b.len(), curve_type.point_bytes());

        let pt2 = EccPoint::deserialize(curve_type, &b)
            .expect("Failed to deserialize the point serialization");

        assert_eq!(pt, pt2);

        let b2 = pt2.serialize();
        assert_eq!(b, b2);
    }

    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let identity = EccPoint::identity(curve_type);

        if curve_type != EccCurveType::Ed25519 {
            // Identity should consist entirely of zero bytes
            // except for Edwards which does its own thing
            assert!(identity.serialize().iter().all(|x| *x == 0x00));
        }

        assert_serialization_round_trips(identity);
        assert_serialization_round_trips(EccPoint::generator_g(curve_type));
        assert_serialization_round_trips(EccPoint::generator_h(curve_type));

        for _r in 0..100 {
            let s = EccScalar::random(curve_type, rng);
            let gs = EccPoint::mul_by_g(&s);

            assert_serialization_round_trips(gs);
        }
    }

    Ok(())
}

#[test]
fn hash_to_scalar_is_deterministic() -> CanisterThresholdResult<()> {
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
fn hash_to_scalar_p256_has_fixed_output() -> CanisterThresholdResult<()> {
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
fn hash_to_scalar_k256_has_fixed_output() -> CanisterThresholdResult<()> {
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
fn generator_h_has_expected_value() -> CanisterThresholdResult<()> {
    for curve_type in EccCurveType::all() {
        let h = EccPoint::generator_h(curve_type);

        let input = "h";

        let proto_name = if curve_type == EccCurveType::K256 || curve_type == EccCurveType::P256 {
            "tecdsa"
        } else {
            "idkg"
        };

        let dst = format!("ic-crypto-{proto_name}-{curve_type}-generator-h");

        let h2p = EccPoint::hash_to_point(curve_type, input.as_bytes(), dst.as_bytes())?;

        assert_eq!(h, h2p);
    }
    Ok(())
}

#[test]
fn k256_wide_reduce_scalar_expected_value() -> CanisterThresholdResult<()> {
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
fn p256_wide_reduce_scalar_expected_value() -> CanisterThresholdResult<()> {
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
fn ed25519_wide_reduce_scalar_expected_value() -> CanisterThresholdResult<()> {
    // Checked using Python
    let wide_input = hex::decode("5465872a72824a73539f16e825035c403a2596407116900d47141fca8cbfd9a638af75a71310b08fe6351dd302b820c86b15e71ea73c78c876c1f88338a0").unwrap();

    let scalar = EccScalar::from_bytes_wide(EccCurveType::Ed25519, &wide_input)?;

    let mut bytes = scalar.serialize();
    bytes.reverse(); // Ed25519 uses little endian serialization

    assert_eq!(
        hex::encode(bytes),
        "0dbde3b1df91378aedecf61861150a7961b23ef8aa7650aaf27c44b73fbec2c2"
    );

    Ok(())
}

#[test]
fn scalar_deserializaion_errors_if_byte_length_invalid() {
    let rng = &mut reproducible_rng();
    for curve in EccCurveType::all() {
        let max_bytes: usize = curve.scalar_bytes() * 100;
        for num_bytes in 0..=max_bytes {
            if num_bytes == curve.scalar_bytes() {
                continue;
            }
            let mut bytes = vec![0u8; num_bytes];
            rng.fill_bytes(&mut bytes[..]);
            assert_eq!(
                EccScalar::deserialize(curve, &bytes[..]),
                Err(CanisterThresholdSerializationError(
                    "failed to deserialize EccScalar: unexpected length".to_string()
                ))
            );
        }
    }
}

#[test]
fn scalar_deserializaion_errors_is_over_the_order() {
    for curve in EccCurveType::all() {
        let bytes = vec![0xFFu8; curve.scalar_bytes()];
        assert_eq!(
            EccScalar::deserialize(curve, &bytes[..]),
            Err(CanisterThresholdSerializationError(
                "failed to deserialize EccScalar: invalid encoding".to_string()
            ))
        );
    }
}

#[test]
fn scalar_from_bytes_wide_errors_if_byte_length_invalid() {
    let rng = &mut reproducible_rng();
    for curve in EccCurveType::all() {
        let valid_num_bytes = curve.scalar_bytes() * 2;
        let min_bytes = valid_num_bytes + 1;
        let max_bytes: usize = curve.scalar_bytes() * 100;
        for num_bytes in min_bytes..=max_bytes {
            let mut bytes = vec![0u8; num_bytes];
            rng.fill_bytes(&mut bytes[..]);
            assert_eq!(
                EccScalar::from_bytes_wide(curve, &bytes[..]),
                Err(CanisterThresholdError::InvalidScalar)
            );
        }
    }
}

#[test]
fn point_deserialization_errors_if_byte_length_invalid() {
    let rng = &mut reproducible_rng();
    for curve in EccCurveType::all() {
        let max_bytes: usize = curve.point_bytes() * 100;
        for num_bytes in 0..=max_bytes {
            if num_bytes == curve.point_bytes() {
                continue;
            }
            let mut bytes = vec![0u8; num_bytes];
            rng.fill_bytes(&mut bytes[..]);
            assert_eq!(
                EccPoint::deserialize(curve, &bytes[..]),
                Err(CanisterThresholdError::InvalidPoint)
            );
        }
    }
}

#[test]
fn test_scalar_negate() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let zero = EccScalar::zero(curve);

        for _trial in 0..100 {
            let random = EccScalar::random(curve, rng);
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
fn test_point_mul_by_node_index() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();
    for curve in EccCurveType::all() {
        let g = EccPoint::generator_g(curve);

        let mut node_indices: Vec<_> = (0..300).collect();
        node_indices.push(u32::MAX - 1);
        node_indices.push(u32::MAX);
        for _ in 0..100 {
            node_indices.push(rng.r#gen());
        }

        for node_index in node_indices {
            let g_ni = g.mul_by_node_index_vartime(node_index)?;

            let scalar = EccScalar::from_node_index(curve, node_index);
            let g_s = g.scalar_mul(&scalar)?;

            assert_eq!(g_s, g_ni);
        }
    }

    Ok(())
}

#[test]
fn test_point_mul_naf() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();
    for curve_type in EccCurveType::all() {
        for window_size in [3, 4, 5, 6, 7] {
            // 0, 1, -1 (maximum value), 100 random values
            let mut scalars = Vec::with_capacity(103);
            scalars.push(EccScalar::zero(curve_type));
            scalars.push(EccScalar::one(curve_type));
            scalars.push(EccScalar::one(curve_type).negate());
            for _ in 0..100 {
                scalars.push(EccScalar::random(curve_type, rng));
            }

            // test correctness for the generated scalars
            for scalar in scalars {
                // random point
                let random_scalar = EccScalar::random(curve_type, rng);
                let mut random_point = EccPoint::mul_by_g(&random_scalar);
                let expected_point = random_point.scalar_mul(&scalar)?;
                assert!(!random_point.is_precomputed());
                random_point.precompute(window_size)?;
                assert!(random_point.is_precomputed());
                let computed_point = random_point.scalar_mul_vartime(&scalar)?;
                assert_eq!(computed_point, expected_point);
            }
        }
    }

    Ok(())
}

#[test]
fn test_point_negate() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let id = EccPoint::identity(curve_type);
        let g = EccPoint::generator_g(curve_type);

        assert_eq!(id.negate(), id);

        for _trial in 0..100 {
            let random_scalar = EccScalar::random(curve_type, rng);
            let random_point = g.scalar_mul(&random_scalar)?;
            let n_random_point = random_point.negate();

            let should_be_zero = random_point.add_points(&n_random_point)?;
            assert_eq!(should_be_zero, id);

            let should_be_zero = n_random_point.add_points(&random_point)?;
            assert_eq!(should_be_zero, id);
        }
    }
    Ok(())
}

#[test]
fn test_mul_by_g_is_correct() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let g = EccPoint::generator_g(curve_type);
        for small in 0..1024 {
            let s = EccScalar::from_u64(curve_type, small);
            assert_eq!(g.scalar_mul(&s)?, EccPoint::mul_by_g(&s));
        }

        for _iteration in 0..300 {
            let s = EccScalar::random(curve_type, rng);
            assert_eq!(g.scalar_mul(&s)?, EccPoint::mul_by_g(&s));
        }
    }
    Ok(())
}

#[test]
fn test_y_is_even() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        if curve_type == EccCurveType::Ed25519 {
            continue;
        }

        let g = EccPoint::generator_g(curve_type);

        for _trial in 0..100 {
            let s = EccScalar::random(curve_type, rng);
            let p = g.scalar_mul(&s)?;
            let np = p.negate();

            match (p.is_y_even()?, np.is_y_even()?) {
                (true, true) => panic!("Both point and its negation have even y"),
                (false, false) => panic!("Neither point nor its negation have even y"),
                (_, _) => {}
            }
        }
    }
    Ok(())
}

#[test]
fn test_mul_2_is_correct() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let g = EccPoint::generator_g(curve_type);

        for _iteration in 0..100 {
            let p_0 = g.scalar_mul(&EccScalar::random(curve_type, rng))?;
            let p_1 = g.scalar_mul(&EccScalar::random(curve_type, rng))?;

            let s_0 = EccScalar::random(curve_type, rng);
            let s_1 = EccScalar::random(curve_type, rng);

            let computed_result = EccPoint::mul_2_points(&p_0, &s_0, &p_1, &s_1)?;
            let expected_result = p_0.scalar_mul(&s_0)?.add_points(&p_1.scalar_mul(&s_1)?)?;
            assert_eq!(computed_result, expected_result);
        }
    }

    Ok(())
}

#[test]
fn test_pedersen_is_correct() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let g = EccPoint::generator_g(curve_type);
        let h = EccPoint::generator_h(curve_type);

        for _iteration in 0..100 {
            let x = EccScalar::random(curve_type, rng);
            let y = EccScalar::random(curve_type, rng);

            let computed_result = EccPoint::pedersen(&x, &y)?;
            let expected_result = g.scalar_mul(&x)?.add_points(&h.scalar_mul(&y)?)?;
            assert_eq!(computed_result, expected_result);
        }
    }

    Ok(())
}

#[test]
fn test_mul_n_ct_pippenger_is_correct() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();
    let mut random_point_and_scalar =
        |curve_type| -> CanisterThresholdResult<(EccPoint, EccScalar)> {
            let p = EccPoint::mul_by_g(&EccScalar::random(curve_type, rng));
            Ok((p, EccScalar::random(curve_type, rng)))
        };

    for curve_type in EccCurveType::all() {
        for num_terms in 2..20 {
            // generate point-scalar pairs
            let pairs: Vec<_> = (0..num_terms)
                .map(|_| random_point_and_scalar(curve_type))
                .collect::<Result<Vec<_>, _>>()?;

            // create "deep" refs of pairs
            let refs_of_pairs: Vec<(&EccPoint, &EccScalar)> =
                pairs.iter().map(|pair| (&pair.0, &pair.1)).collect();

            // compute the result using an optimized algorithm, which is to be tested
            let computed_result = EccPoint::mul_n_points_pippenger(&refs_of_pairs)?;

            let mul_and_aggregate =
                |acc: &EccPoint, p: EccPoint, s: EccScalar| -> CanisterThresholdResult<EccPoint> {
                    let mul = p.scalar_mul(&s)?;
                    acc.add_points(&mul)
                };
            // compute the result using a non-optimized algorithm, which is assumed to always be correct
            let expected_result =
                pairs
                    .into_iter()
                    .try_fold(EccPoint::identity(curve_type), |acc, pair| {
                        let (p, s) = pair;
                        // acc += p * s
                        mul_and_aggregate(&acc, p, s)
                    })?;
            assert_eq!(computed_result, expected_result);
        }
    }
    Ok(())
}

#[test]
fn test_mul_n_vartime_naf() -> CanisterThresholdResult<()> {
    assert_eq!(EccPoint::MIN_LUT_WINDOW_SIZE, 3);
    assert_eq!(EccPoint::MAX_LUT_WINDOW_SIZE, 7);

    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        for window_size in [3, 4, 5, 6, 7] {
            let g = EccPoint::generator_g(curve_type);
            let mut random_pair = || -> CanisterThresholdResult<_> {
                Ok((
                    g.scalar_mul(&EccScalar::random(curve_type, rng))?,
                    EccScalar::random(curve_type, rng),
                ))
            };

            for num_terms in [1, 2, 3, 4, 5, 10, 30, 50] {
                // generate point-scalar pairs
                let mut pairs: Vec<_> = (0..num_terms)
                    .map(|_| random_pair())
                    .collect::<Result<Vec<_>, _>>()?;

                // compute the result using a non-optimized algorithm, which is assumed to always be correct
                let expected_result =
                    pairs
                        .iter()
                        .try_fold(EccPoint::identity(curve_type), |acc, pair| {
                            let (p, s) = &pair;
                            // acc += p * s
                            acc.add_points(&p.scalar_mul(s)?)
                        })?;

                for (p, _s) in pairs.iter_mut() {
                    assert!(!p.is_precomputed());
                    p.precompute(window_size)?;
                    assert!(p.is_precomputed());
                }

                // create refs of pairs
                let refs_of_pairs: Vec<_> = pairs.iter().map(|(p, s)| (p, s)).collect();

                // compute the result using an optimized algorithm, which is to be tested
                let computed_result = EccPoint::mul_n_points_vartime(&refs_of_pairs[..])?;

                assert_eq!(computed_result, expected_result);
            }
        }
    }

    Ok(())
}

#[test]
fn test_scalar_inversion() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let zero = EccScalar::zero(curve);
        assert!(zero.invert().is_none());
        assert!(zero.invert_vartime().is_none());

        let hex_one = hex::encode(EccScalar::one(curve).serialize());

        for _trial in 0..1024 {
            let s = EccScalar::random(curve, rng);

            match (s.invert(), s.invert_vartime()) {
                (Some(si), Some(siv)) => {
                    assert_eq!(hex::encode(si.serialize()), hex::encode(siv.serialize()));
                    assert_eq!(hex::encode(s.mul(&si)?.serialize()), hex_one);
                }
                (None, None) => {
                    assert!(s.is_zero());
                }
                (Some(_), None) => panic!("Invert and invert vartime disagreed"),
                (None, Some(_)) => panic!("Invert and invert vartime disagreed"),
            }
        }

        for n in 0..64 {
            let scalars = (0..n)
                .map(|_i| EccScalar::random(curve, rng))
                .collect::<Vec<_>>();

            if let Ok(inverses) = EccScalar::batch_invert_vartime(&scalars) {
                assert_eq!(inverses.len(), scalars.len());

                for (s, i) in scalars.iter().zip(&inverses) {
                    assert_eq!(hex::encode(s.mul(i)?.serialize()), hex_one);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn test_scalarbytes_deserialization_with_old_cbor_format() {
    let old_ser = [
        (EccCurveType::K256, hex!("a1644b323536982018c8183c18431893183f188f188e182e1857181b18ab18ce041870187f183b1856185d1886187018d518ce182418421871184618ba187b186918ac09183d").to_vec()),
        (EccCurveType::P256, hex!("a1645032353698201830182a185d1018c018290a189e189b04183c1822185b061896182e187018af1887182f18d1182e183b189b18cb18441822187618b303185c186f").to_vec()),
        (EccCurveType::Ed25519, hex!("a16745643235353139982018a118a9187c11187818ed18df18cb182218ad184b18ce182b187f1878188618d9185d18d9186d11181f182b1892186018221882187a18a8186f0c0e").to_vec()),
    ];

    for (curve, bytes) in &old_ser {
        let sb: EccScalarBytes =
            serde_cbor::from_slice(&bytes).expect("Failed to deserialize CBOR encoding");

        assert_eq!(*curve, sb.curve_type());

        // Confirm that (for now) the default serialization is the old format for K256 and Ed25519
        if *curve == EccCurveType::K256 || *curve == EccCurveType::Ed25519 {
            assert_eq!(
                hex::encode(serde_cbor::to_vec(&sb).unwrap()),
                hex::encode(bytes)
            );
        }
    }
}

#[test]
fn test_scalarbytes_deserialization_compact_cbor_format() {
    let old_ser = [
        (EccCurveType::K256, hex!("a1644b3235365820b5ebe6143c8a7f7f459413a69c34ffce7227ea0e37f3524e67283b1e99fd8194").to_vec()),
        (EccCurveType::P256, hex!("a164503235365820eadb7e4360365ce1a417d9fdddda706296e367053e14136f57b4a69b00494c06").to_vec()),
        (EccCurveType::Ed25519, hex!("a1674564323535313958207f7096a7e536695c1ecce3d6b3ba75e81bd910a79cb2e33f1e60cc4df292e404").to_vec()),
    ];

    for (curve, bytes) in &old_ser {
        let sb: EccScalarBytes =
            serde_cbor::from_slice(&bytes).expect("Failed to deserialize CBOR encoding");

        assert_eq!(*curve, sb.curve_type());

        // Confirm that the new format is used for P256
        if *curve == EccCurveType::P256 {
            assert_eq!(
                hex::encode(serde_cbor::to_vec(&sb).unwrap()),
                hex::encode(bytes)
            );
        }
    }
}
