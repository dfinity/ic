use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;
use strum::IntoEnumIterator;

#[test]
fn should_zk_equal_openings_proof_work() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for alg in IdkgProtocolAlgorithm::iter() {
        let curve = alg.curve();
        let ad = rng.gen::<[u8; 32]>();

        let seed = Seed::from_rng(rng);

        let secret = EccScalar::random(curve, rng);
        let masking = EccScalar::random(curve, rng);

        let pedersen = EccPoint::pedersen(&secret, &masking)?;
        let simple = EccPoint::mul_by_g(&secret);

        let proof = zk::ProofOfEqualOpenings::create(seed, alg, &secret, &masking, &ad)?;

        assert!(proof.verify(alg, &pedersen, &simple, &ad).is_ok());

        // basic test that obviously incorrect values are not accepted:
        assert!(proof.verify(alg, &simple, &simple, &ad).is_err());
        assert!(proof.verify(alg, &simple, &pedersen, &ad).is_err());
        assert!(proof.verify(alg, &pedersen, &pedersen, &ad).is_err());
    }

    Ok(())
}

#[test]
fn should_zk_mul_proof_work() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for alg in IdkgProtocolAlgorithm::iter() {
        let curve = alg.curve();
        let ad = rng.gen::<[u8; 32]>();

        let seed = Seed::from_rng(rng);

        let lhs = EccScalar::random(curve, rng);
        let rhs = EccScalar::random(curve, rng);
        let masking = EccScalar::random(curve, rng);

        let product = lhs.mul(&rhs)?;
        let product_masking = EccScalar::random(curve, rng);
        let product_c = EccPoint::pedersen(&product, &product_masking)?;

        let lhs_c = EccPoint::mul_by_g(&lhs);
        let rhs_c = EccPoint::pedersen(&rhs, &masking)?;

        let proof = zk::ProofOfProduct::create(
            seed,
            alg,
            &lhs,
            &rhs,
            &masking,
            &product,
            &product_masking,
            &ad,
        )?;

        assert!(proof.verify(alg, &lhs_c, &rhs_c, &product_c, &ad).is_ok());

        // basic test that obviously incorrect values are not accepted:
        assert!(proof.verify(alg, &rhs_c, &lhs_c, &product_c, &ad).is_err());
        assert!(proof.verify(alg, &lhs_c, &rhs_c, &lhs_c, &ad).is_err());
    }

    Ok(())
}

#[test]
fn should_invalid_zk_mul_proof_be_rejected() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for alg in IdkgProtocolAlgorithm::iter() {
        let curve = alg.curve();
        let ad = rng.gen::<[u8; 32]>();

        let seed = Seed::from_rng(rng);

        let lhs = EccScalar::random(curve, rng);
        let rhs = EccScalar::random(curve, rng);
        let masking = EccScalar::random(curve, rng);

        let product = EccScalar::random(curve, rng); // bad product!
        let product_masking = EccScalar::random(curve, rng);
        let product_c = EccPoint::pedersen(&product, &product_masking)?;

        let lhs_c = EccPoint::mul_by_g(&lhs);
        let rhs_c = EccPoint::pedersen(&rhs, &masking)?;

        let proof = zk::ProofOfProduct::create(
            seed,
            alg,
            &lhs,
            &rhs,
            &masking,
            &product,
            &product_masking,
            &ad,
        )?;

        assert!(proof.verify(alg, &lhs_c, &rhs_c, &product_c, &ad).is_err());
    }

    Ok(())
}

#[test]
fn should_zk_dlog_eq_proof_work() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for alg in IdkgProtocolAlgorithm::iter() {
        let curve = alg.curve();
        let ad = rng.gen::<[u8; 32]>();

        let seed = Seed::from_rng(rng);

        let g = EccPoint::hash_to_point(curve, &rng.gen::<[u8; 32]>(), "g_domain".as_bytes())?;
        let h = EccPoint::hash_to_point(curve, &rng.gen::<[u8; 32]>(), "h_domain".as_bytes())?;

        let x = EccScalar::random(curve, rng);
        let g_x = g.scalar_mul(&x)?;
        let h_x = h.scalar_mul(&x)?;

        let proof = zk::ProofOfDLogEquivalence::create(seed, alg, &x, &g, &h, &ad)?;

        assert!(proof.verify(alg, &g, &h, &g_x, &h_x, &ad).is_ok());
        assert!(proof.verify(alg, &h, &g, &h_x, &g_x, &ad).is_err());
        assert!(proof.verify(alg, &g, &h, &h_x, &g_x, &ad).is_err());
    }

    Ok(())
}
