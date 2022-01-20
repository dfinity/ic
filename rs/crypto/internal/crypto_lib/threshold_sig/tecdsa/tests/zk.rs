use rand::Rng;
use tecdsa::*;

#[test]
fn should_zk_equal_openings_proof_work() -> ThresholdEcdsaResult<()> {
    let curve = EccCurveType::K256;

    let mut rng = rand::thread_rng();
    let ad = rng.gen::<[u8; 32]>();

    let seed = Seed::from_bytes(&rng.gen::<[u8; 32]>());

    let secret = EccScalar::random(curve, &mut rng)?;
    let masking = EccScalar::random(curve, &mut rng)?;

    let pedersen = EccPoint::pedersen(&secret, &masking)?;
    let simple = EccPoint::mul_by_g(&secret)?;

    let proof = zk::ProofOfEqualOpenings::create(seed, &secret, &masking, &ad)?;

    assert!(proof.verify(&pedersen, &simple, &ad).is_ok());

    // basic test that obviously incorrect values are not accepted:
    assert!(proof.verify(&simple, &simple, &ad).is_err());
    assert!(proof.verify(&simple, &pedersen, &ad).is_err());
    assert!(proof.verify(&pedersen, &pedersen, &ad).is_err());

    Ok(())
}

#[test]
fn should_zk_mul_proof_work() -> ThresholdEcdsaResult<()> {
    let curve = EccCurveType::K256;

    let mut rng = rand::thread_rng();
    let ad = rng.gen::<[u8; 32]>();

    let seed = Seed::from_bytes(&rng.gen::<[u8; 32]>());

    let lhs = EccScalar::random(curve, &mut rng)?;
    let rhs = EccScalar::random(curve, &mut rng)?;
    let masking = EccScalar::random(curve, &mut rng)?;

    let product = lhs.mul(&rhs)?;
    let product_masking = EccScalar::random(curve, &mut rng)?;
    let product_c = EccPoint::pedersen(&product, &product_masking)?;

    let lhs_c = EccPoint::mul_by_g(&lhs)?;
    let rhs_c = EccPoint::pedersen(&rhs, &masking)?;

    let proof =
        zk::ProofOfProduct::create(seed, &lhs, &rhs, &masking, &product, &product_masking, &ad)?;

    assert!(proof.verify(&lhs_c, &rhs_c, &product_c, &ad).is_ok());

    // basic test that obviously incorrect values are not accepted:
    assert!(proof.verify(&rhs_c, &lhs_c, &product_c, &ad).is_err());
    assert!(proof.verify(&lhs_c, &rhs_c, &lhs_c, &ad).is_err());

    Ok(())
}

#[test]
fn should_invalid_zk_mul_proof_be_rejected() -> ThresholdEcdsaResult<()> {
    let curve = EccCurveType::K256;

    let mut rng = rand::thread_rng();
    let ad = rng.gen::<[u8; 32]>();

    let seed = Seed::from_bytes(&rng.gen::<[u8; 32]>());

    let lhs = EccScalar::random(curve, &mut rng)?;
    let rhs = EccScalar::random(curve, &mut rng)?;
    let masking = EccScalar::random(curve, &mut rng)?;

    let product = EccScalar::random(curve, &mut rng)?; // bad product!
    let product_masking = EccScalar::random(curve, &mut rng)?;
    let product_c = EccPoint::pedersen(&product, &product_masking)?;

    let lhs_c = EccPoint::mul_by_g(&lhs)?;
    let rhs_c = EccPoint::pedersen(&rhs, &masking)?;

    let proof =
        zk::ProofOfProduct::create(seed, &lhs, &rhs, &masking, &product, &product_masking, &ad)?;

    assert!(proof.verify(&lhs_c, &rhs_c, &product_c, &ad).is_err());

    Ok(())
}

#[test]
fn should_zk_dlog_eq_proof_work() -> ThresholdEcdsaResult<()> {
    let curve = EccCurveType::K256;

    let mut rng = rand::thread_rng();
    let ad = rng.gen::<[u8; 32]>();

    let seed = Seed::from_bytes(&rng.gen::<[u8; 32]>());

    let g = EccPoint::hash_to_point(curve, &rng.gen::<[u8; 32]>(), "g_domain".as_bytes())?;
    let h = EccPoint::hash_to_point(curve, &rng.gen::<[u8; 32]>(), "h_domain".as_bytes())?;

    let x = EccScalar::random(curve, &mut rng)?;
    let g_x = g.scalar_mul(&x)?;
    let h_x = h.scalar_mul(&x)?;

    let proof = zk::ProofOfDLogEquivalence::create(seed, &x, &g, &h, &ad)?;

    assert!(proof.verify(&g, &h, &g_x, &h_x, &ad).is_ok());
    assert!(proof.verify(&h, &g, &h_x, &g_x, &ad).is_err());
    assert!(proof.verify(&g, &h, &h_x, &g_x, &ad).is_err());

    Ok(())
}
