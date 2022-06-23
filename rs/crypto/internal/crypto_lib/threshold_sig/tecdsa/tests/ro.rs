use ic_crypto_internal_threshold_sig_ecdsa::*;

#[test]
fn test_random_oracle_stability() -> ThresholdEcdsaResult<()> {
    let curve_type = EccCurveType::K256;
    let seed = Seed::from_bytes(&[0x42; 32]);

    let mut rng = seed.into_rng();

    let mut ro = ro::RandomOracle::new("ic-test-domain-sep");

    let s1 = EccScalar::random(curve_type, &mut rng)?;
    let pt1 = EccPoint::generator_g(curve_type)?.scalar_mul(&s1)?;
    ro.add_point("pt1", &pt1)?;
    assert!(ro.add_point("pt1", &pt1).is_err()); // duplicate name

    ro.add_u64("i1", 42)?;
    ro.add_bytestring("v1", &[42; 42])?;
    ro.add_scalar("s1", &s1)?;
    ro.add_u64("round", 1)?;

    let c1 = ro.output_scalars(curve_type, 2)?;

    assert_eq!(
        hex::encode(c1[0].serialize()),
        "a4d99e60e6985076b4f9a7e0042ec4cb279135d128d431b5618005755ecb6611"
    );
    assert_eq!(
        hex::encode(c1[1].serialize()),
        "9175435e81a33b3e5f585bfb509a2f3292e92edf522fa2015ba0de165b499335"
    );

    // Test random oracle chaining:
    let mut ro = ro::RandomOracle::new("ic-test-domain-sep-2");

    ro.add_scalar("c1", &c1[1])?;
    ro.add_u64("round", 2)?;

    let c2 = ro.output_scalar(curve_type)?;

    assert_eq!(
        hex::encode(c2.serialize()),
        "7b032238061db2dd2de9346713c6d141ee0eb2c979e29dfe8f6c23f7f685ab52"
    );

    let mut ro = ro::RandomOracle::new("ic-test-domain-sep-3");

    ro.add_scalar("c2", &c2)?;
    ro.add_u64("round", 3)?;

    let byte_output = ro.output_bytestring(42)?;

    assert_eq!(
        hex::encode(&byte_output),
        "ee5a02cb81b9146b403a7f8b8b3f0f44c7dbf602c3070691f882562888646290d9f88a6e7d36af0e6ed0"
    );

    let mut ro = ro::RandomOracle::new("ic-test-domain-sep-4");

    ro.add_bytestring("c3", &byte_output)?;
    ro.add_u64("round", 4)?;

    let pt = ro.output_point(EccCurveType::P256)?;

    assert_eq!(
        hex::encode(pt.serialize()),
        "0377a23b74bdce383717d39f52a7e806193102f842a62afa6a0ccc6ef21206838f"
    );

    Ok(())
}

#[test]
fn test_random_oracle_max_outputs() -> ThresholdEcdsaResult<()> {
    let curve_type = EccCurveType::K256;

    /*
    Our XMD hash_to_scalar construction consumes 256+128 bits per
    scalar. XMD with SHA-256 can produce at most 255*32 = 8160 bytes.
    Thus we can produce at most exactly 170 challenges (which ought to
    be enough for anyone!) - verify that we Err appropriately for
    larger requests.
    */

    for i in 1..170 {
        let mut ro = ro::RandomOracle::new("ic-test-domain-sep");
        ro.add_usize("input", i)?;
        assert_eq!(ro.output_scalars(curve_type, i).unwrap().len(), i);
    }

    for i in 171..256 {
        let mut ro = ro::RandomOracle::new("ic-test-domain-sep");
        ro.add_usize("input", i)?;
        assert!(ro.output_scalars(curve_type, i).is_err());
    }

    Ok(())
}

#[test]
fn test_random_oracle_min_inputs() -> ThresholdEcdsaResult<()> {
    let curve_type = EccCurveType::K256;
    let ro = ro::RandomOracle::new("ic-test-domain-sep");
    assert!(ro.output_scalar(curve_type).is_err());
    Ok(())
}

#[test]
fn test_random_oracle_max_name_len() -> ThresholdEcdsaResult<()> {
    let mut ro = ro::RandomOracle::new("ic-test-domain-sep");

    let name255 = "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY";
    let name256 = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";

    assert!(ro.add_usize(name255, 1).is_ok()); // allowed
    assert!(ro.add_usize(name256, 1).is_err()); // too long

    Ok(())
}

#[test]
fn test_random_oracle_dup_names_rejected() -> ThresholdEcdsaResult<()> {
    let mut ro = ro::RandomOracle::new("ic-test-domain-sep");

    assert!(ro.add_usize("a", 1).is_ok());
    assert!(ro.add_usize("b", 1).is_ok());
    assert!(ro.add_usize("c", 1).is_ok());

    // no duplicates are allowed, even if the same value/type:
    assert!(ro.add_usize("a", 1).is_err());
    assert!(ro.add_usize("b", 1).is_err());
    assert!(ro.add_usize("c", 1).is_err());

    assert!(ro.add_usize("a", 2).is_err());
    assert!(ro.add_usize("b", 2).is_err());
    assert!(ro.add_usize("c", 2).is_err());

    // no duplicates are allowed even across types:
    assert!(ro.add_bytestring("a", &[1]).is_err());
    assert!(ro.add_bytestring("b", &[1]).is_err());
    assert!(ro.add_bytestring("c", &[1]).is_err());

    Ok(())
}

#[test]
fn test_random_oracle_allows_duplicated_inputs() -> ThresholdEcdsaResult<()> {
    let mut ro = ro::RandomOracle::new("ic-test-domain-sep");

    let pt = EccPoint::hash_to_point(EccCurveType::K256, "input".as_bytes(), "dst".as_bytes())?;

    assert!(ro.add_point("a", &pt).is_ok());
    assert!(ro.add_point("b", &pt).is_ok());
    assert!(ro.add_point("c", &pt).is_ok());

    let int = 5;

    assert!(ro.add_usize("d", int).is_ok());
    assert!(ro.add_usize("e", int).is_ok());
    assert!(ro.add_usize("f", int).is_ok());

    let v = vec![1, 2, 3, 4, 5];

    assert!(ro.add_bytestring("x", &v).is_ok());
    assert!(ro.add_bytestring("y", &v).is_ok());
    assert!(ro.add_bytestring("z", &v).is_ok());

    Ok(())
}

#[test]
fn test_random_oracle_empty_name_rejected() -> ThresholdEcdsaResult<()> {
    let mut ro = ro::RandomOracle::new("ic-test-domain-sep");

    assert!(ro.add_usize("", 5).is_err());

    Ok(())
}
