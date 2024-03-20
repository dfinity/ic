use ic_crypto_internal_threshold_sig_ecdsa::*;

#[test]
fn test_random_oracle_stability() -> ThresholdEcdsaResult<()> {
    let curve_type = EccCurveType::K256;
    let seed = Seed::from_bytes(&[0x42; 32]);

    let rng = &mut seed.into_rng();

    let mut ro = RandomOracle::new("ic-test-domain-sep");

    let s1 = EccScalar::random(curve_type, rng);
    let pt1 = EccPoint::generator_g(curve_type).scalar_mul(&s1)?;
    ro.add_point("pt1", &pt1)?;
    assert!(ro.add_point("pt1", &pt1).is_err()); // duplicate name

    ro.add_u64("i1", 42)?;
    ro.add_bytestring("v1", &[42; 42])?;
    ro.add_scalar("s1", &s1)?;
    ro.add_u64("round", 1)?;

    let c1 = ro.output_scalars(curve_type, 2)?;

    assert_eq!(
        hex::encode(c1[0].serialize()),
        "e1cc3546518665d7321cd5b5aa7cbae2ae9d8bad3a2f28b495ac3d3af139b460"
    );
    assert_eq!(
        hex::encode(c1[1].serialize()),
        "d46b5ef6fafdaf2a1e50f7b979f1fd31e058e9c2ab69115c4f2c15077ae94969"
    );

    // Test random oracle chaining:
    let mut ro = RandomOracle::new("ic-test-domain-sep-2");

    ro.add_scalar("c1", &c1[1])?;
    ro.add_u64("round", 2)?;

    let c2 = ro.output_scalar(curve_type)?;

    assert_eq!(
        hex::encode(c2.serialize()),
        "f35e7f0a649f8c8e92084d04d40cd13cb82e9e2ebc3aabb5bd88c04ce2f5ebe9"
    );

    let mut ro = RandomOracle::new("ic-test-domain-sep-3");

    ro.add_scalar("c2", &c2)?;
    ro.add_u64("round", 3)?;

    let byte_output = ro.output_bytestring(42)?;

    assert_eq!(
        hex::encode(&byte_output),
        "c569bf3e900df5d5e61fdf3b9d798d3089bf9dfd875e8735cb99aef2e5a865f2eb44fb6f363730a4b2dc"
    );

    let mut ro = RandomOracle::new("ic-test-domain-sep-4");

    ro.add_bytestring("c3", &byte_output)?;
    ro.add_u64("round", 4)?;

    let pt = ro.output_point(EccCurveType::P256)?;

    assert_eq!(
        hex::encode(pt.serialize()),
        "020585e68447c2697248df1fbceceb56858c23ff982ee9dbcded85e92860dd618b"
    );

    Ok(())
}

#[test]
fn test_random_oracle_max_outputs() -> ThresholdEcdsaResult<()> {
    for curve_type in EccCurveType::all() {
        /*
        Our XMD hash_to_scalar construction consumes 256+128 bits per
        scalar. XMD with SHA-256 can produce at most 255*32 = 8160 bytes.
        Thus we can produce at most exactly 170 challenges (which ought to
        be enough for anyone!) - verify that we Err appropriately for
        larger requests.
         */

        for i in 1..170 {
            let mut ro = RandomOracle::new("ic-test-domain-sep");
            ro.add_usize("input", i)?;
            assert_eq!(ro.output_scalars(curve_type, i).unwrap().len(), i);
        }

        for i in 171..256 {
            let mut ro = RandomOracle::new("ic-test-domain-sep");
            ro.add_usize("input", i)?;
            assert!(ro.output_scalars(curve_type, i).is_err());
        }
    }

    Ok(())
}

#[test]
fn test_random_oracle_min_inputs() -> ThresholdEcdsaResult<()> {
    for curve_type in EccCurveType::all() {
        let ro = RandomOracle::new("ic-test-domain-sep");
        assert!(ro.output_scalar(curve_type).is_err());
    }

    Ok(())
}

#[test]
fn test_random_oracle_max_name_len() -> ThresholdEcdsaResult<()> {
    let mut ro = RandomOracle::new("ic-test-domain-sep");

    let name255 = "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY";
    let name256 = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";

    assert!(ro.add_usize(name255, 1).is_ok()); // allowed
    assert!(ro.add_usize(name256, 1).is_err()); // too long

    Ok(())
}

#[test]
fn test_random_oracle_dup_names_rejected() -> ThresholdEcdsaResult<()> {
    let mut ro = RandomOracle::new("ic-test-domain-sep");

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
    let mut ro = RandomOracle::new("ic-test-domain-sep");

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
    let mut ro = RandomOracle::new("ic-test-domain-sep");

    assert!(ro.add_usize("", 5).is_err());

    Ok(())
}
