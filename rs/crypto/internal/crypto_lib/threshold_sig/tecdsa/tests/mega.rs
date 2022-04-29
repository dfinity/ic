use ic_crypto_internal_threshold_sig_ecdsa::*;
use std::convert::TryFrom;

#[test]
fn mega_key_generation() -> ThresholdEcdsaResult<()> {
    let randomness = ic_types::Randomness::from([0x42; 32]);

    let (pk_k256, sk_k256) = gen_keypair(EccCurveType::K256, randomness)?;

    assert_eq!(pk_k256.curve_type(), EccCurveType::K256);
    assert_eq!(sk_k256.curve_type(), EccCurveType::K256);

    assert_eq!(
        hex::encode(sk_k256.serialize()),
        "a4ddf31f7f32ba696f14ce50ecf3f21e3e100e83bdf47966e7b07468e9500b6e"
    );
    assert_eq!(
        hex::encode(pk_k256.serialize()),
        "034f6340cfdd930a6f54e730188e3071d150877fa664945fb6f120c18b56ce1c09"
    );

    let (pk_p256, sk_p256) = gen_keypair(EccCurveType::P256, randomness)?;

    assert_eq!(pk_p256.curve_type(), EccCurveType::P256);
    assert_eq!(sk_p256.curve_type(), EccCurveType::P256);

    assert_eq!(
        hex::encode(sk_p256.serialize()),
        "a4ddf31f7f32ba696f14ce50ecf3f21e3e100e83bdf47966e7b07468e9500b6e"
    );
    assert_eq!(
        hex::encode(pk_p256.serialize()),
        "0300f4b1cc1352d482d56da7e6604d7bfc7a83f591761843456726b93d9d5e1b35"
    );

    Ok(())
}

#[test]
fn mega_key_validity() -> ThresholdEcdsaResult<()> {
    let mut rng = rand::thread_rng();

    for curve_type in EccCurveType::all() {
        let sk = MEGaPrivateKey::generate(curve_type, &mut rng)?;
        let pk = sk.public_key()?;

        let mut pk_bytes = pk.serialize();

        assert!(verify_mega_public_key(curve_type, &pk_bytes).is_ok());

        // In compressed format flipping this bit is equivalant to
        // flipping the sign of y, which is equivalent to negating the
        // point.  In all cases if pk_bytes is a valid encoding, this
        // modification is also
        pk_bytes[0] ^= 1;
        assert!(verify_mega_public_key(curve_type, &pk_bytes).is_ok());

        // Invalid header:
        pk_bytes[0] ^= 2;
        assert!(verify_mega_public_key(curve_type, &pk_bytes).is_err());

        // This x is too large to be a field element (except for P-521)
        let mut max_x = vec![0xFF; curve_type.point_bytes()];
        max_x[0] = 2;
        assert!(verify_mega_public_key(curve_type, &max_x).is_err());
    }
    Ok(())
}

#[test]
fn mega_single_smoke_test() -> Result<(), ThresholdEcdsaError> {
    let curve = EccCurveType::K256;

    let mut rng = Seed::from_bytes(&[42; 32]).into_rng();

    let a_sk = MEGaPrivateKey::generate(curve, &mut rng)?;
    let b_sk = MEGaPrivateKey::generate(curve, &mut rng)?;

    let a_pk = a_sk.public_key()?;
    let b_pk = b_sk.public_key()?;

    let associated_data = b"assoc_data_test";

    let ptext_for_a = EccScalar::random(curve, &mut rng)?;
    let ptext_for_b = EccScalar::random(curve, &mut rng)?;

    let dealer_index = 0;

    let seed = Seed::from_rng(&mut rng);

    let ctext = MEGaCiphertextSingle::encrypt(
        seed,
        &[ptext_for_a, ptext_for_b],
        &[a_pk, b_pk],
        dealer_index,
        associated_data,
    )?;

    let ptext_a = ctext.decrypt(associated_data, dealer_index, 0, &a_sk, &a_pk)?;

    assert_eq!(
        hex::encode(ptext_a.serialize()),
        hex::encode(ptext_for_a.serialize())
    );

    let ptext_b = ctext.decrypt(associated_data, dealer_index, 1, &b_sk, &b_pk)?;

    assert_eq!(
        hex::encode(ptext_b.serialize()),
        hex::encode(ptext_for_b.serialize())
    );

    Ok(())
}

#[test]
fn mega_pair_smoke_test() -> Result<(), ThresholdEcdsaError> {
    let curve = EccCurveType::K256;

    let mut rng = Seed::from_bytes(&[43; 32]).into_rng();

    let a_sk = MEGaPrivateKey::generate(curve, &mut rng)?;
    let b_sk = MEGaPrivateKey::generate(curve, &mut rng)?;

    let a_pk = a_sk.public_key()?;
    let b_pk = b_sk.public_key()?;

    let associated_data = b"assoc_data_test";

    let ptext_for_a = (
        EccScalar::random(curve, &mut rng)?,
        EccScalar::random(curve, &mut rng)?,
    );
    let ptext_for_b = (
        EccScalar::random(curve, &mut rng)?,
        EccScalar::random(curve, &mut rng)?,
    );

    let seed = Seed::from_rng(&mut rng);

    let dealer_index = 0;

    let ctext = MEGaCiphertextPair::encrypt(
        seed,
        &[ptext_for_a, ptext_for_b],
        &[a_pk, b_pk],
        dealer_index,
        associated_data,
    )?;

    let ptext_a = ctext.decrypt(associated_data, dealer_index, 0, &a_sk, &a_pk)?;
    assert_eq!(ptext_a, ptext_for_a);

    let ptext_b = ctext.decrypt(associated_data, dealer_index, 1, &b_sk, &b_pk)?;
    assert_eq!(ptext_b, ptext_for_b);

    Ok(())
}

#[test]
fn mega_private_key_should_redact_logs() -> Result<(), ThresholdEcdsaError> {
    let curve = EccCurveType::K256;

    let mut rng = Seed::from_bytes(&[43; 32]).into_rng();

    let sk = MEGaPrivateKey::generate(curve, &mut rng)?;

    let log = format!("{:?}", sk);
    assert_eq!("MEGaPrivateKey(EccScalar::K256) - REDACTED", log);

    Ok(())
}

#[test]
fn mega_private_key_bytes_should_redact_logs() -> Result<(), ThresholdEcdsaError> {
    let curve = EccCurveType::K256;

    let mut rng = Seed::from_bytes(&[43; 32]).into_rng();

    let sk = MEGaPrivateKey::generate(curve, &mut rng)?;

    let bytes = MEGaPrivateKeyK256Bytes::try_from(&sk)?;

    let log = format!("{:?}", bytes);
    assert_eq!("MEGaPrivateKeyK256Bytes - REDACTED", log);

    Ok(())
}
