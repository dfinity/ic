use tecdsa::*;

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

    let ctext = mega_encrypt_single(
        seed,
        &[ptext_for_a, ptext_for_b],
        &[a_pk, b_pk],
        dealer_index,
        associated_data,
    )?;

    let ptext_a = mega_decrypt_single(&ctext, associated_data, dealer_index, 0, &a_sk, &a_pk)?;

    assert_eq!(
        hex::encode(ptext_a.serialize()),
        hex::encode(ptext_for_a.serialize())
    );

    let ptext_b = mega_decrypt_single(&ctext, associated_data, dealer_index, 1, &b_sk, &b_pk)?;

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

    let ctext = mega_encrypt_pair(
        seed,
        &[ptext_for_a, ptext_for_b],
        &[a_pk, b_pk],
        dealer_index,
        associated_data,
    )?;

    let ptext_a = mega_decrypt_pair(&ctext, associated_data, dealer_index, 0, &a_sk, &a_pk)?;
    assert_eq!(ptext_a, ptext_for_a);

    let ptext_b = mega_decrypt_pair(&ctext, associated_data, dealer_index, 1, &b_sk, &b_pk)?;
    assert_eq!(ptext_b, ptext_for_b);

    Ok(())
}
