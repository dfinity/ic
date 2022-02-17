use ic_crypto_internal_threshold_sig_ecdsa::*;
use std::convert::TryFrom;

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
