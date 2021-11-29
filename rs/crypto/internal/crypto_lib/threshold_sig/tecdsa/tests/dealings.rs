use ic_types::crypto::AlgorithmId;
use ic_types::*;
use rand::Rng;
use tecdsa::*;

fn gen_private_keys(
    curve: EccCurveType,
    cnt: usize,
) -> Result<(Vec<MEGaPrivateKey>, Vec<MEGaPublicKey>), ThresholdEcdsaError> {
    let mut rng = rand::thread_rng();
    let mut private_keys = Vec::with_capacity(cnt);

    for _i in 0..cnt {
        private_keys.push(MEGaPrivateKey::generate(curve, &mut rng)?);
    }

    let public_keys = private_keys
        .iter()
        .map(|k| k.public_key())
        .collect::<Result<Vec<_>, _>>()?;

    Ok((private_keys, public_keys))
}

#[test]
fn create_random_dealing() -> Result<(), IdkgCreateDealingInternalError> {
    let curve = EccCurveType::K256;
    let mut rng = rand::thread_rng();
    let associated_data = vec![1, 2, 3];
    let (private_keys, public_keys) = gen_private_keys(curve, 5)?;
    let threshold = 2;
    let dealer_index = 0;
    let randomness = Randomness::from(rng.gen::<[u8; 32]>());

    let shares = SecretShares::Random;

    let dealing = create_dealing(
        AlgorithmId::ThresholdEcdsaSecp256k1,
        &associated_data,
        dealer_index,
        NumberOfNodes::from(threshold as u32),
        &public_keys,
        &shares,
        randomness,
    )?;

    match dealing.commitment {
        PolynomialCommitment::Pedersen(c) => {
            assert_eq!(c.points.len(), threshold);
        }
        _ => panic!("Unexpected commitment type for random dealing"),
    }

    match dealing.ciphertext {
        MEGaCiphertext::Pairs(p) => {
            assert_eq!(p.ctexts.len(), private_keys.len())
        }
        _ => panic!("Unexpected ciphertext type for random dealing"),
    }

    assert!(dealing.proof.is_none()); // random dealings have no associated proof

    Ok(())
}

#[test]
fn create_reshare_unmasked_dealing() -> Result<(), IdkgCreateDealingInternalError> {
    let curve = EccCurveType::K256;
    let mut rng = rand::thread_rng();
    let associated_data = vec![1, 2, 3];
    let (private_keys, public_keys) = gen_private_keys(curve, 5)?;
    let threshold = 2;
    let dealer_index = 0;
    let randomness = Randomness::from(rng.gen::<[u8; 32]>());

    let secret = EccScalar::random(curve, &mut rng)?;
    let shares = SecretShares::ReshareOfUnmasked(secret);

    let dealing = create_dealing(
        AlgorithmId::ThresholdEcdsaSecp256k1,
        &associated_data,
        dealer_index,
        NumberOfNodes::from(threshold as u32),
        &public_keys,
        &shares,
        randomness,
    )?;

    match dealing.commitment {
        PolynomialCommitment::Simple(c) => {
            assert_eq!(c.points.len(), threshold);
        }
        _ => panic!("Unexpected commitment type for reshare unmasked dealing"),
    }

    match dealing.ciphertext {
        MEGaCiphertext::Single(p) => {
            assert_eq!(p.ctexts.len(), private_keys.len())
        }
        _ => panic!("Unexpected ciphertext type for reshare unmasked dealing"),
    }

    Ok(())
}

#[test]
fn create_reshare_masked_dealings() -> Result<(), IdkgCreateDealingInternalError> {
    let curve = EccCurveType::K256;
    let mut rng = rand::thread_rng();
    let associated_data = vec![1, 2, 3];
    let (private_keys, public_keys) = gen_private_keys(curve, 5)?;
    let threshold = 2;
    let dealer_index = 0;
    let randomness = Randomness::from(rng.gen::<[u8; 32]>());

    let secret = EccScalar::random(curve, &mut rng)?;
    let mask = EccScalar::random(curve, &mut rng)?;
    let shares = SecretShares::ReshareOfMasked(secret, mask);

    let dealing = create_dealing(
        AlgorithmId::ThresholdEcdsaSecp256k1,
        &associated_data,
        dealer_index,
        NumberOfNodes::from(threshold as u32),
        &public_keys,
        &shares,
        randomness,
    )?;

    match dealing.commitment {
        PolynomialCommitment::Simple(c) => {
            assert_eq!(c.points.len(), threshold);
        }
        _ => panic!("Unexpected commitment type for reshare masked dealing"),
    }

    match dealing.ciphertext {
        MEGaCiphertext::Single(p) => {
            assert_eq!(p.ctexts.len(), private_keys.len())
        }
        _ => panic!("Unexpected ciphertext type for reshare masked dealing"),
    }

    Ok(())
}

#[test]
fn create_mult_dealing() -> Result<(), IdkgCreateDealingInternalError> {
    let curve = EccCurveType::K256;
    let mut rng = rand::thread_rng();
    let associated_data = vec![1, 2, 3];
    let (private_keys, public_keys) = gen_private_keys(curve, 5)?;
    let threshold = 2;
    let dealer_index = 0;
    let randomness = Randomness::from(rng.gen::<[u8; 32]>());

    let lhs = EccScalar::random(curve, &mut rng)?;
    let rhs = EccScalar::random(curve, &mut rng)?;
    let mask = EccScalar::random(curve, &mut rng)?;
    let shares = SecretShares::UnmaskedTimesMasked(lhs, (rhs, mask));

    let dealing = create_dealing(
        AlgorithmId::ThresholdEcdsaSecp256k1,
        &associated_data,
        dealer_index,
        NumberOfNodes::from(threshold as u32),
        &public_keys,
        &shares,
        randomness,
    )?;

    match dealing.commitment {
        PolynomialCommitment::Pedersen(c) => {
            assert_eq!(c.points.len(), threshold);
        }
        _ => panic!("Unexpected commitment type for mult dealing"),
    }

    match dealing.ciphertext {
        MEGaCiphertext::Pairs(p) => {
            assert_eq!(p.ctexts.len(), private_keys.len())
        }
        _ => panic!("Unexpected ciphertext type for mult dealing"),
    }

    Ok(())
}

#[test]
fn invalid_create_dealing_requests() -> Result<(), IdkgCreateDealingInternalError> {
    let curve = EccCurveType::K256;
    let mut rng = rand::thread_rng();
    let associated_data = vec![1, 2, 3];
    let (private_keys, public_keys) = gen_private_keys(curve, 5)?;
    let threshold = 2;
    let dealer_index = 0;
    let randomness = Randomness::from(rng.gen::<[u8; 32]>());

    let shares = SecretShares::Random;

    // invalid threshold
    assert!(create_dealing(
        AlgorithmId::ThresholdEcdsaSecp256k1,
        &associated_data,
        dealer_index,
        NumberOfNodes::from(private_keys.len() as u32 + 1),
        &public_keys,
        &shares,
        randomness,
    )
    .is_err());

    let (_wrong_private_keys, wrong_public_keys) = gen_private_keys(EccCurveType::P256, 5)?;

    // bad public keys
    assert!(create_dealing(
        AlgorithmId::ThresholdEcdsaSecp256k1,
        &associated_data,
        dealer_index,
        NumberOfNodes::from(threshold),
        &wrong_public_keys,
        &shares,
        randomness,
    )
    .is_err());

    // wrong algorithm id
    assert!(create_dealing(
        AlgorithmId::Groth20_Bls12_381,
        &associated_data,
        dealer_index,
        NumberOfNodes::from(threshold),
        &public_keys,
        &shares,
        randomness,
    )
    .is_err());

    Ok(())
}
