use ic_crypto_internal_threshold_sig_canister_threshold_sig::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::NumberOfNodes;
use ic_types::crypto::AlgorithmId;
use rand::{CryptoRng, RngCore};
use strum::IntoEnumIterator;

fn alg_for_curve(curve: EccCurveType) -> AlgorithmId {
    match curve {
        EccCurveType::P256 => AlgorithmId::ThresholdEcdsaSecp256r1,
        EccCurveType::K256 => AlgorithmId::ThresholdEcdsaSecp256k1,
        EccCurveType::Ed25519 => AlgorithmId::ThresholdEd25519,
    }
}

fn wrong_curve(curve: EccCurveType) -> EccCurveType {
    match curve {
        EccCurveType::K256 => EccCurveType::P256,
        EccCurveType::P256 => EccCurveType::K256,
        EccCurveType::Ed25519 => EccCurveType::K256,
    }
}

fn gen_private_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
    curve: EccCurveType,
    cnt: usize,
) -> (Vec<MEGaPrivateKey>, Vec<MEGaPublicKey>) {
    let mut public_keys = Vec::with_capacity(cnt);
    let mut private_keys = Vec::with_capacity(cnt);

    for _i in 0..cnt {
        let sk = MEGaPrivateKey::generate(curve, rng);
        public_keys.push(sk.public_key());
        private_keys.push(sk);
    }

    (private_keys, public_keys)
}

#[test]
fn create_random_dealing() -> Result<(), IdkgCreateDealingInternalError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let associated_data = vec![1, 2, 3];
        let (private_keys, public_keys) = gen_private_keys(rng, curve, 5);
        let threshold = 2;
        let dealer_index = 0;

        let shares = SecretShares::Random;

        let dealing = create_dealing(
            alg_for_curve(curve),
            &associated_data,
            dealer_index,
            NumberOfNodes::from(threshold as u32),
            &public_keys,
            &shares,
            Seed::from_rng(rng),
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
    }

    Ok(())
}

#[test]
fn create_random_unmasked_dealing() -> Result<(), IdkgCreateDealingInternalError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let associated_data = vec![1, 2, 3];
        let (private_keys, public_keys) = gen_private_keys(rng, curve, 5);
        let threshold = 2;
        let dealer_index = 0;

        let shares = SecretShares::RandomUnmasked;

        let dealing = create_dealing(
            alg_for_curve(curve),
            &associated_data,
            dealer_index,
            NumberOfNodes::from(threshold as u32),
            &public_keys,
            &shares,
            Seed::from_rng(rng),
        )?;

        match dealing.commitment {
            PolynomialCommitment::Simple(c) => {
                assert_eq!(c.points.len(), threshold);
            }
            _ => panic!("Unexpected commitment type for random unmasked dealing"),
        }

        match dealing.ciphertext {
            MEGaCiphertext::Single(p) => {
                assert_eq!(p.ctexts.len(), private_keys.len())
            }
            _ => panic!("Unexpected ciphertext type for random unmasked dealing"),
        }

        assert!(dealing.proof.is_none()); // random dealings have no associated proof
    }

    Ok(())
}

#[test]
fn create_reshare_unmasked_dealing() -> Result<(), IdkgCreateDealingInternalError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let associated_data = vec![1, 2, 3];
        let (private_keys, public_keys) = gen_private_keys(rng, curve, 5);
        let threshold = 2;
        let dealer_index = 0;

        let secret = EccScalar::random(curve, rng);
        let shares = SecretShares::ReshareOfUnmasked(secret);

        let dealing = create_dealing(
            alg_for_curve(curve),
            &associated_data,
            dealer_index,
            NumberOfNodes::from(threshold as u32),
            &public_keys,
            &shares,
            Seed::from_rng(rng),
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
    }

    Ok(())
}

#[test]
fn create_reshare_masked_dealings() -> Result<(), IdkgCreateDealingInternalError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let associated_data = vec![1, 2, 3];
        let (private_keys, public_keys) = gen_private_keys(rng, curve, 5);
        let threshold = 2;
        let dealer_index = 0;

        let secret = EccScalar::random(curve, rng);
        let mask = EccScalar::random(curve, rng);
        let shares = SecretShares::ReshareOfMasked(secret, mask);

        let dealing = create_dealing(
            alg_for_curve(curve),
            &associated_data,
            dealer_index,
            NumberOfNodes::from(threshold as u32),
            &public_keys,
            &shares,
            Seed::from_rng(rng),
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
    }

    Ok(())
}

#[test]
fn create_mult_dealing() -> Result<(), IdkgCreateDealingInternalError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let associated_data = vec![1, 2, 3];
        let (private_keys, public_keys) = gen_private_keys(rng, curve, 5);
        let threshold = 2;
        let dealer_index = 0;

        let lhs = EccScalar::random(curve, rng);
        let rhs = EccScalar::random(curve, rng);
        let mask = EccScalar::random(curve, rng);
        let shares = SecretShares::UnmaskedTimesMasked(lhs, (rhs, mask));

        let dealing = create_dealing(
            alg_for_curve(curve),
            &associated_data,
            dealer_index,
            NumberOfNodes::from(threshold as u32),
            &public_keys,
            &shares,
            Seed::from_rng(rng),
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
    }

    Ok(())
}

#[test]
fn invalid_create_dealing_requests() -> Result<(), IdkgCreateDealingInternalError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let associated_data = vec![1, 2, 3];
        let (private_keys, public_keys) = gen_private_keys(rng, curve, 5);
        let threshold = 2;
        let dealer_index = 0;

        let shares = SecretShares::Random;

        // invalid threshold
        assert!(
            create_dealing(
                alg_for_curve(curve),
                &associated_data,
                dealer_index,
                NumberOfNodes::from(private_keys.len() as u32 + 1),
                &public_keys,
                &shares,
                Seed::from_rng(rng),
            )
            .is_err()
        );

        // wrong algorithm id
        assert!(
            create_dealing(
                AlgorithmId::Groth20_Bls12_381,
                &associated_data,
                dealer_index,
                NumberOfNodes::from(threshold),
                &public_keys,
                &shares,
                Seed::from_rng(rng),
            )
            .is_err()
        );
    }

    Ok(())
}

#[test]
fn secret_shares_should_redact_logs() -> Result<(), CanisterThresholdError> {
    let curve = EccCurveType::K256;
    let rng = &mut reproducible_rng();

    {
        let shares = SecretShares::Random;
        let log = format!("{shares:?}");
        assert_eq!("SecretShares::Random", log);
    }

    {
        let shares = SecretShares::RandomUnmasked;
        let log = format!("{shares:?}");
        assert_eq!("SecretShares::RandomUnmasked", log);
    }

    {
        let secret = EccScalar::random(curve, rng);
        let shares = SecretShares::ReshareOfUnmasked(secret);
        let log = format!("{shares:?}");
        assert_eq!("SecretShares::ReshareOfUnmasked(K256) - REDACTED", log);
    }

    {
        let secret = EccScalar::random(curve, rng);
        let mask = EccScalar::random(curve, rng);
        let shares = SecretShares::ReshareOfMasked(secret, mask);
        let log = format!("{shares:?}");
        assert_eq!("SecretShares::ReshareOfMasked(K256) - REDACTED", log);
    }

    {
        let lhs = EccScalar::random(curve, rng);
        let rhs = EccScalar::random(curve, rng);
        let mask = EccScalar::random(curve, rng);
        let shares = SecretShares::UnmaskedTimesMasked(lhs, (rhs, mask));
        let log = format!("{shares:?}");
        assert_eq!("SecretShares::UnmaskedTimesMasked(K256) - REDACTED", log);
    }

    Ok(())
}

fn flip_curve(s: &EccScalar) -> EccScalar {
    let wrong_curve = wrong_curve(s.curve_type());

    let s_bytes = s.serialize();

    // Since ord(k256) > ord(p256) we might have to reduce in that case
    EccScalar::from_bytes_wide(wrong_curve, &s_bytes).expect("Deserialization failed")
}

#[test]
fn wrong_curve_reshare_of_unmasked_rejected() -> Result<(), CanisterThresholdError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let associated_data = vec![1, 2, 3];
        let (_private_keys, public_keys) = gen_private_keys(rng, curve, 5);
        let threshold = 3;

        let secret = EccScalar::random(curve, rng);
        let shares = SecretShares::ReshareOfUnmasked(flip_curve(&secret));

        let dealing = create_dealing(
            alg_for_curve(curve),
            &associated_data,
            0,
            NumberOfNodes::from(threshold as u32),
            &public_keys,
            &shares,
            Seed::from_rng(rng),
        );

        assert_eq!(
            dealing.unwrap_err(),
            IdkgCreateDealingInternalError::InvalidSecretShare
        );
    }

    Ok(())
}

#[test]
fn wrong_curve_reshare_of_masked_rejected() -> Result<(), CanisterThresholdError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let associated_data = vec![1, 2, 3];
        let (_private_keys, public_keys) = gen_private_keys(rng, curve, 5);
        let threshold = 3;

        let secret = EccScalar::random(curve, rng);
        let mask = EccScalar::random(curve, rng);
        let shares = SecretShares::ReshareOfMasked(flip_curve(&secret), mask);

        let dealing = create_dealing(
            alg_for_curve(curve),
            &associated_data,
            0,
            NumberOfNodes::from(threshold as u32),
            &public_keys,
            &shares,
            Seed::from_rng(rng),
        );

        assert_eq!(
            dealing.unwrap_err(),
            IdkgCreateDealingInternalError::InvalidSecretShare
        );
    }

    Ok(())
}

#[test]
fn wrong_curve_mul_share_rejected() -> Result<(), CanisterThresholdError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let associated_data = vec![1, 2, 3];
        let (_private_keys, public_keys) = gen_private_keys(rng, curve, 5);
        let threshold = 3;

        let lhs = EccScalar::random(curve, rng);
        let rhs = EccScalar::random(curve, rng);
        let mask = EccScalar::random(curve, rng);

        let shares =
            SecretShares::UnmaskedTimesMasked(flip_curve(&lhs), (rhs.clone(), mask.clone()));

        let dealing = create_dealing(
            alg_for_curve(curve),
            &associated_data,
            0,
            NumberOfNodes::from(threshold as u32),
            &public_keys,
            &shares,
            Seed::from_rng(rng),
        );

        assert_eq!(
            dealing.unwrap_err(),
            IdkgCreateDealingInternalError::InvalidSecretShare
        );

        let shares = SecretShares::UnmaskedTimesMasked(lhs, (flip_curve(&rhs), mask));

        let dealing = create_dealing(
            alg_for_curve(curve),
            &associated_data,
            0,
            NumberOfNodes::from(threshold as u32),
            &public_keys,
            &shares,
            Seed::from_rng(rng),
        );

        assert_eq!(
            dealing.unwrap_err(),
            IdkgCreateDealingInternalError::InvalidSecretShare
        );
    }

    Ok(())
}

mod privately_verify {
    use super::*;

    #[test]
    fn should_fail_on_private_key_curve_mismatch() {
        let rng = &mut reproducible_rng();

        for alg in IdkgProtocolAlgorithm::iter() {
            let curve_type = alg.curve();
            let setup = Setup::new(curve_type, rng);
            let private_key = MEGaPrivateKey::generate(wrong_curve(curve_type), rng);

            assert_eq!(
                setup.dealing_internal.privately_verify(
                    curve_type,
                    alg,
                    &private_key,
                    &setup.public_key,
                    &setup.associated_data,
                    setup.dealer_index,
                    0
                ),
                Err(CanisterThresholdError::CurveMismatch)
            );
        }
    }

    #[test]
    fn should_fail_on_public_key_curve_mismatch() {
        let rng = &mut reproducible_rng();

        for alg in IdkgProtocolAlgorithm::iter() {
            let curve_type = alg.curve();
            let setup = Setup::new(curve_type, rng);
            let private_key = MEGaPrivateKey::generate(wrong_curve(curve_type), rng);
            let public_key = private_key.public_key();

            assert_eq!(
                setup.dealing_internal.privately_verify(
                    curve_type,
                    alg,
                    &setup.private_key,
                    &public_key,
                    &setup.associated_data,
                    setup.dealer_index,
                    0
                ),
                Err(CanisterThresholdError::CurveMismatch)
            );
        }
    }

    #[test]
    fn should_fail_on_commitment_constant_curve_type_mismatch() {
        let rng = &mut reproducible_rng();

        for alg in IdkgProtocolAlgorithm::iter() {
            let curve_type = alg.curve();
            let setup = Setup::new(curve_type, rng);
            let private_key = MEGaPrivateKey::generate(wrong_curve(curve_type), rng);
            let public_key = private_key.public_key();

            assert_eq!(
                setup.dealing_internal.privately_verify(
                    wrong_curve(curve_type),
                    alg,
                    &private_key,
                    &public_key,
                    &setup.associated_data,
                    setup.dealer_index,
                    0
                ),
                Err(CanisterThresholdError::CurveMismatch)
            );
        }
    }

    #[test]
    fn should_fail_if_decryption_and_check_of_internal_ciphertext_fails() {
        let rng = &mut reproducible_rng();

        for alg in IdkgProtocolAlgorithm::iter() {
            let curve_type = alg.curve();
            let setup = Setup::new(curve_type, rng);
            let another_setup = Setup::new(curve_type, rng);

            assert_eq!(
                another_setup.dealing_internal.privately_verify(
                    curve_type,
                    alg,
                    &setup.private_key,
                    &setup.public_key,
                    &setup.associated_data,
                    setup.dealer_index,
                    0
                ),
                Err(CanisterThresholdError::InvalidCommitment)
            );
        }
    }
}

mod privately_verify_dealing {
    use super::*;
    use ic_crypto_internal_threshold_sig_canister_threshold_sig::privately_verify_dealing;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_types::crypto::AlgorithmId;
    use strum::IntoEnumIterator;

    #[test]
    fn should_fail_for_unsupported_algorithms() {
        let rng = &mut reproducible_rng();

        for curve_type in EccCurveType::all() {
            let setup = Setup::new(curve_type, rng);
            for algorithm_id in AlgorithmId::iter() {
                if IdkgProtocolAlgorithm::from_algorithm(algorithm_id).is_none() {
                    assert_eq!(
                        privately_verify_dealing(
                            algorithm_id,
                            &setup.dealing_internal,
                            &setup.private_key,
                            &setup.public_key,
                            &setup.associated_data,
                            setup.dealer_index,
                            0
                        ),
                        Err(IDkgVerifyDealingInternalError::UnsupportedAlgorithm)
                    );
                }
            }
        }
    }
}

struct Setup {
    pub dealing_internal: IDkgDealingInternal,
    pub private_key: MEGaPrivateKey,
    pub public_key: MEGaPublicKey,
    pub associated_data: Vec<u8>,
    pub dealer_index: NodeIndex,
}

impl Setup {
    fn new<R: RngCore + CryptoRng>(curve: EccCurveType, rng: &mut R) -> Self {
        let associated_data = vec![1, 2, 3];
        let (private_keys, public_keys) = gen_private_keys(rng, curve, 5);
        let threshold = 2;
        let dealer_index = 0;
        let shares = SecretShares::Random;

        let algorithm_id = alg_for_curve(curve);

        let dealing_internal = create_dealing(
            algorithm_id,
            &associated_data,
            dealer_index,
            NumberOfNodes::from(threshold as u32),
            &public_keys,
            &shares,
            Seed::from_rng(rng),
        )
        .expect("should create dealing from input");

        Self {
            dealing_internal,
            private_key: private_keys
                .first()
                .expect("should have at least one private key")
                .clone(),
            public_key: public_keys
                .first()
                .expect("should have at least one public key")
                .clone(),
            associated_data,
            dealer_index,
        }
    }
}
