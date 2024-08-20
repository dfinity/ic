use assert_matches::assert_matches;
use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::Randomness;
use rand::{Rng, RngCore};
use std::collections::BTreeMap;

use ic_crypto_internal_threshold_sig_ecdsa_test_utils::*;

fn insufficient_dealings(r: Result<ProtocolRound, CanisterThresholdError>) {
    match r {
        Err(CanisterThresholdError::InsufficientDealings) => {}
        Err(e) => panic!("Unexpected error {:?}", e),
        Ok(r) => panic!("Unexpected success {:?}", r),
    }
}

#[test]
fn should_reshare_masked_random_transcripts_correctly() -> Result<(), CanisterThresholdError> {
    let mut rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(&mut rng);
        let setup = ProtocolSetup::new(cfg, 4, 2, random_seed)?;

        let no_corruption = 0; // number of corrupted dealings == 0
        let corrupted_dealings = 1;

        // First create a transcript of random dealings
        let random = ProtocolRound::random(&setup, 4, corrupted_dealings)?;

        // Now reshare the random value twice

        // 1 dealing is not sufficient
        insufficient_dealings(ProtocolRound::reshare_of_masked(
            &setup,
            &random,
            1,
            no_corruption,
        ));

        // 2, 3, or 4 works:
        let reshared2 = ProtocolRound::reshare_of_masked(&setup, &random, 2, corrupted_dealings)?;
        let reshared3 = ProtocolRound::reshare_of_masked(&setup, &random, 3, corrupted_dealings)?;
        let reshared4 = ProtocolRound::reshare_of_masked(&setup, &random, 4, corrupted_dealings)?;

        // The same value is committed in the resharings despite different dealing cnt
        assert_eq!(reshared2.constant_term(), reshared3.constant_term());
        assert_eq!(reshared2.constant_term(), reshared4.constant_term());

        // Now reshare the now-unmasked value
        insufficient_dealings(ProtocolRound::reshare_of_unmasked(
            &setup,
            &reshared2,
            1,
            no_corruption,
        ));
        let unmasked =
            ProtocolRound::reshare_of_unmasked(&setup, &reshared2, 2, corrupted_dealings)?;
        assert_eq!(reshared2.constant_term(), unmasked.constant_term());

        // Now multiply the masked and umasked values
        // We need 3 dealings to multiply
        insufficient_dealings(ProtocolRound::multiply(
            &setup,
            &random,
            &unmasked,
            1,
            no_corruption,
        ));
        insufficient_dealings(ProtocolRound::multiply(
            &setup,
            &random,
            &unmasked,
            2,
            no_corruption,
        ));
        let _product = ProtocolRound::multiply(&setup, &random, &unmasked, 3, corrupted_dealings)?;
    }

    Ok(())
}

#[test]
fn should_reshare_unmasked_random_transcripts_correctly() -> Result<(), CanisterThresholdError> {
    let mut rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(&mut rng);
        let setup = ProtocolSetup::new(cfg, 4, 2, random_seed)?;

        let no_corruption = 0; // number of corrupted dealings == 0
        let corrupted_dealings = 1;

        let random = ProtocolRound::random_unmasked(&setup, 4, corrupted_dealings)?;

        // 1 dealing is not sufficient
        insufficient_dealings(ProtocolRound::reshare_of_unmasked(
            &setup,
            &random,
            1,
            no_corruption,
        ));

        // 2, 3, or 4 works:
        let reshared2 = ProtocolRound::reshare_of_unmasked(&setup, &random, 2, corrupted_dealings)?;
        let reshared3 = ProtocolRound::reshare_of_unmasked(&setup, &random, 3, corrupted_dealings)?;
        let reshared4 = ProtocolRound::reshare_of_unmasked(&setup, &random, 4, corrupted_dealings)?;

        // The same value is committed in the resharings despite different dealing cnt
        assert_eq!(random.constant_term(), reshared2.constant_term());
        assert_eq!(random.constant_term(), reshared3.constant_term());
        assert_eq!(random.constant_term(), reshared4.constant_term());
    }

    Ok(())
}

#[test]
fn should_multiply_transcripts_correctly() -> Result<(), CanisterThresholdError> {
    let mut rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(&mut rng);
        let setup = ProtocolSetup::new(cfg, 4, 2, random_seed)?;

        let dealers = 4;
        let corrupted_dealings = 1;

        // First create two random transcripts
        let random_a = ProtocolRound::random(&setup, dealers, corrupted_dealings)?;
        let random_b = ProtocolRound::random(&setup, dealers, corrupted_dealings)?;

        // Now reshare them both
        let random_c =
            ProtocolRound::reshare_of_masked(&setup, &random_a, dealers, corrupted_dealings)?;
        let random_d =
            ProtocolRound::reshare_of_masked(&setup, &random_b, dealers, corrupted_dealings)?;

        // Now multiply A*D and B*C (which will be the same numbers)
        let product_ad =
            ProtocolRound::multiply(&setup, &random_a, &random_d, dealers, corrupted_dealings)?;
        let product_bc =
            ProtocolRound::multiply(&setup, &random_b, &random_c, dealers, corrupted_dealings)?;

        // Now reshare AD and BC
        let reshare_ad =
            ProtocolRound::reshare_of_masked(&setup, &product_ad, dealers, corrupted_dealings)?;
        let reshare_bc =
            ProtocolRound::reshare_of_masked(&setup, &product_bc, dealers, corrupted_dealings)?;

        // The committed values of AD and BC should be the same:
        assert_eq!(reshare_ad.constant_term(), reshare_bc.constant_term());
    }

    Ok(())
}

#[test]
fn should_multiply_unmasked_random_transcripts_correctly() -> Result<(), CanisterThresholdError> {
    let mut rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(&mut rng);
        let setup = ProtocolSetup::new(cfg, 4, 2, random_seed)?;

        let dealers = 4;
        let corrupted_dealings = 1;

        let a = ProtocolRound::random_unmasked(&setup, dealers, corrupted_dealings)?;

        // same value!
        let b = ProtocolRound::reshare_of_unmasked(&setup, &a, dealers, corrupted_dealings)?;

        let c = ProtocolRound::random(&setup, dealers, corrupted_dealings)?;

        let ac = ProtocolRound::multiply(&setup, &c, &a, dealers, corrupted_dealings)?;
        let bc = ProtocolRound::multiply(&setup, &c, &b, dealers, corrupted_dealings)?;

        let reshare_ac =
            ProtocolRound::reshare_of_masked(&setup, &ac, dealers, corrupted_dealings)?;
        let reshare_bc =
            ProtocolRound::reshare_of_masked(&setup, &bc, dealers, corrupted_dealings)?;

        assert_eq!(reshare_ac.constant_term(), reshare_bc.constant_term());
    }

    Ok(())
}

#[test]
fn should_reshare_transcripts_with_dynamic_threshold() -> Result<(), CanisterThresholdError> {
    let mut rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(&mut rng);
        let mut setup = ProtocolSetup::new(cfg, 5, 2, random_seed)?;

        let no_corruption = 0; // number of corrupted dealings == 0
        let corrupted_dealings = 1;

        let random_a = ProtocolRound::random(&setup, 5, corrupted_dealings)?;

        insufficient_dealings(ProtocolRound::reshare_of_masked(
            &setup,
            &random_a,
            1,
            no_corruption,
        ));
        let reshared_b =
            ProtocolRound::reshare_of_masked(&setup, &random_a, 2, corrupted_dealings)?;

        setup.modify_threshold(1);
        setup.remove_nodes(2);
        insufficient_dealings(ProtocolRound::reshare_of_unmasked(
            &setup,
            &reshared_b,
            1,
            no_corruption,
        ));

        let reshared_c =
            ProtocolRound::reshare_of_unmasked(&setup, &reshared_b, 2, corrupted_dealings)?;
        let reshared_d =
            ProtocolRound::reshare_of_unmasked(&setup, &reshared_b, 3, corrupted_dealings)?;

        // b, c, and d all have the same value
        assert_eq!(reshared_b.constant_term(), reshared_c.constant_term());
        assert_eq!(reshared_b.constant_term(), reshared_d.constant_term());
    }

    Ok(())
}

#[test]
fn should_multiply_transcripts_with_dynamic_threshold() -> Result<(), CanisterThresholdError> {
    let mut rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(&mut rng);
        let mut setup = ProtocolSetup::new(cfg, 5, 2, random_seed)?;

        let corrupted_dealings = 1;

        let random_a = ProtocolRound::random(&setup, 5, corrupted_dealings)?;
        let random_b = ProtocolRound::random(&setup, 5, corrupted_dealings)?;

        let reshared_c =
            ProtocolRound::reshare_of_masked(&setup, &random_a, 3, corrupted_dealings)?;

        setup.modify_threshold(1);
        setup.remove_nodes(2);
        insufficient_dealings(ProtocolRound::multiply(
            &setup,
            &random_b,
            &reshared_c,
            1,
            0,
        ));
        insufficient_dealings(ProtocolRound::multiply(
            &setup,
            &random_b,
            &reshared_c,
            2,
            0,
        ));

        let _product =
            ProtocolRound::multiply(&setup, &random_b, &reshared_c, 3, corrupted_dealings)?;
    }

    Ok(())
}

fn random_subset<R: rand::Rng, T: Clone>(
    shares: &BTreeMap<NodeIndex, T>,
    include: usize,
    rng: &mut R,
) -> BTreeMap<NodeIndex, T> {
    assert!(include <= shares.len());

    let mut result = BTreeMap::new();

    let keys = shares.keys().collect::<Vec<_>>();

    while result.len() != include {
        let key_to_add = keys[rng.gen::<usize>() % keys.len()];

        if !result.contains_key(key_to_add) {
            result.insert(*key_to_add, shares[key_to_add].clone());
        }
    }

    result
}

#[test]
fn should_basic_signing_protocol_work() -> Result<(), CanisterThresholdError> {
    fn test_sig_serialization(
        alg: ic_types::crypto::AlgorithmId,
        sig: &ThresholdEcdsaCombinedSigInternal,
    ) -> Result<(), CanisterThresholdError> {
        let bytes = sig.serialize();
        let sig2 = ThresholdEcdsaCombinedSigInternal::deserialize(alg, &bytes)
            .expect("Deserialization failed");
        assert_eq!(*sig, sig2);
        Ok(())
    }

    let nodes = 10;
    let threshold = nodes / 3;
    let number_of_dealings_corrupted = threshold;

    let rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(rng);

        let setup = EcdsaSignatureProtocolSetup::new(
            cfg,
            nodes,
            threshold,
            number_of_dealings_corrupted,
            random_seed,
        )?;

        let alg = setup.alg();

        let signed_message = rng.gen::<[u8; 32]>().to_vec();
        let random_beacon = Randomness::from(rng.gen::<[u8; 32]>());

        let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
        let proto = EcdsaSignatureProtocolExecution::new(
            setup.clone(),
            signed_message.clone(),
            random_beacon,
            derivation_path.clone(),
        );

        let shares = proto.generate_shares()?;

        for i in 0..=nodes {
            let shares = random_subset(&shares, i, rng);

            if shares.len() < threshold {
                assert!(proto.generate_signature(&shares).is_err());
            } else {
                let sig = proto.generate_signature(&shares).unwrap();
                test_sig_serialization(alg, &sig)?;
                assert!(proto.verify_signature(&sig).is_ok());
            }
        }

        // Test that another run of the protocol generates signatures
        // which are not verifiable in the earlier one (due to different rho)
        let random_beacon2 = Randomness::from(rng.gen::<[u8; 32]>());
        let proto2 = EcdsaSignatureProtocolExecution::new(
            setup,
            signed_message,
            random_beacon2,
            derivation_path,
        );

        let shares = proto2.generate_shares()?;
        let sig = proto2.generate_signature(&shares).unwrap();
        test_sig_serialization(alg, &sig)?;

        assert!(proto.verify_signature(&sig).is_err());
        assert!(proto2.verify_signature(&sig).is_ok());
    }

    Ok(())
}

#[test]
fn should_be_able_to_perform_bip340_signature() -> Result<(), CanisterThresholdError> {
    let mut rng = &mut reproducible_rng();

    let nodes = 13;
    let corrupted_dealings = 1;
    let threshold = (nodes - 1) / 3;

    let msg_lens = [0, 1, 32, rng.gen_range(0..2_000_000)];
    for msg_len in msg_lens {
        let mut signed_message = vec![0; msg_len];
        rng.fill_bytes(&mut signed_message);

        let random_beacon = Randomness::from(rng.gen::<[u8; 32]>());

        let random_seed = Seed::from_rng(&mut rng);

        let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);

        let cfg = TestConfig::new(IdkgProtocolAlgorithm::Bip340, EccCurveType::K256);

        let setup = SchnorrSignatureProtocolSetup::new(
            cfg,
            nodes,
            threshold,
            corrupted_dealings,
            random_seed,
        )?;

        let proto = Bip340SignatureProtocolExecution::new(
            setup,
            signed_message,
            random_beacon,
            derivation_path,
        );

        let shares = proto.generate_shares()?;
        assert_eq!(shares.len(), nodes);

        let sig_all_shares = proto.generate_signature(&shares).unwrap();
        assert_eq!(proto.verify_signature(&sig_all_shares), Ok(()));

        for cnt in 0..(nodes - 1) {
            let expect_fail = cnt < threshold;

            let share_subset = random_subset(&shares, cnt, &mut rng);
            let sig = proto.generate_signature(&share_subset);

            if expect_fail {
                assert_eq!(
                    sig.unwrap_err(),
                    ThresholdBip340CombineSigSharesInternalError::InsufficientShares
                );
            } else {
                assert_eq!(sig.unwrap().serialize(), sig_all_shares.serialize());
            }
        }
    }
    Ok(())
}

#[test]
fn should_be_able_to_perform_ed25519_signature() -> Result<(), CanisterThresholdError> {
    let mut rng = &mut reproducible_rng();

    let nodes = 4;
    let corrupted_dealings = 0;
    let threshold = (nodes - 1) / 3;

    let signed_message = rng.gen::<[u8; 32]>().to_vec();
    let random_beacon = Randomness::from(rng.gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);

    let random_seed = Seed::from_rng(&mut rng);

    // Ed25519 signatures using secp256k1 MEGa keys
    let cfg = TestConfig::new(IdkgProtocolAlgorithm::Ed25519, EccCurveType::K256);

    let setup =
        SchnorrSignatureProtocolSetup::new(cfg, nodes, threshold, corrupted_dealings, random_seed)?;

    let proto = Ed25519SignatureProtocolExecution::new(
        setup,
        signed_message,
        random_beacon,
        derivation_path,
    );

    println!("creating shares");
    let shares = proto.generate_shares()?;
    assert_eq!(shares.len(), nodes);

    let sig_all_shares = proto.generate_signature(&shares).unwrap();
    assert_eq!(proto.verify_signature(&sig_all_shares), Ok(()));

    for cnt in 0..(nodes - 1) {
        let expect_fail = cnt < threshold;

        let share_subset = random_subset(&shares, cnt, &mut rng);
        let sig = proto.generate_signature(&share_subset);

        if expect_fail {
            assert!(sig.is_err());
        } else {
            assert_eq!(sig.unwrap().serialize(), sig_all_shares.serialize());
        }
    }

    Ok(())
}

#[test]
fn invalid_signatures_are_rejected() -> Result<(), CanisterThresholdError> {
    let nodes = 13;
    let threshold = (nodes + 2) / 3;
    let number_of_dealings_corrupted = 0;

    let rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(rng);

        let setup = EcdsaSignatureProtocolSetup::new(
            cfg,
            nodes,
            threshold,
            number_of_dealings_corrupted,
            random_seed,
        )?;

        let alg = setup.alg();

        let signed_message = rng.gen::<[u8; 32]>().to_vec();
        let random_beacon = Randomness::from(rng.gen::<[u8; 32]>());

        let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
        let proto = EcdsaSignatureProtocolExecution::new(
            setup,
            signed_message,
            random_beacon,
            derivation_path,
        );

        let shares = proto.generate_shares()?;

        let sig = proto.generate_signature(&shares).unwrap();

        assert_eq!(proto.verify_signature(&sig), Ok(()));

        let sig = sig.serialize();

        assert_eq!(sig.len() % 2, 0);

        let half_sig = sig.len() / 2;

        let sig_with_r_eq_zero = {
            let mut sig_with_r_eq_zero = sig.clone();
            sig_with_r_eq_zero[..half_sig].fill(0);
            ThresholdEcdsaCombinedSigInternal::deserialize(alg, &sig_with_r_eq_zero).unwrap()
        };

        assert!(proto.verify_signature(&sig_with_r_eq_zero).is_err());

        let sig_with_s_eq_zero = {
            let mut sig_with_s_eq_zero = sig.clone();
            sig_with_s_eq_zero[half_sig..].fill(0);
            ThresholdEcdsaCombinedSigInternal::deserialize(alg, &sig_with_s_eq_zero).unwrap()
        };

        assert!(proto.verify_signature(&sig_with_s_eq_zero).is_err());

        let sig_with_high_s = {
            let s = EccScalar::deserialize(cfg.signature_alg().curve(), &sig[half_sig..])
                .unwrap()
                .negate();

            let mut sig_with_high_s = sig;
            sig_with_high_s[half_sig..].copy_from_slice(&s.serialize());
            ThresholdEcdsaCombinedSigInternal::deserialize(alg, &sig_with_high_s).unwrap()
        };

        assert!(proto.verify_signature(&sig_with_high_s).is_err());
    }

    Ok(())
}

#[test]
fn should_fail_on_hashed_message_length_mismatch() {
    let nodes = 3;
    let threshold = nodes / 3;
    let number_of_dealings_corrupted = 0;

    let rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let setup = EcdsaSignatureProtocolSetup::new(
            cfg,
            nodes,
            threshold,
            number_of_dealings_corrupted,
            Seed::from_rng(rng),
        )
        .expect("failed to create setup");

        let alg = setup.alg();
        let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
        let random_beacon = Randomness::from(rng.gen::<[u8; 32]>());

        let message_with_wrong_length = vec![0; cfg.signature_alg().curve().scalar_bytes() + 1];

        let sign_share_result_with_wrong_msg_length = create_ecdsa_signature_share(
            &derivation_path,
            &message_with_wrong_length,
            random_beacon,
            &setup.key.transcript,
            &setup.kappa.transcript,
            &setup.lambda.openings[0],
            &setup.kappa_times_lambda.openings[0],
            &setup.key_times_lambda.openings[0],
            alg,
        );
        assert_matches!(sign_share_result_with_wrong_msg_length, Err(ThresholdEcdsaGenerateSigShareInternalError::InvalidArguments(e))
            if e.contains("length of hashed_message") && e.contains("not matching expected length")
        );

        let signed_message = rng.gen::<[u8; 32]>().to_vec();

        let proto = EcdsaSignatureProtocolExecution::new(
            setup.clone(),
            signed_message.clone(),
            random_beacon,
            derivation_path.clone(),
        );
        let shares = proto.generate_shares().expect("failed to generate shares");
        for (&node_index, share) in &shares {
            let verify_share_result_with_wrong_msg_length = verify_ecdsa_signature_share(
                share,
                &derivation_path,
                &message_with_wrong_length,
                random_beacon,
                node_index,
                &setup.key.transcript,
                &setup.kappa.transcript,
                &setup.lambda.transcript,
                &setup.kappa_times_lambda.transcript,
                &setup.key_times_lambda.transcript,
                alg,
            );
            assert_matches!(verify_share_result_with_wrong_msg_length, Err(ThresholdEcdsaVerifySigShareInternalError::InvalidArguments(e))
                if e.contains("length of hashed_message") && e.contains("not matching expected length")
            );
        }

        let sig = proto
            .generate_signature(&shares)
            .expect("failed to generate signature");
        let verify_sig_result_with_wrong_msg_length = verify_ecdsa_threshold_signature(
            &sig,
            &derivation_path,
            &message_with_wrong_length,
            random_beacon,
            &setup.kappa.transcript,
            &setup.key.transcript,
            alg,
        );
        assert_matches!(verify_sig_result_with_wrong_msg_length, Err(ThresholdEcdsaVerifySignatureInternalError::InvalidArguments(e))
            if e.contains("length of hashed_message") && e.contains("not matching expected length")
        );
    }
}
