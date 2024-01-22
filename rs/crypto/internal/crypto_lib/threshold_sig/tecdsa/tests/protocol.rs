use assert_matches::assert_matches;
use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::*;
use rand::Rng;
use std::collections::BTreeMap;

mod test_utils;

use crate::test_utils::*;

fn insufficient_dealings(r: Result<ProtocolRound, ThresholdEcdsaError>) {
    match r {
        Err(ThresholdEcdsaError::InsufficientDealings) => {}
        Err(e) => panic!("Unexpected error {:?}", e),
        Ok(r) => panic!("Unexpected success {:?}", r),
    }
}

#[test]
fn should_reshare_masked_random_transcripts_correctly() -> Result<(), ThresholdEcdsaError> {
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
fn should_reshare_unmasked_random_transcripts_correctly() -> Result<(), ThresholdEcdsaError> {
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
fn should_multiply_transcripts_correctly() -> Result<(), ThresholdEcdsaError> {
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
fn should_multiply_unmasked_random_transcripts_correctly() -> Result<(), ThresholdEcdsaError> {
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
fn should_be_able_to_perform_schnorr_signature() -> Result<(), ThresholdEcdsaError> {
    /*
    This test demonstrates how a Schnorr signature protocol that produces signatures
    in the style of BIP340 would run using the IDKG.
    */

    let mut rng = &mut reproducible_rng();

    fn hash(r: &EccPoint, key: &EccPoint, msg: &[u8]) -> ThresholdEcdsaResult<EccScalar> {
        let mut hash = ic_crypto_sha2::Sha256::new();

        let curve = key.curve_type();

        hash.write(&r.serialize());
        hash.write(&key.serialize());
        hash.write(msg);

        let rhash = hash.finish();

        EccScalar::from_bytes_wide(curve, &rhash)
    }

    fn verify_schnorr(
        sig_s: &EccScalar,
        sig_r: &EccPoint,
        msg: &[u8],
        pk: &EccPoint,
    ) -> ThresholdEcdsaResult<bool> {
        // The signature satisfies s⋅G = R + H(r || pk || m)⋅P.

        let lhs = EccPoint::mul_by_g(sig_s);
        let h = hash(sig_r, pk, msg)?;
        let hp = pk.scalar_mul(&h)?;
        let rhs = sig_r.add_points(&hp)?;
        Ok(lhs == rhs)
    }

    fn fix_to_even_y(pt: &EccPoint) -> ThresholdEcdsaResult<(EccPoint, bool)> {
        if pt.is_y_even()? {
            Ok((pt.clone(), false))
        } else {
            Ok((pt.negate(), true))
        }
    }

    for cfg in TestConfig::all() {
        let receivers = 13;
        let dealers = 9;
        let corrupted_dealings = 1;
        let threshold = receivers / 3;

        let msg = rng.gen::<[u8; 32]>();

        let random_seed = Seed::from_rng(&mut rng);
        let setup = ProtocolSetup::new(cfg, receivers, threshold, random_seed)?;

        /*
         * Create a long term key using random + reshare_of_masked
         */
        let key_masked = ProtocolRound::random(&setup, dealers, corrupted_dealings)?;

        let key =
            ProtocolRound::reshare_of_masked(&setup, &key_masked, dealers, corrupted_dealings)?;

        /*
         * Create shares of a random value r using random_unmasked
         */
        let r = ProtocolRound::random_unmasked(&setup, dealers, corrupted_dealings)?;

        /*
         * Derive a subkey from the master key
         *
         * (In practice we would use BIP32 here, instead of our internal RO)
         */
        // derive a subkey from the IDKG master key
        let mut tweak_ro = ro::RandomOracle::new("ic-test-schnorr-key-tweak");
        tweak_ro.add_point("transcript_k", &key.constant_term())?;
        tweak_ro.add_bytestring("derivation_path", &[1, 2, 3, 4])?;
        let key_tweak = tweak_ro.output_scalar(cfg.signature_curve())?;

        /*
         * Correct the public key to have even y, and record if we needed to
         * negate the point or not
         */
        let (public_key, negate_sk) = fix_to_even_y(
            &key.constant_term()
                .add_points(&EccPoint::mul_by_g(&key_tweak))?,
        )?;

        /*
         * Use a random oracle to derive a rerandomizer value for r
         *
         * The actual signature is created using r+v where r was created using
         * the IDKG and v was the output of a random oracle whose inputs include
         * the public key, the message, and the block state.
         */
        let mut rerandomizer_ro = ro::RandomOracle::new("ic-test-schnorr-r-rerandomizer");
        rerandomizer_ro.add_point("public_key", &public_key)?;
        rerandomizer_ro.add_point("transcript_r", &r.constant_term())?;
        rerandomizer_ro.add_bytestring("randomness", &rng.gen::<[u8; 32]>())?;
        rerandomizer_ro.add_bytestring("msg", &msg)?;
        let rerandomizer = rerandomizer_ro.output_scalar(cfg.signature_curve())?;

        let rerandomized_r = r
            .constant_term()
            .add_points(&EccPoint::mul_by_g(&rerandomizer))?;

        /*
         * Correct the R point to have even y, and record if we needed to
         * negate the point or not
         */
        let (sig_r, negate_r) = fix_to_even_y(&rerandomized_r)?;

        /*
         * Hash the message using the rerandomized r and the derived public key.
         */
        let h = hash(&sig_r, &public_key, &msg)?;

        let mut node_indices = vec![];
        let mut sig_shares = vec![];

        /*
         * Each node takes as inputs its opening associated with the r and key
         * transcripts, and uses it to create a signature share.
         */
        for node_index in 0..receivers {
            // [s] = [r] + h * [x]
            let r = match r.openings.get(node_index) {
                None => panic!("Couldn't find opening"),
                Some(CommitmentOpening::Simple(s)) => s,
                Some(CommitmentOpening::Pedersen(_, _)) => panic!("Unexpected commitment"),
            };

            let x = match key.openings.get(node_index) {
                None => panic!("Couldn't find opening"),
                Some(CommitmentOpening::Simple(s)) => s,
                Some(CommitmentOpening::Pedersen(_, _)) => panic!("Unexpected commitment"),
            };

            let tweaked_x = x.add(&key_tweak)?;

            /*
             * The linear combination used to create the share varies based on
             * if we had to negate pk and/or r
             */

            let xh = if negate_sk {
                tweaked_x.negate().mul(&h)?
            } else {
                tweaked_x.mul(&h)?
            };

            let r_plus_randomizer = r.add(&rerandomizer)?;

            let share = if negate_r {
                xh.sub(&r_plus_randomizer)?
            } else {
                xh.add(&r_plus_randomizer)?
            };

            node_indices.push(node_index as u32);
            sig_shares.push(share);
        }

        /*
         * Each node would validate the signature shares, which are themselves
         * zero knowledge proofs.
         */
        for (index, share) in node_indices.iter().zip(&sig_shares) {
            let node_pk = key
                .commitment
                .evaluate_at(*index)?
                .add_points(&EccPoint::mul_by_g(&key_tweak))?;
            let node_r = r
                .commitment
                .evaluate_at(*index)?
                .add_points(&EccPoint::mul_by_g(&rerandomizer))?;

            let fixed_pk = if negate_sk { node_pk.negate() } else { node_pk };
            let fixed_r = if negate_r { node_r.negate() } else { node_r };

            let lhs = EccPoint::mul_by_g(share);
            let hp = fixed_pk.scalar_mul(&h)?;
            let rhs = fixed_r.add_points(&hp)?;

            assert_eq!(lhs, rhs, "signature share validates");
        }

        /*
         * Verify that our y-correction worked as we expected
         */
        assert!(sig_r.is_y_even()?);
        assert!(public_key.is_y_even()?);

        /*
         * Combine the signature shares using interpolation to derive s
         */
        let interp = LagrangeCoefficients::at_zero(cfg.signature_curve(), &node_indices)?;
        let sig_s = interp.interpolate_scalar(&sig_shares)?;

        /*
         * Verify the combined signature
         */
        assert_eq!(
            verify_schnorr(&sig_s, &sig_r, &msg, &public_key),
            Ok(true),
            "signature is accepted"
        );
    }

    Ok(())
}

#[test]
fn should_reshare_transcripts_with_dynamic_threshold() -> Result<(), ThresholdEcdsaError> {
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
fn should_multiply_transcripts_with_dynamic_threshold() -> Result<(), ThresholdEcdsaError> {
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

fn random_subset<R: rand::Rng>(
    shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
    include: usize,
    rng: &mut R,
) -> BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal> {
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
fn should_basic_signing_protocol_work() -> Result<(), ThresholdEcdsaError> {
    fn test_sig_serialization(
        alg: ic_types::crypto::AlgorithmId,
        sig: &ThresholdEcdsaCombinedSigInternal,
    ) -> Result<(), ThresholdEcdsaError> {
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
        for use_masked_kappa in [true, false] {
            let random_seed = Seed::from_rng(rng);

            let setup = SignatureProtocolSetup::new(
                cfg,
                nodes,
                threshold,
                number_of_dealings_corrupted,
                random_seed,
                use_masked_kappa,
            )?;

            let alg = setup.alg();

            let signed_message = rng.gen::<[u8; 32]>().to_vec();
            let random_beacon = Randomness::from(rng.gen::<[u8; 32]>());

            let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
            let proto = SignatureProtocolExecution::new(
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
            let proto2 = SignatureProtocolExecution::new(
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
    }

    Ok(())
}

#[test]
fn invalid_signatures_are_rejected() -> Result<(), ThresholdEcdsaError> {
    let nodes = 13;
    let threshold = (nodes + 2) / 3;
    let number_of_dealings_corrupted = 0;

    let rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(rng);

        let setup = SignatureProtocolSetup::new(
            cfg,
            nodes,
            threshold,
            number_of_dealings_corrupted,
            random_seed,
            true,
        )?;

        let alg = setup.alg();

        let signed_message = rng.gen::<[u8; 32]>().to_vec();
        let random_beacon = Randomness::from(rng.gen::<[u8; 32]>());

        let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
        let proto =
            SignatureProtocolExecution::new(setup, signed_message, random_beacon, derivation_path);

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
            let s = EccScalar::deserialize(cfg.signature_curve(), &sig[half_sig..])
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
        let setup = SignatureProtocolSetup::new(
            cfg,
            nodes,
            threshold,
            number_of_dealings_corrupted,
            Seed::from_rng(rng),
            true,
        )
        .expect("failed to create setup");

        let alg = setup.alg();
        let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
        let random_beacon = Randomness::from(rng.gen::<[u8; 32]>());

        let message_with_wrong_length = vec![0; cfg.signature_curve().scalar_bytes() + 1];

        let sign_share_result_with_wrong_msg_length = sign_share(
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

        let proto = SignatureProtocolExecution::new(
            setup.clone(),
            signed_message.clone(),
            random_beacon,
            derivation_path.clone(),
        );
        let shares = proto.generate_shares().expect("failed to generate shares");
        for (&node_index, share) in &shares {
            let verify_share_result_with_wrong_msg_length = verify_signature_share(
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
        let verify_sig_result_with_wrong_msg_length = verify_threshold_signature(
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
