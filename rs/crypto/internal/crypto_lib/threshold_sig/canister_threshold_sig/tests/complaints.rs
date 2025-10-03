use ic_crypto_internal_threshold_sig_canister_threshold_sig::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;
use std::collections::BTreeMap;
use strum::IntoEnumIterator;

#[test]
fn should_complaint_system_work() -> CanisterThresholdResult<()> {
    use strum::IntoEnumIterator;
    let rng = &mut reproducible_rng();

    for alg in IdkgProtocolAlgorithm::iter() {
        let curve = alg.curve();
        let associated_data = b"assoc_data_test";

        let sk0 = MEGaPrivateKey::generate(curve, rng);
        let pk0 = sk0.public_key();

        let sk1 = MEGaPrivateKey::generate(curve, rng);
        let pk1 = sk1.public_key();

        let dealer_index = 0;
        let threshold = 1;

        let dealing = IDkgDealingInternal::new(
            &SecretShares::Random,
            alg,
            Seed::from_rng(rng),
            threshold,
            &[pk0.clone(), pk1.clone()],
            dealer_index,
            associated_data,
        )?;

        let mut dealings = BTreeMap::new();

        let corruption_target = 0;

        dealings.insert(
            dealer_index,
            test_utils::corrupt_dealing(&dealing, &[corruption_target], Seed::from_rng(rng))?,
        );

        let complaints = generate_complaints(
            alg.to_algorithm_id(),
            &dealings,
            associated_data,
            corruption_target,
            &sk0,
            &pk0,
            Seed::from_rng(rng),
        )
        .expect("failed to generate complaints");

        assert_eq!(complaints.len(), 1);

        for complaint in complaints.values() {
            let dealing = dealings.get(&dealer_index).unwrap();

            // the complaint is valid:
            complaint
                .verify(
                    alg,
                    dealing,
                    dealer_index,
                    corruption_target,
                    &pk0,
                    associated_data,
                )
                .unwrap();

            for complaint_corrupter in test_utils::ComplaintCorrupter::iter() {
                let corrupted_complaint =
                    complaint_corrupter.clone_and_corrupt_complaint(complaint)?;
                assert_eq!(
                    corrupted_complaint
                        .verify(
                            alg,
                            dealing,
                            dealer_index,
                            corruption_target,
                            &pk0,
                            associated_data,
                        )
                        .unwrap_err(),
                    CanisterThresholdError::InvalidProof,
                    "failed for {complaint_corrupter:?}"
                );
            }

            // the complaint is invalid if we change the AD:
            assert_eq!(
                complaint
                    .verify(
                        alg,
                        dealing,
                        dealer_index,
                        corruption_target,
                        &pk0,
                        &rng.r#gen::<[u8; 32]>(),
                    )
                    .unwrap_err(),
                CanisterThresholdError::InvalidProof
            );

            // the complaint is invalid if we change the complainer public key:
            assert_eq!(
                complaint
                    .verify(
                        alg,
                        dealing,
                        dealer_index,
                        corruption_target,
                        &pk1,
                        associated_data,
                    )
                    .unwrap_err(),
                CanisterThresholdError::InvalidProof
            );

            // the complaint is invalid if we change the dealer ID
            assert_eq!(
                complaint
                    .verify(
                        alg,
                        dealings.get(&dealer_index).unwrap(),
                        dealer_index + 1,
                        corruption_target,
                        &pk0,
                        associated_data,
                    )
                    .unwrap_err(),
                CanisterThresholdError::InvalidProof
            );

            let opener_index = 1;

            let opening = CommitmentOpening::open_dealing(
                alg,
                dealing,
                associated_data,
                dealer_index,
                opener_index,
                &sk1,
                &pk1,
            )
            .expect("Unable to open dealing");

            assert_eq!(
                verify_dealing_opening(dealing, opener_index, &opening),
                Ok(())
            );

            let corrupted_opening = test_utils::corrupt_opening(&opening)?;

            assert_eq!(
                verify_dealing_opening(dealing, opener_index, &corrupted_opening).unwrap_err(),
                ThresholdVerifyOpeningInternalError::InvalidOpening
            );
        }

        // a complaint against a dealing with modified ephemeral key will not verify
        // (because the complaint proof will fail)

        // Create a new dealing so we can steal the dealing's ephemeral key and PoP

        let dealing2 = IDkgDealingInternal::new(
            &SecretShares::Random,
            alg,
            Seed::from_rng(rng),
            threshold,
            &[pk0.clone(), pk1],
            dealer_index,
            associated_data,
        )?;

        let bad_key_dealing = IDkgDealingInternal {
            ciphertext: dealing2.ciphertext,
            commitment: dealing.commitment.clone(),
            proof: dealing.proof,
        };

        assert_eq!(
            complaints
                .get(&0)
                .unwrap()
                .verify(
                    alg,
                    &bad_key_dealing,
                    dealer_index,
                    corruption_target,
                    &pk0,
                    associated_data,
                )
                .unwrap_err(),
            CanisterThresholdError::InvalidProof
        );
    }

    Ok(())
}

#[test]
fn should_complaint_verification_reject_spurious_complaints() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for alg in IdkgProtocolAlgorithm::iter() {
        let curve = alg.curve();
        let associated_data = b"assoc_data_test";

        let sk = MEGaPrivateKey::generate(curve, rng);
        let pk = sk.public_key();

        let dealer_index = 0;
        let receiver_index = 0;
        let threshold = 1;

        let dealing = IDkgDealingInternal::new(
            &SecretShares::Random,
            alg,
            Seed::from_rng(rng),
            threshold,
            std::slice::from_ref(&pk),
            dealer_index,
            associated_data,
        )?;

        let complaint = IDkgComplaintInternal::new(
            Seed::from_rng(rng),
            alg,
            &dealing,
            dealer_index,
            receiver_index,
            &sk,
            &pk,
            associated_data,
        )?;

        assert_eq!(
            complaint
                .verify(alg, &dealing, dealer_index, 0, &pk, associated_data)
                .unwrap_err(),
            CanisterThresholdError::InvalidComplaint
        );
    }

    Ok(())
}
