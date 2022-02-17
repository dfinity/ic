use ic_crypto_internal_threshold_sig_ecdsa::*;
use rand::Rng;
use std::collections::BTreeMap;

#[test]
fn should_complaint_system_work() -> ThresholdEcdsaResult<()> {
    let curve = EccCurveType::K256;
    let associated_data = b"assoc_data_test";

    let mut rng = rand::thread_rng();

    let sk0 = MEGaPrivateKey::generate(curve, &mut rng)?;
    let pk0 = sk0.public_key()?;

    let sk1 = MEGaPrivateKey::generate(curve, &mut rng)?;
    let pk1 = sk1.public_key()?;

    let dealer_index = 0;
    let threshold = 1;

    let dealing = IDkgDealingInternal::new(
        &SecretShares::Random,
        curve,
        Seed::from_rng(&mut rng),
        threshold,
        &[pk0, pk1],
        dealer_index,
        associated_data,
    )?;

    let mut dealings = BTreeMap::new();

    let corruption_target = 0;

    dealings.insert(
        dealer_index,
        test_utils::corrupt_dealing(&dealing, &[corruption_target], &mut rng)?,
    );

    let complaints = generate_complaints(
        &dealings,
        associated_data,
        corruption_target,
        &sk0,
        &pk0,
        Seed::from_rng(&mut rng),
    )
    .expect("failed to generate complaints");

    assert_eq!(complaints.len(), 1);

    for complaint in complaints.values() {
        let dealing = dealings.get(&dealer_index).unwrap();

        // the complaint is valid:
        complaint
            .verify(
                dealing,
                dealer_index,
                corruption_target,
                &pk0,
                associated_data,
            )
            .unwrap();

        // the complaint is invalid if we change the AD:
        assert!(complaint
            .verify(
                dealing,
                dealer_index,
                corruption_target,
                &pk0,
                &rng.gen::<[u8; 32]>(),
            )
            .is_err());

        // the complaint is invalid if we change the complainer public key:
        assert!(complaint
            .verify(
                dealing,
                dealer_index,
                corruption_target,
                &pk1,
                associated_data,
            )
            .is_err());

        // the complaint is invalid if we change the dealer ID
        assert!(complaint
            .verify(
                dealings.get(&dealer_index).unwrap(),
                dealer_index + 1,
                corruption_target,
                &pk0,
                associated_data,
            )
            .is_err());

        let opener_index = 1;

        let opening = open_dealing(
            dealing,
            associated_data,
            dealer_index,
            opener_index,
            &sk1,
            &pk1,
        )
        .expect("Unable to open dealing");

        assert!(verify_dealing_opening(dealing, opener_index, &opening).is_ok());
    }

    // a complaint against a dealing with modified ephemeral key will not verify
    // (because the proof will fail)

    let modified_ephemeral_key = MEGaCiphertextPair {
        ephemeral_key: EccPoint::hash_to_point(curve, &rng.gen::<[u8; 32]>(), "ad".as_bytes())?,
        ctexts: vec![
            (
                EccScalar::random(curve, &mut rng)?,
                EccScalar::random(curve, &mut rng)?,
            ),
            (
                EccScalar::random(curve, &mut rng)?,
                EccScalar::random(curve, &mut rng)?,
            ),
        ],
    };

    let bad_key_dealing = IDkgDealingInternal {
        ciphertext: modified_ephemeral_key.into(),
        commitment: dealing.commitment.clone(),
        proof: dealing.proof,
    };

    assert_eq!(
        complaints
            .get(&0)
            .unwrap()
            .verify(
                &bad_key_dealing,
                dealer_index,
                corruption_target,
                &pk0,
                associated_data,
            )
            .unwrap_err(),
        ThresholdEcdsaError::InvalidProof
    );

    Ok(())
}

#[test]
fn should_complaint_verification_reject_spurious_complaints() -> ThresholdEcdsaResult<()> {
    let curve = EccCurveType::K256;
    let associated_data = b"assoc_data_test";

    let mut rng = rand::thread_rng();

    let sk = MEGaPrivateKey::generate(curve, &mut rng)?;
    let pk = sk.public_key()?;

    let dealer_index = 0;
    let receiver_index = 0;
    let threshold = 1;

    let dealing = IDkgDealingInternal::new(
        &SecretShares::Random,
        curve,
        Seed::from_rng(&mut rng),
        threshold,
        &[pk],
        dealer_index,
        associated_data,
    )?;

    let complaint = IDkgComplaintInternal::new(
        Seed::from_rng(&mut rng),
        &dealing,
        dealer_index,
        receiver_index,
        &sk,
        &pk,
        associated_data,
    )?;

    assert!(complaint
        .verify(&dealing, dealer_index, 0, &pk, associated_data)
        .is_err());

    Ok(())
}
