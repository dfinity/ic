use rand::Rng;
use std::collections::BTreeMap;
use tecdsa::*;

fn corrupt_ciphertext_single(
    ctext: &[EccScalar],
    corruption_target: usize,
) -> ThresholdEcdsaResult<Vec<EccScalar>> {
    let mut ctext = ctext.to_vec();
    let curve_type = ctext[corruption_target].curve_type();
    let randomizer = EccScalar::one(curve_type);
    ctext[corruption_target] = ctext[corruption_target].add(&randomizer)?;
    Ok(ctext)
}

fn corrupt_ciphertext_pairs(
    ctext: &[(EccScalar, EccScalar)],
    corruption_target: usize,
) -> ThresholdEcdsaResult<Vec<(EccScalar, EccScalar)>> {
    let mut ctext = ctext.to_vec();
    let curve_type = ctext[corruption_target].0.curve_type();
    let randomizer = EccScalar::one(curve_type);
    ctext[corruption_target].0 = ctext[corruption_target].0.add(&randomizer)?;
    Ok(ctext)
}

fn corrupt_dealing(
    dealing: &IDkgDealingInternal,
    corruption_target: usize,
) -> ThresholdEcdsaResult<IDkgDealingInternal> {
    let ciphertext = match &dealing.ciphertext {
        MEGaCiphertext::Single(c) => MEGaCiphertext::Single(MEGaCiphertextSingle {
            ephemeral_key: c.ephemeral_key,
            ctexts: corrupt_ciphertext_single(&c.ctexts, corruption_target)?,
        }),
        MEGaCiphertext::Pairs(c) => MEGaCiphertext::Pairs(MEGaCiphertextPair {
            ephemeral_key: c.ephemeral_key,
            ctexts: corrupt_ciphertext_pairs(&c.ctexts, corruption_target)?,
        }),
    };

    Ok(IDkgDealingInternal {
        ciphertext,
        commitment: dealing.commitment.clone(),
        proof: dealing.proof.clone(),
    })
}

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
        corrupt_dealing(&dealing, corruption_target as usize)?,
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
        // the complaint is valid:
        complaint
            .verify(
                dealings.get(&dealer_index).unwrap(),
                dealer_index,
                corruption_target,
                &pk0,
                associated_data,
            )
            .unwrap();

        // the complaint is invalid if we change the AD:
        assert!(complaint
            .verify(
                dealings.get(&dealer_index).unwrap(),
                dealer_index,
                corruption_target,
                &pk0,
                &rng.gen::<[u8; 32]>(),
            )
            .is_err());

        // the complaint is invalid if we change the complainer public key:
        assert!(complaint
            .verify(
                dealings.get(&dealer_index).unwrap(),
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
