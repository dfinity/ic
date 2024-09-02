use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use std::convert::TryFrom;
use strum::IntoEnumIterator;

#[test]
fn mega_key_generation() -> CanisterThresholdResult<()> {
    let fixed_seed = [0x42; 32];

    let expected = [
        (
            EccCurveType::K256,
            "078af152fb1edc2488a6d414ac13e76de66904648c585dc5f5032b3c022716cd",
            "027e4c1145be85c1d62c24be6ff81f837a1c63d4051071233569b55fb410da4ebd",
        ),
        (
            EccCurveType::P256,
            "078af152fb1edc2488a6d414ac13e76de66904648c585dc5f5032b3c022716cd",
            "03343ae689bf56d0bb443694eacdf83435380f564d1a63c9689f3f5f606c480c01",
        ),
    ];

    for (curve_type, expected_sk, expected_pk) in expected {
        let seed = Seed::from_bytes(&fixed_seed);

        let (pk, sk) = gen_keypair(curve_type, seed);

        assert_eq!(pk.curve_type(), curve_type);
        assert_eq!(sk.curve_type(), curve_type);

        let sk_bytes = hex::encode(sk.serialize());
        assert_eq!(sk_bytes, *expected_sk);

        let pk_bytes = hex::encode(pk.serialize());
        assert_eq!(pk_bytes, *expected_pk);
    }

    Ok(())
}

#[test]
fn mega_key_validity() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let sk = MEGaPrivateKey::generate(curve_type, rng);
        let pk = sk.public_key();

        let mut pk_bytes = pk.serialize();

        assert!(verify_mega_public_key(curve_type, &pk_bytes).is_ok());

        if curve_type != EccCurveType::Ed25519 {
            // In compressed format flipping this bit is equivalent to
            // flipping the sign of y, which is equivalent to negating the
            // point. In all cases if pk_bytes is a valid encoding, this
            // modification is also valid.
            pk_bytes[0] ^= 1;
            assert!(verify_mega_public_key(curve_type, &pk_bytes).is_ok());

            // Invalid SEC1 header.
            pk_bytes[0] ^= 2;
            assert!(verify_mega_public_key(curve_type, &pk_bytes).is_err());
        }
        // This x is too large to be a field element (except for P-521)
        let mut max_x = vec![0xFF; curve_type.point_bytes()];
        max_x[0] = 2;
        assert!(verify_mega_public_key(curve_type, &max_x).is_err());
    }
    Ok(())
}

#[test]
fn mega_single_smoke_test() -> Result<(), CanisterThresholdError> {
    let rng = &mut reproducible_rng();

    for alg in IdkgProtocolAlgorithm::iter() {
        let curve = alg.curve();
        let a_sk = MEGaPrivateKey::generate(curve, rng);
        let b_sk = MEGaPrivateKey::generate(curve, rng);

        let a_pk = a_sk.public_key();
        let b_pk = b_sk.public_key();

        let associated_data = b"assoc_data_test";

        let ptext_for_a = EccScalar::random(curve, rng);
        let ptext_for_b = EccScalar::random(curve, rng);

        let dealer_index = 0;

        let seed = Seed::from_rng(rng);

        let ctext = MEGaCiphertextSingle::encrypt(
            seed,
            alg,
            &[ptext_for_a.clone(), ptext_for_b.clone()],
            &[a_pk.clone(), b_pk.clone()],
            dealer_index,
            associated_data,
        )?;

        let ptext_a = ctext.decrypt(alg, associated_data, dealer_index, 0, &a_sk, &a_pk)?;

        assert_eq!(
            hex::encode(ptext_a.serialize()),
            hex::encode(ptext_for_a.serialize())
        );

        let ptext_b = ctext.decrypt(alg, associated_data, dealer_index, 1, &b_sk, &b_pk)?;

        assert_eq!(
            hex::encode(ptext_b.serialize()),
            hex::encode(ptext_for_b.serialize())
        );
    }

    Ok(())
}

#[test]
fn mega_pair_smoke_test() -> Result<(), CanisterThresholdError> {
    let rng = &mut reproducible_rng();

    for alg in IdkgProtocolAlgorithm::iter() {
        let curve = alg.curve();
        let a_sk = MEGaPrivateKey::generate(curve, rng);
        let b_sk = MEGaPrivateKey::generate(curve, rng);

        let a_pk = a_sk.public_key();
        let b_pk = b_sk.public_key();

        let associated_data = b"assoc_data_test";

        let ptext_for_a = (EccScalar::random(curve, rng), EccScalar::random(curve, rng));
        let ptext_for_b = (EccScalar::random(curve, rng), EccScalar::random(curve, rng));

        let seed = Seed::from_rng(rng);

        let dealer_index = 0;

        let ctext = MEGaCiphertextPair::encrypt(
            seed,
            alg,
            &[ptext_for_a.clone(), ptext_for_b.clone()],
            &[a_pk.clone(), b_pk.clone()],
            dealer_index,
            associated_data,
        )?;

        let ptext_a = ctext.decrypt(alg, associated_data, dealer_index, 0, &a_sk, &a_pk)?;
        assert_eq!(ptext_a, ptext_for_a);

        let ptext_b = ctext.decrypt(alg, associated_data, dealer_index, 1, &b_sk, &b_pk)?;
        assert_eq!(ptext_b, ptext_for_b);
    }

    Ok(())
}

#[test]
fn mega_should_reject_invalid_pop() -> Result<(), CanisterThresholdError> {
    let rng = &mut reproducible_rng();

    for alg in IdkgProtocolAlgorithm::iter() {
        let curve = alg.curve();
        let a_sk = MEGaPrivateKey::generate(curve, rng);
        let b_sk = MEGaPrivateKey::generate(curve, rng);

        let a_pk = a_sk.public_key();
        let b_pk = b_sk.public_key();

        let ad = b"assoc_data_test";

        let ptext_for_a = EccScalar::random(curve, rng);
        let ptext_for_b = EccScalar::random(curve, rng);

        let dealer_index = 0;

        let seed = Seed::from_rng(rng);

        let ctext = MEGaCiphertextSingle::encrypt(
            seed,
            alg,
            &[ptext_for_a, ptext_for_b],
            &[a_pk, b_pk.clone()],
            dealer_index,
            ad,
        )?;

        assert!(ctext
            .decrypt(alg, ad, dealer_index, 1, &b_sk, &b_pk)
            .is_ok());
        assert_eq!(
            ctext.verify_pop(alg, b"wrong_ad", dealer_index),
            Err(CanisterThresholdError::InvalidProof)
        );

        let mut bad_pop_pk = ctext.clone();
        bad_pop_pk.pop_public_key = ctext.ephemeral_key.clone();
        assert_eq!(
            bad_pop_pk.verify_pop(alg, ad, dealer_index),
            Err(CanisterThresholdError::InvalidProof)
        );

        let mut bad_eph_key = ctext;
        bad_eph_key.ephemeral_key = EccPoint::hash_to_point(curve, b"input", b"dst")?;
        assert_eq!(
            bad_eph_key.verify_pop(alg, ad, dealer_index),
            Err(CanisterThresholdError::InvalidProof)
        );
    }

    Ok(())
}

#[test]
fn mega_private_key_should_redact_logs() -> Result<(), CanisterThresholdError> {
    let rng = &mut reproducible_rng();

    for curve in EccCurveType::all() {
        let sk = MEGaPrivateKey::generate(curve, rng);

        let log = format!("{:?}", sk);
        assert_eq!(format!("MEGaPrivateKey({}) - REDACTED", curve), log);
    }

    Ok(())
}

#[test]
fn mega_private_key_bytes_should_redact_logs() -> Result<(), CanisterThresholdError> {
    let curve = EccCurveType::K256;

    let rng = &mut reproducible_rng();

    let sk = MEGaPrivateKey::generate(curve, rng);

    let bytes = MEGaPrivateKeyK256Bytes::try_from(&sk).expect("Deserialization failed");

    let log = format!("{:?}", bytes);
    assert_eq!("MEGaPrivateKeyK256Bytes - REDACTED", log);

    Ok(())
}

mod mega_cipher_text {
    use super::*;
    use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;

    #[test]
    fn should_decrypt_to_different_plaintext_when_secret_key_wrong() {
        let rng = &mut reproducible_rng();
        for ctext_type in MEGaCiphertextType::iter() {
            let setup = Setup::new(rng, ctext_type);

            let ptext_a = decrypt(
                setup.alg,
                setup.ctext,
                setup.associated_data,
                setup.dealer_index,
                0,
                &setup.b_sk,
                &setup.b_pk,
            )
            .expect("should successfully decrypt");

            assert_ne!(hex_encoded(ptext_a), hex_encoded(setup.ptext));
        }
    }

    #[test]
    fn should_fail_if_decrypt_of_ciphertext_fails_due_to_dealer_index_mismatch() {
        let rng = &mut reproducible_rng();

        for ctext_type in MEGaCiphertextType::iter() {
            let setup = Setup::new(rng, ctext_type);
            let invalid_dealer_index = 47;

            assert_eq!(
                setup.ctext.check_validity(
                    setup.alg,
                    1,
                    setup.associated_data,
                    invalid_dealer_index
                ),
                Err(CanisterThresholdError::InvalidProof)
            );
        }
    }

    #[test]
    fn should_fail_if_decrypt_of_ciphertext_fails_due_to_recipient_index_out_of_bounds() {
        let rng = &mut reproducible_rng();
        for ctext_type in MEGaCiphertextType::iter() {
            let setup = Setup::new(rng, ctext_type);
            // only a single recipient, so any index > 0 is invalid
            let invalid_recipient_index = 1;

            assert_eq!(
                decrypt(
                    setup.alg,
                    setup.ctext,
                    setup.associated_data,
                    setup.dealer_index,
                    invalid_recipient_index,
                    &setup.a_sk,
                    &setup.a_pk
                ),
                Err(CanisterThresholdError::InvalidArguments(
                    "Invalid index".to_string()
                ))
            );
        }
    }

    #[test]
    fn should_fail_if_decrypt_of_ciphertext_fails_due_to_secret_key_curve_mismatch() {
        let rng = &mut reproducible_rng();
        for ctext_type in MEGaCiphertextType::iter() {
            let setup = Setup::new(rng, ctext_type);
            let another_curve = EccCurveType::P256;
            let b_sk = MEGaPrivateKey::generate(another_curve, rng);

            assert_eq!(
                decrypt(
                    setup.alg,
                    setup.ctext,
                    setup.associated_data,
                    setup.dealer_index,
                    0,
                    &b_sk,
                    &setup.a_pk
                ),
                Err(CanisterThresholdError::CurveMismatch)
            );
        }
    }

    #[derive(Debug, PartialEq)]
    enum MEGaPlaintext {
        Single(EccScalar),
        Pair((EccScalar, EccScalar)),
    }

    fn hex_encoded(ptext: MEGaPlaintext) -> String {
        match ptext {
            MEGaPlaintext::Single(ptext) => hex::encode(ptext.serialize()),
            MEGaPlaintext::Pair((ptext_a, ptext_b)) => {
                format!(
                    "{}{}",
                    hex::encode(ptext_a.serialize()),
                    hex::encode(ptext_b.serialize())
                )
            }
        }
    }

    fn decrypt(
        alg: IdkgProtocolAlgorithm,
        ctext: MEGaCiphertext,
        associated_data: &[u8],
        dealer_index: NodeIndex,
        recipient_index: NodeIndex,
        our_private_key: &MEGaPrivateKey,
        recipient_public_key: &MEGaPublicKey,
    ) -> CanisterThresholdResult<MEGaPlaintext> {
        match ctext {
            MEGaCiphertext::Single(single) => single
                .decrypt(
                    alg,
                    associated_data,
                    dealer_index,
                    recipient_index,
                    our_private_key,
                    recipient_public_key,
                )
                .map(MEGaPlaintext::Single),
            MEGaCiphertext::Pairs(pairs) => pairs
                .decrypt(
                    alg,
                    associated_data,
                    dealer_index,
                    recipient_index,
                    our_private_key,
                    recipient_public_key,
                )
                .map(MEGaPlaintext::Pair),
        }
    }

    struct Setup {
        a_sk: MEGaPrivateKey,
        b_sk: MEGaPrivateKey,
        a_pk: MEGaPublicKey,
        b_pk: MEGaPublicKey,
        associated_data: &'static [u8],
        ptext: MEGaPlaintext,
        dealer_index: NodeIndex,
        ctext: MEGaCiphertext,
        alg: IdkgProtocolAlgorithm,
    }

    impl Setup {
        fn new(rng: &mut ReproducibleRng, ctext_type: MEGaCiphertextType) -> Setup {
            let alg = IdkgProtocolAlgorithm::EcdsaSecp256k1;
            let curve = alg.curve();
            let a_sk = MEGaPrivateKey::generate(curve, rng);
            let b_sk = MEGaPrivateKey::generate(curve, rng);
            let a_pk = a_sk.public_key();
            let b_pk = b_sk.public_key();
            let associated_data = b"assoc_data_test";
            let dealer_index = 0;
            let seed = Seed::from_rng(rng);
            let (ptext, ctext) = match ctext_type {
                MEGaCiphertextType::Single => {
                    let ptext = EccScalar::random(curve, rng);
                    let ctext = MEGaCiphertext::Single(
                        MEGaCiphertextSingle::encrypt(
                            seed,
                            alg,
                            &[ptext.clone()],
                            &[a_pk.clone()],
                            dealer_index,
                            associated_data,
                        )
                        .expect("should successfully encrypt"),
                    );
                    (MEGaPlaintext::Single(ptext), ctext)
                }
                MEGaCiphertextType::Pairs => {
                    let ptext = (EccScalar::random(curve, rng), EccScalar::random(curve, rng));
                    let ctext = MEGaCiphertext::Pairs(
                        MEGaCiphertextPair::encrypt(
                            seed,
                            alg,
                            &[ptext.clone()],
                            &[a_pk.clone()],
                            dealer_index,
                            associated_data,
                        )
                        .expect("should successfully encrypt"),
                    );
                    (MEGaPlaintext::Pair(ptext), ctext)
                }
            };

            Setup {
                a_sk,
                b_sk,
                a_pk,
                b_pk,
                associated_data,
                ptext,
                dealer_index,
                ctext,
                alg,
            }
        }
    }
}
