use ic_crypto_ecdsa_secp256r1::{KeyDecodingError, PrivateKey, PublicKey};

#[test]
fn should_pass_wycheproof_ecdsa_secp256r1_verification_tests() -> Result<(), KeyDecodingError> {
    use wycheproof::ecdsa::*;

    let test_set =
        TestSet::load(TestName::EcdsaSecp256r1Sha256P1363).expect("Unable to load test set");

    for test_group in &test_set.test_groups {
        let pk = PublicKey::deserialize_sec1(&test_group.key.key)?;
        let pk_der = PublicKey::deserialize_der(&test_group.der)?;
        assert_eq!(pk, pk_der);

        for test in &test_group.tests {
            let accepted = pk.verify_signature(&test.msg, &test.sig);

            if accepted {
                assert_eq!(test.result, wycheproof::TestResult::Valid);
            } else {
                assert_eq!(test.result, wycheproof::TestResult::Invalid);
            }
        }
    }

    Ok(())
}

#[test]
fn should_use_rfc6979_nonces_for_ecdsa_signature_generation() {
    // See https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5
    let sk = PrivateKey::deserialize_sec1(
        &hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .expect("Valid hex"),
    )
    .expect("Valid key");

    let message = b"sample";

    let expected_sig = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

    let generated_sig = sk.sign_message(message);

    assert_eq!(hex::encode(generated_sig), expected_sig);
}

#[test]
fn should_reject_short_x_when_deserializing_private_key() {
    for short_len in 0..31 {
        let short_x = vec![42; short_len];
        assert!(PrivateKey::deserialize_sec1(&short_x).is_err());
    }
}

#[test]
fn should_reject_long_x_when_deserializing_private_key() {
    for long_len in 33..128 {
        let long_x = vec![42; long_len];
        assert!(PrivateKey::deserialize_sec1(&long_x).is_err());
    }
}

#[test]
fn should_accept_signatures_that_we_generate() {
    use rand::RngCore;

    let mut rng = rand::thread_rng();

    let sk = PrivateKey::generate_using_rng(&mut rng);
    let pk = sk.public_key();

    for m in 0..100 {
        let mut msg = vec![0u8; m];
        rng.fill_bytes(&mut msg);
        let sig = sk.sign_message(&msg);

        assert_eq!(
            sk.sign_message(&msg),
            sig,
            "ECDSA signature generation is deterministic"
        );

        assert!(pk.verify_signature(&msg, &sig));
    }
}

#[test]
fn should_serialization_and_deserialization_round_trip_for_private_keys(
) -> Result<(), KeyDecodingError> {
    let mut rng = rand::thread_rng();

    for _ in 0..2000 {
        let key = PrivateKey::generate_using_rng(&mut rng);

        let key_via_sec1 = PrivateKey::deserialize_sec1(&key.serialize_sec1())?;
        let key_via_p8_der = PrivateKey::deserialize_pkcs8_der(&key.serialize_pkcs8_der())?;
        let key_via_p8_pem = PrivateKey::deserialize_pkcs8_pem(&key.serialize_pkcs8_pem())?;

        let expected = key.serialize_sec1();
        assert_eq!(expected.len(), 32);

        assert_eq!(key_via_sec1.serialize_sec1(), expected);
        assert_eq!(key_via_p8_der.serialize_sec1(), expected);
        assert_eq!(key_via_p8_pem.serialize_sec1(), expected);
    }
    Ok(())
}

#[test]
fn should_serialization_and_deserialization_round_trip_for_public_keys(
) -> Result<(), KeyDecodingError> {
    let mut rng = rand::thread_rng();

    for _ in 0..2000 {
        let key = PrivateKey::generate_using_rng(&mut rng).public_key();

        let key_via_sec1 = PublicKey::deserialize_sec1(&key.serialize_sec1(false))?;
        let key_via_sec1c = PublicKey::deserialize_sec1(&key.serialize_sec1(true))?;
        let key_via_der = PublicKey::deserialize_der(&key.serialize_der())?;
        let key_via_pem = PublicKey::deserialize_pem(&key.serialize_pem())?;

        assert_eq!(key.serialize_sec1(true).len(), 33);
        let expected = key.serialize_sec1(false);
        assert_eq!(expected.len(), 65);

        assert_eq!(key_via_sec1.serialize_sec1(false), expected);
        assert_eq!(key_via_sec1c.serialize_sec1(false), expected);
        assert_eq!(key_via_der.serialize_sec1(false), expected);
        assert_eq!(key_via_pem.serialize_sec1(false), expected);
    }

    Ok(())
}

#[test]
fn should_insecure_keygen_for_testing_be_deterministic() {
    assert_eq!(
        hex::encode(PrivateKey::generate_insecure_key_for_testing(42).serialize_sec1()),
        "7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a"
    );

    assert_eq!(
        hex::encode(PrivateKey::generate_insecure_key_for_testing(9000).serialize_sec1()),
        "20bfd7f85be7ce1f54ea1b0d750ae3324ab7897fde3235e189ec697f0fade983"
    );
}

#[test]
fn should_be_able_to_parse_openssl_generated_pkcs8_key() {
    pub const SAMPLE_SECP256R1_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCONVBIjiyGluSnRK
i+XLTxAsC8Ru+vVg7nb4m/0WVs2hRANCAASfFwq3hYPaJxZmL+Q0fo82sVyjmoWn
0nEEwy+F3w/aAL5BM7Sca2GPohxJbSDqr08tH0F7raEDWE+LUkZTU643
-----END PRIVATE KEY-----
"#;

    let key = PrivateKey::deserialize_pkcs8_pem(SAMPLE_SECP256R1_PEM).unwrap();

    assert_eq!(
        hex::encode(key.serialize_sec1()),
        "08e3550488e2c8696e4a744a8be5cb4f102c0bc46efaf560ee76f89bfd1656cd",
    );
}
