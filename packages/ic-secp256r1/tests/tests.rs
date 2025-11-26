use hex_literal::hex;
use ic_secp256r1::*;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use sha2::Digest;

fn test_rng_with_seed(seed: [u8; 32]) -> ChaCha20Rng {
    use rand::SeedableRng;
    ChaCha20Rng::from_seed(seed)
}

fn test_rng() -> ChaCha20Rng {
    let seed = rand::rng().r#gen::<[u8; 32]>();
    // If a test ever fails, reproduce it using
    // let mut rng = test_rng_with_seed(hex!("SEED"));
    println!("RNG seed: {}", hex::encode(seed));
    test_rng_with_seed(seed)
}

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

    // Now check the prehash variant:
    let mut sha256 = sha2::Sha256::new();
    sha256.update(message);
    let message_hash = sha256.finalize();
    let generated_sig = sk.sign_digest(&message_hash).unwrap();
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

    let rng = &mut test_rng();

    let sk = PrivateKey::generate_using_rng(rng);
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
fn should_serialization_and_deserialization_round_trip_for_private_keys()
-> Result<(), KeyDecodingError> {
    let rng = &mut test_rng();

    for _ in 0..200 {
        let key = PrivateKey::generate_using_rng(rng);

        let key_via_sec1 = PrivateKey::deserialize_sec1(&key.serialize_sec1())?;
        let key_via_5915_der = PrivateKey::deserialize_rfc5915_der(&key.serialize_rfc5915_der())?;
        let key_via_5915_pem = PrivateKey::deserialize_rfc5915_pem(&key.serialize_rfc5915_pem())?;
        let key_via_p8_der = PrivateKey::deserialize_pkcs8_der(&key.serialize_pkcs8_der())?;
        let key_via_p8_pem = PrivateKey::deserialize_pkcs8_pem(&key.serialize_pkcs8_pem())?;

        let expected = key.serialize_sec1();
        assert_eq!(expected.len(), 32);

        assert_eq!(key_via_sec1.serialize_sec1(), expected);
        assert_eq!(key_via_5915_der.serialize_sec1(), expected);
        assert_eq!(key_via_5915_pem.serialize_sec1(), expected);
        assert_eq!(key_via_p8_der.serialize_sec1(), expected);
        assert_eq!(key_via_p8_pem.serialize_sec1(), expected);
    }
    Ok(())
}

#[test]
fn test_sign_prehash_works_with_any_size_input_gte_16() {
    let rng = &mut test_rng();

    let sk = PrivateKey::generate_using_rng(rng);
    let pk = sk.public_key();

    for i in 0..16 {
        let buf = vec![0x42; i];
        assert_eq!(sk.sign_digest(&buf), None);
    }

    for i in 16..1024 {
        let buf = vec![0x42; i];
        let sig = sk.sign_digest(&buf).unwrap();
        assert!(pk.verify_signature_prehashed(&buf, &sig));
    }
}

#[test]
fn should_serialization_and_deserialization_round_trip_for_public_keys()
-> Result<(), KeyDecodingError> {
    let rng = &mut test_rng();

    for _ in 0..200 {
        let key = PrivateKey::generate_using_rng(rng).public_key();

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
fn should_reject_invalid_public_keys() {
    struct InvalidKey {
        reason: &'static str,
        key: Vec<u8>,
    }

    impl InvalidKey {
        fn new(reason: &'static str, key_hex: &'static str) -> Self {
            let key = hex::decode(key_hex).expect("Invalid key_hex param");
            Self { reason, key }
        }
    }

    let invalid_keys = [
        InvalidKey::new("empty", ""),
        InvalidKey::new("too short", "02"),
        InvalidKey::new(
            "valid compressed point with uncompressed header",
            "04EB2D21CD969E68C767B091E91900863E7699826C3466F15B956BBB6CBAEDB09A",
        ),
        InvalidKey::new(
            "invalid x, header 02",
            "02EB2D21CD969E68C767B091E91900863E7699826C3466F15B956BBB6CBAEDB09C",
        ),
        InvalidKey::new(
            "invalid x, header 03",
            "03EB2D21CD969E68C767B091E91900863E7699826C3466F15B956BBB6CBAEDB09C",
        ),
        InvalidKey::new(
            "valid uncompressed point with header 02",
            "02EB2D21CD969E68C767B091E91900863E7699826C3466F15B956BBB6CBAEDB09A5A16ED621975EC1BCB81A41EE5DCF719021B12A95CC858A735A266135EFD2E4E",
        ),
        InvalidKey::new(
            "valid uncompressed point with header 03",
            "03EB2D21CD969E68C767B091E91900863E7699826C3466F15B956BBB6CBAEDB09A5A16ED621975EC1BCB81A41EE5DCF719021B12A95CC858A735A266135EFD2E4E",
        ),
        InvalidKey::new(
            "invalid uncompressed point (y off by one)",
            "04EB2D21CD969E68C767B091E91900863E7699826C3466F15B956BBB6CBAEDB09A5A16ED621975EC1BCB81A41EE5DCF719021B12A95CC858A735A266135EFD2E4F",
        ),
        InvalidKey::new(
            "valid secp256k1 point",
            "04F599CDA3A05987498A716E820651AC96A4EEAA3AD9B7D6F244A83CC3381CABC4C300A1369821A5A86D4D9BA74FF68817C4CAEA4BAC737A7B00A48C4835F28DB4",
        ),
    ];

    for invalid_key in &invalid_keys {
        let result = PublicKey::deserialize_sec1(&invalid_key.key);

        assert!(
            result.is_err(),
            "Accepted invalid key ({})",
            invalid_key.reason
        );
    }
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

#[test]
fn should_be_able_to_parse_openssl_generated_rfc5915_key() {
    pub const SAMPLE_SECP256R1_5915_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIF2fjBZ/X47HPxDX4As+gqLUw5QCH8fAfDyOqUe0WmS7oAoGCCqGSM49
AwEHoUQDQgAEdILMY+oxT8lAKSPiAqCFbYkFWJkEQIyb5m/F/5xEoP4I8wbZsu/o
NRLvCGaIxJfchxpjcCysTG12MfKOf6/Phw==
-----END EC PRIVATE KEY-----
"#;

    let key = PrivateKey::deserialize_rfc5915_pem(SAMPLE_SECP256R1_5915_PEM).unwrap();

    assert_eq!(
        hex::encode(key.serialize_sec1()),
        "5d9f8c167f5f8ec73f10d7e00b3e82a2d4c394021fc7c07c3c8ea947b45a64bb",
    );

    // Our re-encoding includes carriage returns, ignore that:
    assert_eq!(
        key.serialize_rfc5915_pem().replace('\r', ""),
        SAMPLE_SECP256R1_5915_PEM
    );
}

#[test]
fn private_derivation_is_compatible_with_public_derivation() {
    use rand::Rng;

    let rng = &mut test_rng();

    fn random_path<R: Rng>(rng: &mut R) -> DerivationPath {
        let l = 1 + rng.r#gen::<usize>() % 9;
        let path = (0..l).map(|_| rng.r#gen::<u32>()).collect::<Vec<u32>>();
        DerivationPath::new_bip32(&path)
    }

    for _ in 0..100 {
        let master_sk = PrivateKey::generate_using_rng(rng);
        let master_pk = master_sk.public_key();

        let path = random_path(rng);

        let chain_code = rng.r#gen::<[u8; 32]>();

        let (derived_pk, cc_pk) = master_pk.derive_subkey_with_chain_code(&path, &chain_code);

        let (derived_sk, cc_sk) = master_sk.derive_subkey_with_chain_code(&path, &chain_code);

        assert_eq!(
            hex::encode(derived_pk.serialize_sec1(true)),
            hex::encode(derived_sk.public_key().serialize_sec1(true))
        );

        assert_eq!(hex::encode(cc_pk), hex::encode(cc_sk));

        let msg = rng.r#gen::<[u8; 32]>();
        let derived_sig = derived_sk.sign_message(&msg);

        assert!(derived_pk.verify_signature(&msg, &derived_sig));
    }
}

#[test]
fn should_match_slip10_derivation_test_data() {
    // Test data from https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-nist256p1
    let chain_code = hex!("98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318");

    let private_key = PrivateKey::deserialize_sec1(&hex!(
        "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7"
    ))
    .expect("Test has valid key");

    let public_key = PublicKey::deserialize_sec1(&hex!(
        "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0"
    ))
    .expect("Test has valid key");

    assert_eq!(
        hex::encode(public_key.serialize_sec1(true)),
        hex::encode(private_key.public_key().serialize_sec1(true))
    );

    let path = DerivationPath::new_bip32(&[2, 1000000000]);

    let (derived_secret_key, sk_chain_code) =
        private_key.derive_subkey_with_chain_code(&path, &chain_code);

    let (derived_public_key, pk_chain_code) =
        public_key.derive_subkey_with_chain_code(&path, &chain_code);
    assert_eq!(
        hex::encode(sk_chain_code),
        "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059",
    );
    assert_eq!(
        hex::encode(pk_chain_code),
        "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059",
    );

    assert_eq!(
        hex::encode(derived_public_key.serialize_sec1(true)),
        "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4",
    );

    assert_eq!(
        hex::encode(derived_secret_key.serialize_sec1()),
        "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119",
    );

    assert_eq!(
        hex::encode(derived_public_key.serialize_sec1(true)),
        hex::encode(derived_secret_key.public_key().serialize_sec1(true)),
        "Derived keys match"
    );
}

#[test]
fn private_derivation_also_works_for_derived_keys() {
    let rng = &mut test_rng();
    use rand::Rng;

    for _ in 0..100 {
        let master_sk = PrivateKey::generate_using_rng(rng);

        let chain_code = rng.r#gen::<[u8; 32]>();
        let path_len = 2 + rng.r#gen::<usize>() % 32;
        let path = (0..path_len)
            .map(|_| rng.r#gen::<u32>())
            .collect::<Vec<u32>>();

        // First derive directly from a normal key
        let (derived_sk, cc_sk) =
            master_sk.derive_subkey_with_chain_code(&DerivationPath::new_bip32(&path), &chain_code);

        // Now derive with the path split in half

        let split = rng.r#gen::<usize>() % (path_len - 1);
        let path1 = DerivationPath::new_bip32(&path[..split]);
        let path2 = DerivationPath::new_bip32(&path[split..]);

        // Derive the intermediate secret key and chain code
        let (isk, icc) = master_sk.derive_subkey_with_chain_code(&path1, &chain_code);

        // From the intermediate key, use the second part of the path to derive the final key

        let (fsk, fcc) = isk.derive_subkey_with_chain_code(&path2, &icc);

        assert_eq!(hex::encode(fcc), hex::encode(cc_sk));

        assert_eq!(
            hex::encode(fsk.serialize_sec1()),
            hex::encode(derived_sk.serialize_sec1())
        );
    }
}

#[test]
fn should_reject_secp256k1_private_key() {
    let secp256k1 = "-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgtyNDLgx0SPJ/4ME90KL3
ZkhZuYpPCWyb1DS6ogQaIpChRANCAAS1xlnnfevnaVSeVScuD7U4AIuN9DftUQIh
SRX0gAHGwZEgbRHaxgEPtpUyCnHhHL/VUmSB6GgerMzD6LzDY6qt
-----END PRIVATE KEY-----";

    match PrivateKey::deserialize_pkcs8_pem(secp256k1) {
        Ok(_) => panic!("Unexpectedly accepted a secp256k1 private key as secp256r1"),
        Err(KeyDecodingError::InvalidKeyEncoding(e)) => {
            assert_eq!(
                format!("{e:?}"),
                "\"PublicKey(OidUnknown { oid: ObjectIdentifier(1.2.840.10045.3.1.7) })\""
            );
        }
        Err(e) => panic!("Unexpected error {e:?}"),
    }
}

#[test]
fn should_reject_secp256k1_public_key() {
    let secp256k1 = "-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAECQoUIgCFbhoM8kE2zNL0g2pWr42QlK41
KZh4l7SeYvLtL818ibSx/IXoUHNp4/gMp+x2sxwA/mtWO5PdPg7ksg==
-----END PUBLIC KEY-----";

    match PublicKey::deserialize_pem(secp256k1) {
        Ok(_) => panic!("Unexpectedly accepted a secp256k1 public key as secp256r1"),
        Err(KeyDecodingError::InvalidKeyEncoding(e)) => {
            assert_eq!(
                format!("{e:?}"),
                "\"OidUnknown { oid: ObjectIdentifier(1.2.840.10045.3.1.7) }\""
            );
        }
        Err(e) => panic!("Unexpected error {e:?}"),
    }
}
