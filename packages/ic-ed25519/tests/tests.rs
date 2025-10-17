use hex_literal::hex;
use ic_ed25519::*;
use rand::Rng;
use rand_chacha::ChaCha20Rng;

fn test_rng_with_seed(seed: [u8; 32]) -> ChaCha20Rng {
    use rand::SeedableRng;
    ChaCha20Rng::from_seed(seed)
}

fn test_rng() -> ChaCha20Rng {
    let seed = rand::thread_rng().r#gen::<[u8; 32]>();
    // If a test ever fails, reproduce it using
    // let mut rng = test_rng_with_seed(hex!("SEED"));
    println!("RNG seed: {}", hex::encode(seed));
    test_rng_with_seed(seed)
}

fn random_key<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> PrivateKey {
    PrivateKey::generate_from_seed(&rng.r#gen::<[u8; 32]>())
}

#[test]
fn secret_key_serialization_round_trips() {
    let mut rng = &mut test_rng();

    let pkcs8_formats = [
        PrivateKeyFormat::Pkcs8v1,
        PrivateKeyFormat::Pkcs8v2,
        PrivateKeyFormat::Pkcs8v2WithRingBug,
    ];

    for _ in 0..100 {
        let key = random_key(&mut rng);

        let via_raw = PrivateKey::deserialize_raw(&key.serialize_raw()).unwrap();
        assert_eq!(key, via_raw);

        for format in pkcs8_formats {
            let via_pkcs8_der =
                PrivateKey::deserialize_pkcs8(&key.serialize_pkcs8(format)).unwrap();
            assert_eq!(key, via_pkcs8_der);

            let via_pkcs8_pem =
                PrivateKey::deserialize_pkcs8_pem(&key.serialize_pkcs8_pem(format)).unwrap();
            assert_eq!(key, via_pkcs8_pem);
        }
    }
}

#[test]
fn secret_key_generation_from_seed_is_stable() {
    let tests = [
        (
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
        ),
        (
            "abcdef",
            "d5d81c66c3b1a0efb49e980ebc5629c352342dc3332c0697cbeeb55f892a8526",
        ),
        (
            "03fc46909ddfe5ed2f37af7923d846ecab53f962a83e4fc30be550671ceab3e6",
            "f3c92b5fe0c39a07b23447427a092f43cca5d03ad5a2b41658426ec5dcd493e2",
        ),
    ];

    for (seed, expected_key) in tests {
        let sk = PrivateKey::generate_from_seed(&hex::decode(seed).unwrap());
        assert_eq!(hex::encode(sk.serialize_raw()), expected_key);
    }
}

#[test]
fn pkcs8_v2_rep_includes_the_public_key() {
    let mut rng = &mut test_rng();
    let sk = random_key(&mut rng);
    let pk = sk.public_key().serialize_raw();

    let sk_pkcs8 = sk.serialize_pkcs8(PrivateKeyFormat::Pkcs8v2);

    let pk_offset = sk_pkcs8.len() - pk.len();

    assert_eq!(hex::encode(pk), hex::encode(&sk_pkcs8[pk_offset..]));
}

#[test]
fn signatures_we_generate_will_verify() {
    let mut rng = &mut test_rng();
    for _ in 0..100 {
        let sk = random_key(&mut rng);
        let pk = sk.public_key();

        let msg = rng.r#gen::<[u8; 32]>();

        let sig = sk.sign_message(&msg);
        assert_eq!(sig.len(), 64);

        assert!(pk.verify_signature(&msg, &sig).is_ok());
    }
}

#[test]
fn public_key_deserialization_rejects_key_not_on_curve() {
    let invalid_pk = hex!("0200000000000000000000000000000000000000000000000000000000000000");
    assert!(PublicKey::deserialize_raw(&invalid_pk).is_err());
}

#[test]
fn public_key_deserialization_rejects_keys_of_incorrect_length() {
    for len in 0..128 {
        if len == PublicKey::BYTES {
            continue;
        }

        let buf = vec![2; len];

        assert!(PublicKey::deserialize_raw(&buf).is_err());
    }
}

#[test]
#[cfg(feature = "rand")]
fn batch_verification_works() {
    fn batch_verifies(
        msg: &[[u8; 32]],
        sigs: &[[u8; 64]],
        keys: &[PublicKey],
        rng: &mut ChaCha20Rng,
    ) -> bool {
        let msg_ref = msg.iter().map(|m| m.as_ref()).collect::<Vec<&[u8]>>();
        let sig_ref = sigs.iter().map(|s| s.as_ref()).collect::<Vec<&[u8]>>();
        PublicKey::batch_verify(&msg_ref, &sig_ref, keys, rng).is_ok()
    }

    // Return two distinct positions in [0..max)
    fn two_positions<R: Rng>(max: usize, rng: &mut R) -> (usize, usize) {
        assert!(max > 1);

        let pos0 = rng.r#gen::<usize>() % max;

        loop {
            let pos1 = rng.r#gen::<usize>() % max;
            if pos0 != pos1 {
                return (pos0, pos1);
            }
        }
    }

    let rng = &mut test_rng();

    // Check that empty batches are accepted
    assert!(PublicKey::batch_verify(&[], &[], &[], rng).is_ok());

    for batch_size in (1..30).chain([50, 75, 100]) {
        let sk = (0..batch_size).map(|_| random_key(rng)).collect::<Vec<_>>();
        let mut pk = sk.iter().map(|k| k.public_key()).collect::<Vec<_>>();

        let mut msg = (0..batch_size)
            .map(|_| rng.r#gen::<[u8; 32]>())
            .collect::<Vec<_>>();
        let mut sigs = (0..batch_size)
            .map(|i| sk[i].sign_message(&msg[i]))
            .collect::<Vec<_>>();

        assert!(batch_verifies(&msg, &sigs, &pk, rng));

        // Corrupt a random signature and check that the batch fails:
        let corrupted_sig_idx = rng.r#gen::<usize>() % batch_size;
        let corrupted_sig_byte = rng.r#gen::<usize>() % 64;
        let corrupted_sig_mask = std::cmp::max(1, rng.r#gen::<u8>());
        sigs[corrupted_sig_idx][corrupted_sig_byte] ^= corrupted_sig_mask;
        assert!(!batch_verifies(&msg, &sigs, &pk, rng));

        // Uncorrupt the signature, then corrupt a random message, verify it fails:
        sigs[corrupted_sig_idx][corrupted_sig_byte] ^= corrupted_sig_mask;
        // We fixed the signature so the batch should verify again:
        debug_assert!(batch_verifies(&msg, &sigs, &pk, rng));

        let corrupted_msg_idx = rng.r#gen::<usize>() % batch_size;
        let corrupted_msg_byte = rng.r#gen::<usize>() % 32;
        let corrupted_msg_mask = std::cmp::max(1, rng.r#gen::<u8>());
        msg[corrupted_msg_idx][corrupted_msg_byte] ^= corrupted_msg_mask;
        assert!(!batch_verifies(&msg, &sigs, &pk, rng));

        // Fix the corrupted message
        msg[corrupted_msg_idx][corrupted_msg_byte] ^= corrupted_msg_mask;

        // Corrupt a random public key and check that the batch fails:
        let corrupted_pk_idx = rng.r#gen::<usize>() % batch_size;
        let correct_pk = pk[corrupted_pk_idx];
        let wrong_pk = random_key(rng).public_key();
        assert_ne!(correct_pk, wrong_pk);
        pk[corrupted_pk_idx] = wrong_pk;
        assert!(!batch_verifies(&msg, &sigs, &pk, rng));
        // Fix the corrupted public key
        pk[corrupted_pk_idx] = correct_pk;
        // We fixed the public key so the batch should verify again:
        debug_assert!(batch_verifies(&msg, &sigs, &pk, rng));

        if batch_size > 1 {
            // Swapping a key causes batch verification to fail:
            let (swap0, swap1) = two_positions(batch_size, rng);
            pk.swap(swap0, swap1);
            assert!(!batch_verifies(&msg, &sigs, &pk, rng));

            // If we swap (also) the message, verification still fails:
            msg.swap(swap0, swap1);
            assert!(!batch_verifies(&msg, &sigs, &pk, rng));

            // If we swap the signature so it is consistent, batch is accepted:
            sigs.swap(swap0, swap1);
            assert!(batch_verifies(&msg, &sigs, &pk, rng));
        }
    }
}

#[test]
fn test_der_public_key_conversions() {
    let test_data = [
        (
            hex!("b3997656ba51ff6da37b61d8d549ec80717266ecf48fb5da52b654412634844c"),
            hex!(
                "302a300506032b6570032100b3997656ba51ff6da37b61d8d549ec80717266ecf48fb5da52b654412634844c"
            ),
        ),
        (
            hex!("a5afb5feb6dfb6ddf5dd6563856fff5484f5fe304391d9ed06697861f220c610"),
            hex!(
                "302a300506032b6570032100a5afb5feb6dfb6ddf5dd6563856fff5484f5fe304391d9ed06697861f220c610"
            ),
        ),
    ];

    for (raw, der) in &test_data {
        let pk_raw = PublicKey::deserialize_raw(raw).unwrap();

        let pk_der = PublicKey::deserialize_rfc8410_der(der).unwrap();

        assert_eq!(pk_raw, pk_der);
        assert_eq!(pk_raw.serialize_rfc8410_der(), der);
        assert_eq!(pk_der.serialize_raw(), *raw);

        let pk_der_via_conversion = PublicKey::convert_raw_to_der(raw).unwrap();
        assert_eq!(pk_der_via_conversion, der);
    }
}

#[test]
fn can_parse_pkcs8_v1_der_secret_key() {
    let pkcs8_v1 = hex!(
        "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    );
    let sk = PrivateKey::deserialize_pkcs8(&pkcs8_v1).unwrap();

    assert_eq!(
        hex::encode(sk.serialize_raw()),
        "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    );
}

#[test]
fn can_parse_pkcs8_v2_ring_variant_secret_key() {
    let pkcs8 = r"-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIEzXNIZbPBAnqbrgkeDI3ox3e8rZkADmGkc0bYsj
cj1BoSMDIQD1+si816/7QQVbbOqgIFv+zizVvGq1QOMLg20pABvT8Q==
-----END PRIVATE KEY-----";

    let sk = PrivateKey::deserialize_pkcs8_pem(pkcs8).unwrap();

    assert_eq!(
        sk.serialize_pkcs8_pem(PrivateKeyFormat::Pkcs8v2WithRingBug)
            .replace("\r\n", ""),
        pkcs8.replace('\n', ""),
    );
}

#[test]
fn can_parse_pkcs8_v2_der_secret_key() {
    // From ring test data
    let pkcs8_v2 = hex!(
        "3051020101300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f4475584281210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    );

    let sk = PrivateKey::deserialize_pkcs8(&pkcs8_v2).unwrap();

    assert_eq!(
        hex::encode(sk.serialize_raw()),
        "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    );
}

#[test]
fn can_parse_dfx_created_private_key() {
    let dfx_key: &str = "-----BEGIN PRIVATE KEY-----\nMFMCAQEwBQYDK2VwBCIEIPXo8WUQM26wS/cT6mmHO1ClYHixF46uhRoQlLmPfsQl\noSMDIQAY6M8L0Ocji3w8k2EBMTwhVJT0G6HI1ZZmWrPOzv8L1Q==\n-----END PRIVATE KEY-----\n";

    match PrivateKey::deserialize_pkcs8_pem(dfx_key) {
        Ok(_sk) => { /* success */ }
        Err(e) => panic!("Unexpected error serializing DFX generated key {e:?}"),
    }
}

#[test]
fn can_pass_old_basic_sig_utils_parsing_tests() {
    struct PublicKeyParsingTest {
        raw: [u8; 32],
        der: [u8; 44],
        pem: String,
    }

    impl PublicKeyParsingTest {
        fn new(raw: [u8; 32], der: [u8; 44], pem: &'static str) -> Self {
            Self {
                raw,
                der,
                pem: pem.to_string(),
            }
        }
    }

    let tests = [
        PublicKeyParsingTest::new(
            hex!("B3997656BA51FF6DA37B61D8D549EC80717266ECF48FB5DA52B654412634844C"),
            hex!(
                "302A300506032B6570032100B3997656BA51FF6DA37B61D8D549EC80717266ECF48FB5DA52B654412634844C"
            ),
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAs5l2VrpR/22je2HY1UnsgHFyZuz0j7XaUrZUQSY0hEw=\n-----END PUBLIC KEY-----\n",
        ),
        PublicKeyParsingTest::new(
            hex!("A5AFB5FEB6DFB6DDF5DD6563856FFF5484F5FE304391D9ED06697861F220C610"),
            hex!(
                "302A300506032B6570032100A5AFB5FEB6DFB6DDF5DD6563856FFF5484F5FE304391D9ED06697861F220C610"
            ),
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEApa+1/rbftt313WVjhW//VIT1/jBDkdntBml4YfIgxhA=\n-----END PUBLIC KEY-----\n",
        ),
        PublicKeyParsingTest::new(
            hex!("C8413108F121CB794A10804D15F613E40ECC7C78A4EC567040DDF78467C71DFF"),
            hex!(
                "302A300506032B6570032100C8413108F121CB794A10804D15F613E40ECC7C78A4EC567040DDF78467C71DFF"
            ),
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyEExCPEhy3lKEIBNFfYT5A7MfHik7FZwQN33hGfHHf8=\n-----END PUBLIC KEY-----\n",
        ),
    ];

    for test in &tests {
        let from_raw = PublicKey::deserialize_raw(&test.raw).expect("Invalid public key (raw)");
        let from_der =
            PublicKey::deserialize_rfc8410_der(&test.der).expect("Invalid public key (DER)");
        let from_pem =
            PublicKey::deserialize_rfc8410_pem(&test.pem).expect("Invalid public key (PEM)");

        assert_eq!(from_raw, from_der);
        assert_eq!(from_raw, from_pem);

        assert_eq!(from_raw.serialize_raw(), test.raw);
        assert_eq!(from_der.serialize_raw(), test.raw);
        assert_eq!(from_pem.serialize_raw(), test.raw);
    }
}

#[test]
fn should_pass_wycheproof_test_vectors() {
    let test_set = wycheproof::eddsa::TestSet::load(wycheproof::eddsa::TestName::Ed25519)
        .expect("Unable to load tests");

    for test_group in test_set.test_groups {
        let pk = PublicKey::deserialize_raw(&test_group.key.pk).unwrap();

        for test in test_group.tests {
            let accept = pk.verify_signature(&test.msg, &test.sig).is_ok();

            if test.result == wycheproof::TestResult::Valid {
                assert!(accept);
            } else {
                assert!(!accept);
            }
        }
    }
}

#[test]
fn should_produce_expected_derived_public_keys() {
    fn check_derivation(
        path: &DerivationPath,
        key: [u8; 32],
        chain_code: [u8; 32],
        expected_key: [u8; 32],
        expected_chain_code: [u8; 32],
    ) {
        let key = PublicKey::deserialize_raw(&key).expect("Invalid key");

        let (dk, chain_code) = key.derive_subkey_with_chain_code(path, &chain_code);

        assert_eq!(hex::encode(dk.serialize_raw()), hex::encode(expected_key));
        assert_eq!(hex::encode(chain_code), hex::encode(expected_chain_code));
    }

    check_derivation(
        &DerivationPath::new_bip32(&[1]),
        hex!("931387a550eb4524a7af29381b938df38e76aeecac08e2cfaae4f4ca99bb4881"),
        [0u8; 32],
        hex!("6f3086e738ab5417c6e02504464f208a763f0fba0c4d7ade40694773b6c2273c"),
        hex!("d34e4e22d2c008ccc7e9bb9882fbc025a1e5516e3421d8e932dbc0be35f787a0"),
    );

    check_derivation(
        &DerivationPath::new_bip32(&[2]),
        hex!("6f3086e738ab5417c6e02504464f208a763f0fba0c4d7ade40694773b6c2273c"),
        hex!("d34e4e22d2c008ccc7e9bb9882fbc025a1e5516e3421d8e932dbc0be35f787a0"),
        hex!("8efb675fcaf45c93e785ff535e380d9019c876a7c5faed264b911f97ef34d838"),
        hex!("2562ad75c50708f8d20c442e48b3f8ee851570be256ef0a7060b9f755a837216"),
    );

    check_derivation(
        &DerivationPath::new_bip32(&[1, 2]),
        hex!("931387a550eb4524a7af29381b938df38e76aeecac08e2cfaae4f4ca99bb4881"),
        [0u8; 32],
        hex!("8efb675fcaf45c93e785ff535e380d9019c876a7c5faed264b911f97ef34d838"),
        hex!("2562ad75c50708f8d20c442e48b3f8ee851570be256ef0a7060b9f755a837216"),
    );
}

#[test]
fn private_derivation_is_compatible_with_public_derivation() {
    let rng = &mut test_rng();

    fn random_path<R: Rng>(rng: &mut R) -> DerivationPath {
        let l = 1 + rng.r#gen::<usize>() % 9;
        let path = (0..l).map(|_| rng.r#gen::<u32>()).collect::<Vec<u32>>();
        DerivationPath::new_bip32(&path)
    }

    for _ in 0..100 {
        let master_sk = random_key(rng);
        let master_pk = master_sk.public_key();

        let path = random_path(rng);

        let chain_code = rng.r#gen::<[u8; 32]>();

        let (derived_pk, cc_pk) = master_pk.derive_subkey_with_chain_code(&path, &chain_code);

        let (derived_sk, cc_sk) = master_sk.derive_subkey_with_chain_code(&path, &chain_code);

        assert_eq!(
            hex::encode(derived_pk.serialize_raw()),
            hex::encode(derived_sk.public_key().serialize_raw())
        );

        assert_eq!(hex::encode(cc_pk), hex::encode(cc_sk));

        let msg = rng.r#gen::<[u8; 32]>();
        let derived_sig = derived_sk.sign_message(&msg);

        assert!(derived_pk.verify_signature(&msg, &derived_sig).is_ok());
    }
}

#[test]
fn private_derivation_also_works_for_derived_keys() {
    let rng = &mut test_rng();

    for _ in 0..100 {
        let master_sk = random_key(rng);

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

        // We can't serialize the keys so instead compare their respective public keys
        assert_eq!(
            hex::encode(fsk.public_key().serialize_raw()),
            hex::encode(derived_sk.public_key().serialize_raw())
        );
    }
}

#[test]
fn public_key_accepts_but_can_detect_non_canonical_keys() {
    // The only non-canonical but torsion free points are 3 non-canonical
    // encodings of the identity element:

    const NON_CANONICAL: [[u8; 32]; 3] = [
        hex!("0100000000000000000000000000000000000000000000000000000000000080"),
        hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ];

    for nc in &NON_CANONICAL {
        let k = PublicKey::deserialize_raw(nc).unwrap();
        assert!(k.is_torsion_free());
        assert!(!k.is_canonical());
    }
}

#[test]
fn public_key_accepts_but_can_detect_keys_with_torsion_component() {
    const WITH_TORSION: [[u8; 32]; 18] = [
        hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
        hex!("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
        hex!("868b1e2248079aa8e24834a827ae8892ed0c826f87c897893cefffce3ac15242"),
        hex!("539903bdd44ecf43aa8ddcb730b1170be7879eab807b2f845754aa07001985bf"),
        hex!("5f44d0277fa2916ae1c7900ad094cff286a8163ee3aa20b4afe2ba91785389d6"),
        hex!("67867e99109b36830205573bcf3875f947ee473dc0d562786c7240ff8941d04d"),
        hex!("67fbbe649a6b8337006f8a2778e79d4f4e8e9c0a7042836eeaa60cb118e9841b"),
        hex!("dda5020fbe04b0ba7449157945718dfe20299f697b39681b03a5d0bec279ffae"),
        hex!("872d3823dcc001e354b09d618c70b2658cc3700c097514ae125cd14704c35a20"),
        hex!("92507296f36dd62d42b7e1306b99d02ffe19dea76f69cdaaf7211ce7f6c24fb9"),
        hex!("b93d302d6a2d629dee6e1415a00651c20e44c2545feb1914d7d41e4eecead522"),
        hex!("f41202b41dcda6410ffd5b8b5cd492b98986b60964d2f04aa1d963cdee64b7b0"),
        hex!("97766a5f4da3bb231935496300946d60bfbe04491750d1e23c4c8eceded274f4"),
        hex!("ae7ab64ec5821986bed36f98d4135cc047c9630c39b61b5f755678f818804eac"),
        hex!("05dd133d881cc14005f3cca6f5e759a8c7ea0bbfcef222e15bce904c70a4851b"),
        hex!("02ce23d0c026d9c95aecc36d5f40d7b7f505e29cad9c2014afd1f467ea15cf40"),
        hex!("ef164a8acaf9fde87b8dffb1b355f3dcefb857d76842720aefc1bfe26a0d9f2e"),
        hex!("4c95b17aa3870017da2b9e62d09689a8e9bb12a605093cba2fc2df02fde2fdbf"),
    ];

    for nc in &WITH_TORSION {
        let k = PublicKey::deserialize_raw(nc).unwrap();
        assert!(!k.is_torsion_free());
        assert!(k.is_canonical());
    }
}

#[test]
fn public_key_accepts_but_can_detect_non_canonical_keys_with_torsion_component() {
    const WITH_TORSION_AND_NON_CANONICAL: [[u8; 32]; 3] = [
        hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ];

    for nc in &WITH_TORSION_AND_NON_CANONICAL {
        let k = PublicKey::deserialize_raw(nc).unwrap();
        assert!(!k.is_torsion_free());
        assert!(!k.is_canonical());
    }
}

#[test]
#[cfg(feature = "rand")]
fn verification_follows_zip215() {
    let rng = &mut test_rng();

    // ZIP215 test data from https://github.com/zcash/zcash/blob/master/src/gtest/test_consensus.cpp#L119-L1298
    let zip215_str = include_str!("data/zip215.txt");

    let testcases = zip215_str
        .split('\n')
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.split(':')
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>()
        })
        .map(|s| {
            (
                ic_ed25519::PublicKey::deserialize_raw(&s[0]).unwrap(),
                s[1].clone(),
            )
        })
        .collect::<Vec<_>>();

    let msg = b"Zcash";

    // Test each signature individually
    for (pk, sig) in &testcases {
        assert!(pk.verify_signature(msg, sig).is_ok());
    }

    for n in 1..testcases.len() {
        let bmsg = vec![&msg[..]; n];

        // Choose n (signature,pk) pairs to validate
        let (bkeys, bsigs) = {
            let mut keys = vec![];
            let mut sigs = vec![];

            for _ in 0..n {
                // Note this intentionally allows repeats!
                let idx = rng.r#gen::<usize>() % testcases.len();
                keys.push(testcases[idx].0);
                sigs.push(&testcases[idx].1[..]);
            }

            (keys, sigs)
        };

        assert!(
            ic_ed25519::PublicKey::batch_verify(&bmsg[..], &bsigs[..], &bkeys[..], rng).is_ok()
        );
    }
}

#[test]
fn offline_key_derivation_matches_mainnet_for_key_1() {
    use std::str::FromStr;

    let canister_id = ic_ed25519::CanisterId::from_str("h5jwf-5iaaa-aaaan-qmvoa-cai").unwrap();
    let derivation_path = [hex!("ABCDEF").to_vec(), hex!("012345").to_vec()];

    let dpk = PublicKey::derive_mainnet_key(
        ic_ed25519::MasterPublicKeyId::Key1,
        &canister_id,
        &derivation_path,
    );

    assert_eq!(
        hex::encode(dpk.0.serialize_raw()),
        "43f0008b26564b6da51f585ad47669dfeb1db6d94d7dd216bd304fc1f5f5e997"
    );
}

#[test]
fn offline_key_derivation_matches_mainnet_for_test_key_1() {
    use std::str::FromStr;

    let canister_id = ic_ed25519::CanisterId::from_str("h5jwf-5iaaa-aaaan-qmvoa-cai").unwrap();
    let derivation_path = [
        "Hello".as_bytes().to_vec(),
        "Threshold".as_bytes().to_vec(),
        "Signatures".as_bytes().to_vec(),
    ];
    let dpk = PublicKey::derive_mainnet_key(
        ic_ed25519::MasterPublicKeyId::TestKey1,
        &canister_id,
        &derivation_path,
    );

    assert_eq!(
        hex::encode(dpk.0.serialize_raw()),
        "d9a2ce6a3cd33fe16dce37e045609e51ff516e93bb51013823d6d7a915e3cfb9"
    );
}

#[test]
fn offline_ecdsa_key_derivation_matches_pocketic_for_key_1() {
    use std::str::FromStr;

    let canister_id = ic_ed25519::CanisterId::from_str("uzt4z-lp777-77774-qaabq-cai").unwrap();
    let derivation_path = [];

    let dpk = PublicKey::derive_pocketic_key(
        ic_ed25519::PocketIcMasterPublicKeyId::Key1,
        &canister_id,
        &derivation_path,
    );

    assert_eq!(
        hex::encode(dpk.0.serialize_raw()),
        "f419977bb61ca6c95ae6ec5b58189ab82e2681f3dbc8fc5d09ce3c6f6103c107",
    );
}

#[test]
fn offline_ecdsa_key_derivation_matches_pocketic_for_test_key_1() {
    use std::str::FromStr;

    let canister_id = ic_ed25519::CanisterId::from_str("uzt4z-lp777-77774-qaabq-cai").unwrap();
    let derivation_path = [];

    let dpk = PublicKey::derive_pocketic_key(
        ic_ed25519::PocketIcMasterPublicKeyId::TestKey1,
        &canister_id,
        &derivation_path,
    );

    assert_eq!(
        hex::encode(dpk.0.serialize_raw()),
        "c4afcb035090ab7dcc6aae48ff7b7df1a3d1120a3d8cbdc37a8d280e5e36ea6a",
    );
}

#[test]
fn offline_ecdsa_key_derivation_matches_pocketic_for_dfx_test_key() {
    use std::str::FromStr;

    let canister_id = ic_ed25519::CanisterId::from_str("uzt4z-lp777-77774-qaabq-cai").unwrap();
    let derivation_path = [];

    let dpk = PublicKey::derive_pocketic_key(
        ic_ed25519::PocketIcMasterPublicKeyId::DfxTestKey,
        &canister_id,
        &derivation_path,
    );

    assert_eq!(
        hex::encode(dpk.0.serialize_raw()),
        "17eb4d719c3c27cdfd7505e38142de4cebea1fc64352aa8b7a41b3d9c6574915",
    );
}
