use ic_bls12_381::*;
use ic_vetkd_utils::*;
use rand::{Rng, SeedableRng};

mod test_utils;

#[test]
fn test_hkdf_test_vector() {
    // HKDF test vectors from wycheproof
    let test_vectors = [
        ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
        ("24aeff2645e3e0f5494a9a102778c43a", "", "d4cca5e416c3d9eb58bd562e922691daff76aa4d"),
        ("a23632e18ec76b59b1c87008da3f8a7e", "", "976d1590926ac35e28d7f1a29fe98a1f787703a71cee3cb2c10acb9cc1b56c0f21b55d5de37755a79b12"),
        ("a4748031a14d3e6aafe42aa20c568f5f", "", "03f5db41f4484ec9468648c9f2a7f73ec18386008691b0555a7eec165e2f8cc72a6e74fffafbfb1ead00a89ff80ba00a266a70fcac07364110c6f5707f5096aa"),
        ("fa4f94e9cdbf725c1ee98decddbe42ec06196116", "", "f32a552257d372b16c5d8c46e6c07dc9c33be9bc"),
        ("094db4e2eaae8fc9dca0d9bc14b29387fd476921", "", "41ae65892c3359f808e906bbc91c701f7e067b548e685bc02d5badad2799221bf313964f8307670d76a8"),
        ("bfbe4f1edace02b2a3afcaada5f319103996dec9", "", "93c737cdce4fe225839614393bc5ff6fd14390dc436ad6f9e13a7714e8b8b2d66cb690fd9a213c0e297ac96fda5d27e002cfc344964b86e78ff23c260cbcc82e"),
        ("7ef7d4f8c11d940471cf9a3048d66b3b3a3d9db9fed5f81419fe75dd50116f4e", "", "a370de1c822b8eb00645c18e32ad6a1f4bb17c9b"),
        ("1b6c7d5da045bf8bd4ac3083e8de2b90904bc7f7830bef876e355b74466cef91", "", "50dd5b5adbe96aa216f93c4cbb7d568d5141b3ef7214be885984629b93f07814870db846c3efc8c7db7f"),
        ("b9da242c02bfe79364aedd7a323692191092edb2094f112675c2609a387c3b21", "", "384c0ded57bf066d6665d88355aff9eab8cbd78c1c71af7b8334cde6536f21223aeddd5a84d278d5d73f5b536973575dd2993a4a857289c3b59861643c464c2c"),
    ];

    for (input, dst, expected) in &test_vectors {
        let computed = derive_symmetric_key(&hex::decode(input).unwrap(), dst, expected.len() / 2);
        assert_eq!(hex::encode(computed), *expected);
    }
}

#[test]
fn test_public_key_derivation() {
    let mpk = MasterPublicKey::deserialize(&hex::decode("9183b871aa141d15ba2efc5bc58a49cb6a167741364804617f48dfe11e0285696b7018f172dad1a87ed81abf27ea4c320995041e2ee4a47b2226a2439d92a38557a7e2a\
  cc72fd157283b20f1f37ba872be235214c6a9cbba1eb2ef39deec72a5").unwrap()).unwrap();

    let canister_id = b"test-canister-id";
    let context = b"test-context";

    let dk1 = mpk.derive_canister_key(canister_id);

    assert_eq!(hex::encode(dk1.serialize()),
               "af78a908589d332fc8b9d042807c483e73872e2aea7620bdb985b9289d5a99ebfd5ac0ec4844a4c542f6d0f12a716d941674953cef4f38dde601ce9792db8832557eaa051733c5541fa5017465d69b62cc4d93f2079fb8c050b4bd735ef75859");

    let dk2 = dk1.derive_sub_key(context);
    assert_eq!(hex::encode(dk2.serialize()),
                 "a20125b8cdfc57f71b6f67e557e82c1307c1af9f728573f3b682f3b1816684f3f6aed5d8dd40a309b457a25dab7d8a1416fc0e0973000321c0c1dd844d80a5708e81fdd8338ea6433f175992fa05ef343b1e7f89a09f3b5b7c0766ccb3c624cd");
}

#[test]
fn test_second_level_public_key_derivation() {
    let canister_key = DerivedPublicKey::deserialize(&hex::decode("8bf165ea580742abf5fd5123eb848aa116dcf75c3ddb3cd3540c852cf99f0c5394e72dfc2f25dbcb5f9220f251cd04040a508a0bcb8b2543908d6626b46f09d614c924c5deb63a9949338ae4f4ac436bd77f8d0a392fd29de0f392a009fa61f3").unwrap()).unwrap();

    // Empty context is a no-op
    assert_eq!(canister_key, canister_key.derive_sub_key(&[]));

    let context = b"test-context";
    let derived_key = canister_key.derive_sub_key(context);

    assert_eq!(hex::encode(derived_key.serialize()),
               "80b4f1e11766d32bed0ea4e8b05e82bf84519de4a63eca0213d9e3603a946ea2968150882d1e9508701f34048fcec80919b4f493a2a254fc13dc956f1d82c6b8e641f962e1c0342c95eb58e168327d5e51e9337627ac9f1aa93d2e3058a1ff09");
}

#[test]
fn protocol_flow_with_emulated_server_side() {
    use test_utils::*;

    let seed = rand::thread_rng().gen::<u64>();
    println!("seed {:?}", seed);

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);

    let derivation_context = DerivationContext::new(b"canister-id", b"context");
    let identity = rng.gen::<[u8; 32]>();

    let tsk_seed = rng.gen::<[u8; 32]>().to_vec();
    let tsk = TransportSecretKey::from_seed(tsk_seed).unwrap();

    let tpk_bytes: [u8; 48] = tsk.public_key().try_into().unwrap();
    let tpk = G1Affine::from_compressed(&tpk_bytes).unwrap();

    // Ordinarily the master secret key would be held as shares by
    // independent notes, with the encrypted key created by combining
    // shares. Here we simply create the master secret key and create
    // the combined encrypted key directly.

    let master_sk = random_scalar(&mut rng);
    let master_pk = G2Affine::from(G2Affine::generator() * master_sk);

    let (derived_public_key, _delta) = derivation_context.derive_key(&master_pk);

    let ek_bytes = create_encrypted_key(
        &mut rng,
        &master_pk,
        &master_sk,
        &tpk,
        &derivation_context,
        &identity,
    );

    let ek = EncryptedVetKey::deserialize(&ek_bytes).unwrap();

    let dpk_bytes = derived_public_key.to_compressed().to_vec();

    let dpk = DerivedPublicKey::deserialize(&dpk_bytes).unwrap();

    let vetkey = ek.decrypt_and_verify(&tsk, &dpk, &identity).unwrap();

    let msg = rng.gen::<[u8; 32]>().to_vec();
    let seed = rng.gen::<[u8; 32]>().to_vec();
    let ctext = IBECiphertext::encrypt(&dpk, &identity, &msg, &seed).unwrap();

    let ptext = ctext.decrypt(&vetkey).expect("IBE decryption failed");
    assert_eq!(ptext, msg);
}

#[test]
fn derivation_matches_expected_value() {
    let vetkey = VetKey::deserialize(&hex::decode("ad19676dd92f116db11f326ff0822f295d87cc00cf65d9f132b5a618bb7381e5b0c3cb814f15e4a0f015359dcfa8a1da").unwrap()).unwrap();

    let domain_sep = "ic-test-domain-sep";

    let key = vetkey.derive_symmetric_key(domain_sep, 32);
    assert_eq!(
        hex::encode(key),
        "3b7bd854033cdc119865ba3019dc1e35010fdaf90f8ff5c9cfe9d1d557dddb29"
    );
}

#[test]
fn protocol_flow_with_fixed_rng_has_expected_outputs() {
    let tsk = TransportSecretKey::from_seed(vec![0x42; 32]).unwrap();

    assert_eq!(
        hex::encode(tsk.serialize()),
        "763e63464c55014a26ac6825616867185cc7204283ca46bd34c1a1446e737b16"
    );

    assert_eq!(
        TransportSecretKey::deserialize(&tsk.serialize())
            .unwrap()
            .serialize(),
        tsk.serialize()
    );

    let tpk = tsk.public_key();

    assert_eq!(hex::encode(tpk),
               "911969d56f42875d37a92d7eaa5d43293eff9f9a20ba4c60523e70a695eaeadeb721659b52a49d74e67841ad19033a12");

    // generated by internal library:

    let dpk = DerivedPublicKey::deserialize(&hex::decode("972c4c6cc184b56121a1d27ef1ca3a2334d1a51be93573bd18e168f78f8fe15ce44fb029ffe8e9c3ee6bea2660f4f35e0774a35a80d6236c050fd8f831475b5e145116d3e83d26c533545f64b08464e4bcc755f990a381efa89804212d4eef5f").unwrap()).unwrap();

    let ek = EncryptedVetKey::deserialize(&hex::decode("b1a13757eaae15a3c8884fc1a3453f8a29b88984418e65f1bd21042ce1d6809b2f8a49f7326c1327f2a3921e8ff1d6c3adde2a801f1f88de98ccb40c62e366a279e7aec5875a0ce2f2a9f3e109d9cb193f0197eadb2c5f5568ee4d6a87e115910662e01e604087246be8b081fc6b8a06b4b0100ed1935d8c8d18d9f70d61718c5dba23a641487e72b3b25884eeede8feb3c71599bfbcebe60d29408795c85b4bdf19588c034d898e7fc513be8dbd04cac702a1672f5625f5833d063b05df7503").unwrap()).unwrap();

    let identity = hex::decode("6d657373616765").unwrap();

    let msg = hex::decode("f00f11").unwrap();
    let seed: [u8; 32] = [0u8; 32];
    let ctext = IBECiphertext::encrypt(&dpk, &identity, &msg, &seed).unwrap();

    let ctext_bytes = ctext.serialize();

    assert_eq!(hex::encode(&ctext_bytes),
               "4943204942450001a9937528bda5826cf5c7da77a5f5e46719a9748f4ea0aa491c8fba92081e5d55457ab36ec4f6335954c6d87987d0b28301bd8da166493bb537c842d20396da5a68cc9e9672fadedf1e311e0057fc906dfd37d1077ca027954c45336405e66e5e4b346b0f24bfd358a09de701654c1e0791741e4826396588440eee021df9b2399f7f98");

    assert_eq!(
        ctext,
        IBECiphertext::deserialize(&ctext_bytes).expect("Deserializing IBECiphertext failed")
    );

    let vetkey = ek.decrypt_and_verify(&tsk, &dpk, &identity).unwrap();

    assert_eq!(hex::encode(vetkey.signature_bytes()),
               "987db5406ce297e729c8564a106dc896943b00216a095fe9c5d32a16a330c02eb80e6f468ede83cde5462b5145b58f65");

    let ptext = ctext.decrypt(&vetkey).expect("IBE decryption failed");
    assert_eq!(ptext, msg);
}
