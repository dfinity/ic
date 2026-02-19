use hex_literal::hex;
use ic_bls12_381::*;
use ic_cdk::management_canister::{VetKDCurve, VetKDKeyId};
use ic_vetkeys::*;
use ic_vetkeys_test_utils::*;
use rand::Rng;

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
fn test_is_valid_transport_public_key() {
    assert!(!is_valid_transport_public_key_encoding(
        &hex::decode("F00F00F00F00").unwrap()
    ));
    assert!(is_valid_transport_public_key_encoding(&hex::decode("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb").unwrap()));
    assert!(is_valid_transport_public_key_encoding(&hex::decode("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()));
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
fn test_bls_signature_verification() {
    let dpk = DerivedPublicKey::deserialize(&hex::decode("972c4c6cc184b56121a1d27ef1ca3a2334d1a51be93573bd18e168f78f8fe15ce44fb029ffe8e9c3ee6bea2660f4f35e0774a35a80d6236c050fd8f831475b5e145116d3e83d26c533545f64b08464e4bcc755f990a381efa89804212d4eef5f").unwrap()).unwrap();

    let msg = b"message";
    let wrong_msg = b"wrong message";

    let signature = hex::decode("987db5406ce297e729c8564a106dc896943b00216a095fe9c5d32a16a330c02eb80e6f468ede83cde5462b5145b58f65").unwrap();

    assert!(verify_bls_signature(&dpk, msg, &signature));
    assert!(!verify_bls_signature(&dpk, wrong_msg, &signature));
}

#[test]
fn test_bls_signature_verification_using_identity() {
    // Check that the identity element is rejected as a public key

    let dpk =
        DerivedPublicKey::deserialize(&ic_bls12_381::G2Affine::identity().to_compressed()).unwrap();

    let msg = b"wrong message";

    let signature = ic_bls12_381::G1Affine::identity().to_compressed();

    assert!(!verify_bls_signature(&dpk, msg, &signature));
}

#[test]
fn test_derivation_using_test_key_1() {
    // This test data was generated on mainnet using test_key_1

    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "test_key_1".to_string(),
    };
    let test_key1 = MasterPublicKey::for_mainnet_key(&key_id).unwrap();

    let canister_id = candid::Principal::from_text("urq22-tyaaa-aaaag-audia-cai").unwrap();

    let canister_key = test_key1.derive_canister_key(canister_id.as_slice());

    assert_eq!(
        hex::encode(canister_key.serialize()),
        "8b961f06d392367e84136088971c4808b434e5d6b928b60fa6177f811db9930e4f2a911ef517db40f7e7897588ae0e2316500dbef3abf08ad7f63940af0cf816c2c1c234943c9bb6f4d53da121dceed093d118d0bd5552740da315eac3b59b0f",
    );

    let derived_key = canister_key.derive_sub_key(b"context-string");

    assert_eq!(
        hex::encode(derived_key.serialize()),
        "958a2700438db39cf848f99c80d4d1c0f42b5e6783c35abffe5acda4fdb09548a025fdf85aad8980fcf6e20c1082596310c2612a3f3034c56445ddfc32a0c3cd34a7d0fea8df06a2996c54e21e3f8361a6e633d706ff58e979858fe436c7edf3",
    );
}

#[test]
fn test_derivation_using_production_key() {
    // This test data was generated on mainnet using key_1

    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "key_1".to_string(),
    };
    let key1 = MasterPublicKey::for_mainnet_key(&key_id).unwrap();

    let canister_id = candid::Principal::from_text("urq22-tyaaa-aaaag-audia-cai").unwrap();

    let canister_key = key1.derive_canister_key(canister_id.as_slice());

    assert_eq!(
        hex::encode(canister_key.serialize()),
        "a4df5fb733dc53ba0b3f8dab3f7538b2f345052072f69a5749d630d9c2b2b1c4b00af09fa1d993e1ce533996961575ad027e058e2a279ab05271c115ef27d750b6b233f12bc9f1973b203e338d43b6a7617be58d5c7195dfb809d756413bc006",
    );

    let derived_key = canister_key.derive_sub_key(b"context-string");

    assert_eq!(
        hex::encode(derived_key.serialize()),
        "aa45fccb82432315e39fedb1b1f150d2e895fb1f7399cc593b826ac151b519f0966b92aef49a89efe60570ef325f0f7e1974ac3519d2e127a52c013e246aedbff2158bdd0bb9f26c763c88c0b8ec796f401d057eab276d0a34384a8a97b1937f",
    );
}

#[test]
fn test_derivation_using_pocketic_keys() {
    let test_vectors = [
        ("key_1", "899a951f6ec2f9a96759c554a6cb01fb1cb20b2f2f96a2d2c869221c04d3349c3be8d49c3257312aed031f430f15f7ef0f4d43adf11251015d70dd91ac07df50fb70818ece721a1d6a314204acddde55542902f5d0d95e2406a5ab1fad18349d"),
        ("test_key_1", "a60993fc46593728bd9b0a4ffb1fb9a662dd89b29c99fde36e403c311c8992e6eeb097b31174dd43f74e73fe10c190271193a4345490f64a41ce778a2f6e7c16804919e843ac72ff65bab959c53fa839c9fb3cb263e41498d17fb82704fe18bc"),
        ("dfx_test_key", "800424bea66b95b715f86a9bed06b1f60df98206a57235c3e0f2da4d485dc1c93c56eef54155d559ef45c757fb0444920620b932652f1d683fdbc57db98b5aeb8ba664a5e040cbdf4d685e4e236a7193d1bd5b0927204fab05fff4f61f26b358"),
    ];

    let canister_id = candid::Principal::from_text("uzt4z-lp777-77774-qaabq-cai").unwrap();

    for (key_id, expected) in &test_vectors {
        let context = format!("Test Derivation For PocketIC VetKD {}", key_id);

        let key_id = VetKDKeyId {
            curve: VetKDCurve::Bls12_381_G2,
            name: key_id.to_string(),
        };

        let mk = MasterPublicKey::for_pocketic_key(&key_id).unwrap();
        let canister_key = mk.derive_canister_key(canister_id.as_slice());
        let derived_key = canister_key.derive_sub_key(context.as_bytes());

        assert_eq!(hex::encode(derived_key.serialize()), *expected);
    }
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
    let mut rng = reproducible_rng();

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
    let seed = IbeSeed::random(&mut rng);
    let ctext = IbeCiphertext::encrypt(&dpk, &IbeIdentity::from_bytes(&identity), &msg, &seed);

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
    let seed = IbeSeed::from_bytes(&[0u8; 32]).unwrap();
    let ctext = IbeCiphertext::encrypt(&dpk, &IbeIdentity::from_bytes(&identity), &msg, &seed);

    let ctext_bytes = ctext.serialize();

    assert_eq!(hex::encode(&ctext_bytes),
               "4943204942450001a9937528bda5826cf5c7da77a5f5e46719a9748f4ea0aa491c8fba92081e5d55457ab36ec4f6335954c6d87987d0b28301bd8da166493bb537c842d20396da5a68cc9e9672fadedf1e311e0057fc906dfd37d1077ca027954c45336405e66e5e4b346b0f24bfd358a09de701654c1e0791741e4826396588440eee021df9b2399f7f98");

    assert_eq!(
        ctext,
        IbeCiphertext::deserialize(&ctext_bytes).expect("Deserializing IbeCiphertext failed")
    );

    let vetkey = ek.decrypt_and_verify(&tsk, &dpk, &identity).unwrap();

    assert_eq!(hex::encode(vetkey.signature_bytes()),
               "987db5406ce297e729c8564a106dc896943b00216a095fe9c5d32a16a330c02eb80e6f468ede83cde5462b5145b58f65");

    let ptext = ctext.decrypt(&vetkey).expect("IBE decryption failed");
    assert_eq!(ptext, msg);
}

#[test]
fn vrf_from_prod_can_be_verified() {
    let vrf_bytes = hex!("82c018756fc09660f19f9f4473820c8f047b9709e9371ae705175cb510efbfc610f0f61fb5ca8bba59e998249d466a818a62a9f32cb3dacc11941ea27256ac5b0ca710f8803d111f04b798677d9c54e127e63000c906a85bcb08c422fc81229d07a2554e7882308c6f1c3ecd07c3d72a465f741e4357144afe042c1e6d7f838ecc3f40c5e681e2b55032cfd689ebd17976726620696e707574");

    let vrf = VrfOutput::deserialize(&vrf_bytes).unwrap();

    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "key_1".to_string(),
    };
    let key1 = MasterPublicKey::for_mainnet_key(&key_id).unwrap();
    let canister_key = key1.derive_canister_key(&hex!("0000000000c0a0d00101"));
    let vrf_public_key = canister_key.derive_sub_key(b"vrf context");
    let input = "vrf input".as_bytes();

    assert_eq!(vrf.public_key().clone(), vrf_public_key);
    assert_eq!(vrf.input(), input);

    assert_eq!(
        hex::encode(vrf.output()),
        "a484fc1e8a2b0dca99beb6f4409370f5c6932a931e47a7625c3bfe9e1f9af37f"
    );
}

#[test]
fn aes_gcm_encryption() {
    let dkm = VetKey::deserialize(&hex!("ad19676dd92f116db11f326ff0822f295d87cc00cf65d9f132b5a618bb7381e5b0c3cb814f15e4a0f015359dcfa8a1da")).unwrap().as_derived_key_material();

    let test_message = b"stay calm, this is only a test";
    let domain_sep = "ic-test-domain-sep";
    let aad = b"some additional authenticated data";

    // Test string encryption path, then decryption

    let mut rng = reproducible_rng();

    let ctext = dkm
        .encrypt_message(test_message, domain_sep, aad, &mut rng)
        .unwrap();

    assert_eq!(
        dkm.decrypt_message(&ctext, domain_sep, aad).unwrap(),
        test_message,
    );

    // Test decryption of known ciphertext encrypted with the derived key

    // This checks the behavior for handling old versions that did not use a header or support AAD
    let fixed_ctext_old_format = hex!("476f440e30bb95fff1420ce41ba6a07e03c3fcc0a751cfb23e64a8dcb0fc2b1eb74e2d4768f5c4dccbf2526609156664046ad27a6e78bd93bb8b");

    assert_eq!(
        dkm.decrypt_message(&fixed_ctext_old_format, domain_sep, &[])
            .unwrap(),
        test_message,
    );

    // Test decryption of known ciphertext encrypted with the derived key
    let fixed_ctext = hex!("49432047434d76325dc1b0f5f8deec973adda66ce7cb9dc06118c738fae12027c5bae5b86e69ffd633ddfc0ea66c4df37b6e7e298d9f80170ec3d51c4238be9a63bd");

    assert_eq!(
        dkm.decrypt_message(&fixed_ctext, domain_sep, aad).unwrap(),
        test_message,
    );

    // Test decryption of various mutated or truncated ciphertexts: all should fail

    // Test sequentially flipping each bit

    for i in 0..ctext.len() * 8 {
        let mod_ctext = {
            let mut m = ctext.clone();
            m[i / 8] ^= 0x80 >> i % 8;
            m
        };

        assert!(dkm.decrypt_message(&mod_ctext, domain_sep, aad).is_err());
    }

    // Test sequentially flipping each bit of the associated data

    for i in 0..aad.len() * 8 {
        let mod_aad = {
            let mut a = aad.clone();
            a[i / 8] ^= 0x80 >> i % 8;
            a
        };

        assert!(dkm.decrypt_message(&ctext, domain_sep, &mod_aad).is_err());
    }

    // Test truncating

    for i in 0..ctext.len() - 1 {
        let mod_ctext = {
            let mut m = ctext.clone();
            m.truncate(i);
            m
        };

        assert!(dkm.decrypt_message(&mod_ctext, domain_sep, aad).is_err());
    }

    // Test appending random bytes

    for i in 1..32 {
        let mod_ctext = {
            use rand::RngCore;
            let mut m = ctext.clone();
            let mut extra = vec![0u8; i];
            rng.fill_bytes(&mut extra);
            m.extend_from_slice(&extra);
            m
        };

        assert!(dkm.decrypt_message(&mod_ctext, domain_sep, aad).is_err());
    }
}
