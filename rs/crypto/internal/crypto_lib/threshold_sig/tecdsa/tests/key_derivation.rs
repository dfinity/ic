use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;
use std::convert::{TryFrom, TryInto};

#[allow(dead_code)]
mod test_utils;

use crate::test_utils::*;
use assert_matches::assert_matches;

#[test]
fn verify_bip32_extended_key_derivation_max_length_enforced() -> Result<(), ThresholdEcdsaError> {
    let nodes = 3;
    let threshold = nodes / 3;

    let seed = Seed::from_bytes(b"verify_bip32_extended_key_derivation_max_length");

    let setup = EcdsaSignatureProtocolSetup::new(
        TestConfig::new(EccCurveType::K256),
        nodes,
        threshold,
        threshold,
        seed,
        true,
    )?;

    for i in 0..=255 {
        let path = vec![i as u32; i];
        assert_matches!(setup.public_key(&DerivationPath::new_bip32(&path)), Ok(_));
    }

    for i in 256..1024 {
        let path = vec![i as u32; i];
        assert_matches!(
            setup.public_key(&DerivationPath::new_bip32(&path)),
            Err(ThresholdEcdsaError::InvalidArguments(_))
        );
    }

    Ok(())
}

#[test]
fn check_key_derivation_slip_0010_test_vectors() {
    // From https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vectors
    //
    // This only includes tests where the derivation was non-hardened since we do not
    // support hardened derivation

    struct Slip10Test {
        path: Vec<DerivationIndex>,
        chain_code: [u8; 32],
        public_key: EccPoint,
        private_key: EccScalar,
        expected_chain_code: [u8; 32],
        expected_public_key: EccPoint,
        expected_private_key: EccScalar,
    }

    impl Slip10Test {
        fn decode_scalar(curve: EccCurveType, hex: &'static str) -> EccScalar {
            let bits = hex::decode(hex).expect("Invalid hex");
            EccScalar::deserialize(curve, &bits).expect("Invalid scalar")
        }

        fn decode_point(curve: EccCurveType, hex: &'static str) -> EccPoint {
            let bits = hex::decode(hex).expect("Invalid hex");
            EccPoint::deserialize(curve, &bits).expect("Invalid point")
        }

        fn decode_chain_code(hex: &'static str) -> [u8; 32] {
            let bits = hex::decode(hex).expect("Invalid hex");
            bits.try_into().expect("Invalid chain code")
        }

        fn new(
            curve: EccCurveType,
            path: &[u32],
            chain_code: &'static str,
            private_key: &'static str,
            public_key: &'static str,
            expected_chain_code: &'static str,
            expected_private_key: &'static str,
            expected_public_key: &'static str,
        ) -> Self {
            let chain_code = Self::decode_chain_code(chain_code);
            let public_key = Self::decode_point(curve, public_key);
            let private_key = Self::decode_scalar(curve, private_key);

            let expected_chain_code = Self::decode_chain_code(expected_chain_code);
            let expected_private_key = Self::decode_scalar(curve, expected_private_key);
            let expected_public_key = Self::decode_point(curve, expected_public_key);

            let path = path
                .iter()
                .map(|p| DerivationIndex(p.to_be_bytes().to_vec()))
                .collect::<Vec<_>>();

            Self {
                path,
                chain_code,
                public_key,
                private_key,
                expected_chain_code,
                expected_public_key,
                expected_private_key,
            }
        }
    }

    let slip10_tests = [
        Slip10Test::new(
            EccCurveType::K256,
            &[1],
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
        ),
        Slip10Test::new(
            EccCurveType::K256,
            &[2],
            "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
            "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
            "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
            "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
            "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
        ),
        Slip10Test::new(
            EccCurveType::K256,
            &[2, 1000000000],
            "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
            "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
            "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
            "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
        ),
        Slip10Test::new(
            EccCurveType::P256,
            &[1],
            "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11",
            "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c",
            "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c",
            "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c",
            "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129",
            "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844",
        ),
        Slip10Test::new(
            EccCurveType::P256,
            &[2],
            "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318",
            "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7",
            "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0",
            "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0",
            "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa",
            "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20",
        ),
        Slip10Test::new(
            EccCurveType::P256,
            &[2, 1000000000],
            "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318",
            "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7",
            "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0",
            "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059",
            "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119",
            "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4",
        ),
        Slip10Test::new(
            EccCurveType::K256,
            &[0],
            "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
            "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
            "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
            "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
            "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
            "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
        ),
        Slip10Test::new(
            EccCurveType::K256,
            &[1],
            "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
            "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
            "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
            "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
            "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
            "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
        ),
        Slip10Test::new(
            EccCurveType::K256,
            &[2],
            "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
            "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
            "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
            "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
            "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
            "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
        ),
        Slip10Test::new(
            EccCurveType::P256,
            &[0],
            "96cd4465a9644e31528eda3592aa35eb39a9527769ce1855beafc1b81055e75d",
            "eaa31c2e46ca2962227cf21d73a7ef0ce8b31c756897521eb6c7b39796633357",
            "02c9e16154474b3ed5b38218bb0463e008f89ee03e62d22fdcc8014beab25b48fa",
            "84e9c258bb8557a40e0d041115b376dd55eda99c0042ce29e81ebe4efed9b86a",
            "d7d065f63a62624888500cdb4f88b6d59c2927fee9e6d0cdff9cad555884df6e",
            "039b6df4bece7b6c81e2adfeea4bcf5c8c8a6e40ea7ffa3cf6e8494c61a1fc82cc",
        ),
        Slip10Test::new(
            EccCurveType::P256,
            &[1],
            "f235b2bc5c04606ca9c30027a84f353acf4e4683edbd11f635d0dcc1cd106ea6",
            "96d2ec9316746a75e7793684ed01e3d51194d81a42a3276858a5b7376d4b94b9",
            "02f89c5deb1cae4fedc9905f98ae6cbf6cbab120d8cb85d5bd9a91a72f4c068c76",
            "7c0b833106235e452eba79d2bdd58d4086e663bc8cc55e9773d2b5eeda313f3b",
            "974f9096ea6873a915910e82b29d7c338542ccde39d2064d1cc228f371542bbc",
            "03abe0ad54c97c1d654c1852dfdc32d6d3e487e75fa16f0fd6304b9ceae4220c64",
        ),
        Slip10Test::new(
            EccCurveType::P256,
            &[2],
            "5794e616eadaf33413aa309318a26ee0fd5163b70466de7a4512fd4b1a5c9e6a",
            "da29649bbfaff095cd43819eda9a7be74236539a29094cd8336b07ed8d4eff63",
            "03cb8cb067d248691808cd6b5a5a06b48e34ebac4d965cba33e6dc46fe13d9b933",
            "3bfb29ee8ac4484f09db09c2079b520ea5616df7820f071a20320366fbe226a7",
            "bb0a77ba01cc31d77205d51d08bd313b979a71ef4de9b062f8958297e746bd67",
            "020ee02e18967237cf62672983b253ee62fa4dd431f8243bfeccdf39dbe181387f",
        ),
        Slip10Test::new(
            EccCurveType::P256,
            &[33941],
            "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2",
            "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669",
            "02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7",
            "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071",
            "092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a",
            "0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120",
        ),
    ];

    for test in &slip10_tests {
        let path = DerivationPath::new(test.path.clone());

        let (tweak, chain_code) = path
            .derive_tweak_with_chain_code(&test.public_key, &test.chain_code)
            .expect("Derivation failed");

        assert_eq!(
            hex::encode(chain_code),
            hex::encode(test.expected_chain_code)
        );

        let derived_private = test
            .private_key
            .add(&tweak)
            .expect("Scalar addition failed");

        assert_eq!(derived_private, test.expected_private_key);

        assert_eq!(
            EccPoint::mul_by_g(&derived_private),
            test.expected_public_key
        );
    }
}

#[test]
fn verify_bip32_secp256k1_extended_key_derivation() -> Result<(), ThresholdEcdsaError> {
    let nodes = 10;
    let threshold = nodes / 3;

    let seed = Seed::from_bytes(b"verify_bip32_extended_key_derivation");

    let setup = EcdsaSignatureProtocolSetup::new(
        TestConfig::new(EccCurveType::K256),
        nodes,
        threshold,
        threshold,
        seed,
        true,
    )?;

    let master_key = setup.public_key(&DerivationPath::new(vec![]))?;
    assert_eq!(
        hex::encode(master_key.public_key),
        "02bef39a470a0fe179cd18509a791e9c5312c07d1346a223a93f723fd90c9690f2"
    );
    assert_eq!(
        hex::encode(master_key.chain_key),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

    let index1 = DerivationIndex(vec![1, 2, 3, 4, 5]);
    let index2 = DerivationIndex(vec![8, 0, 2, 8, 0, 2]);

    let key = setup.public_key(&DerivationPath::new(vec![index1.clone()]))?;
    assert_eq!(
        hex::encode(key.public_key),
        "026b299d834bbb242a961192ba5a1d5663b5fa8d76d88aff93fd2a6044a524ce70"
    );
    assert_eq!(
        hex::encode(key.chain_key),
        "5b37a4f4f656bbe83497232deab1be3a468535ca55c296f123ee8339d56100f5"
    );

    let key = setup.public_key(&DerivationPath::new(vec![index2.clone()]))?;
    assert_eq!(
        hex::encode(key.public_key),
        "03bbe7150acce76b3d155a840a5096e334cddc6a129bd3d481a200518efa066098"
    );
    assert_eq!(
        hex::encode(key.chain_key),
        "68db4ee9e71a592c463e70202b4d49f4408530a7e783c43625360956e6180052"
    );

    let key = setup.public_key(&DerivationPath::new(vec![index1, index2]))?;
    assert_eq!(
        hex::encode(key.public_key),
        "02acd25bb5fbd517e5141aa5bc9b58554a96b9e9436bb285abb2090598cdcf850e"
    );
    assert_eq!(
        hex::encode(key.chain_key),
        "8e808ba4caebadca661fd647fcc8ab5e80a1b538b7ffee7bccf3f3a01a35d19e"
    );

    Ok(())
}

#[test]
fn should_secp256k1_derivation_match_external_bip32_lib() -> Result<(), ThresholdEcdsaError> {
    let nodes = 7;
    let threshold = nodes / 3;

    let rng = &mut reproducible_rng();
    let random_seed = Seed::from_rng(rng);

    let setup = EcdsaSignatureProtocolSetup::new(
        TestConfig::new(EccCurveType::K256),
        nodes,
        threshold,
        threshold,
        random_seed,
        true,
    )?;

    // zeros the high bit to avoid requesting hardened derivation, which we do not support
    let path = (0..255)
        .map(|_| rng.gen::<u32>() & 0x7FFFFFFF)
        .collect::<Vec<u32>>();

    let master_key = setup.public_key(&DerivationPath::new_bip32(&[]))?;

    let mut derived_keys = Vec::with_capacity(path.len());
    for i in 1..=path.len() {
        let pk = setup.public_key(&DerivationPath::new_bip32(&path[..i]))?;
        derived_keys.push(pk);
    }

    let attrs = bip32::ExtendedKeyAttrs {
        depth: 0,
        parent_fingerprint: [0u8; 4],
        child_number: bip32::ChildNumber(0),
        chain_code: master_key.chain_key.try_into().expect("Unexpected size"),
    };

    let ext = bip32::ExtendedKey {
        prefix: bip32::Prefix::XPUB,
        attrs,
        key_bytes: master_key.public_key.try_into().expect("Unexpected size"),
    };

    let bip32_mk = bip32::XPub::try_from(ext).expect("Failed to accept BIP32");

    let mut bip32_state = bip32_mk.clone();
    for (i, p) in path.iter().enumerate() {
        let derived = bip32_state
            .derive_child(bip32::ChildNumber(*p))
            .expect("Failed to derive child");
        assert_eq!(derived.to_bytes().to_vec(), derived_keys[i].public_key);
        bip32_state = derived;
    }

    Ok(())
}

#[test]
fn key_derivation_on_unsupported_alg_fails() {
    let mpk = ic_types::crypto::canister_threshold_sig::MasterEcdsaPublicKey {
        algorithm_id: ic_types::crypto::AlgorithmId::Secp256k1,
        public_key: vec![0x42; 64],
    };

    let path = DerivationPath::new_bip32(&[1, 2, 3]);

    let derived = ic_crypto_internal_threshold_sig_ecdsa::derive_ecdsa_public_key(&mpk, &path);

    assert_matches!(
        derived,
        Err(ThresholdEcdsaDerivePublicKeyError::InvalidArgument(_))
    );
}
