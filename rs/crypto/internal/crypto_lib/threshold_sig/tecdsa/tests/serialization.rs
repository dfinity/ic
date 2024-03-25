use ic_crypto_internal_threshold_sig_ecdsa::*;
use rand::Rng;
use std::collections::BTreeMap;

mod test_utils;

use crate::test_utils::*;

fn verify_data(tag: String, expected_hash: &str, serialized: &[u8]) {
    /*
    Should updating the values in this test be required (eg because you have
    *intentionally* made a change which changed the serialization of some of the
    tECDSA artifacts), then set UPDATING_TEST_VECTORS to true, and then run

    $ cargo test verify_protocol_output_remains_unchanged_over_time -- --nocapture | grep ^perl | parallel -j1

    which will update this file with the produced values.
     */

    const UPDATING_TEST_VECTORS: bool = false;

    let hash = ic_crypto_sha2::Sha256::hash(serialized);
    let computed_hash = hex::encode(&hash[0..8]);

    if !UPDATING_TEST_VECTORS {
        assert_eq!(computed_hash, expected_hash, "{}", tag);
    } else if computed_hash != expected_hash {
        println!(
            "perl -pi -e s/{}/{}/g tests/serialization.rs",
            expected_hash, computed_hash
        );
    }
}

fn check_dealings(
    name: &'static str,
    round: &ProtocolRound,
    commitment_hash: &'static str,
    transcript_hash: &'static str,
    dealing_hashes: &[&'static str],
) -> ThresholdEcdsaResult<()> {
    verify_data(
        format!("{} commitment", name),
        commitment_hash,
        &round.commitment.serialize().expect("Serialization failed"),
    );

    verify_data(
        format!("{} transcript", name),
        transcript_hash,
        &round.transcript.serialize().expect("Serialization failed"),
    );

    assert_eq!(round.dealings.len(), dealing_hashes.len());

    for (dealer_index, hash) in dealing_hashes.iter().enumerate() {
        let dealer_index = dealer_index as u32;
        let dealing = round.dealings.get(&dealer_index).expect("Missing dealing");
        verify_data(
            format!("{} dealing {}", name, dealer_index),
            hash,
            &dealing.serialize().expect("Serialization failed"),
        );
    }

    Ok(())
}

fn check_shares(
    shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
    hashes: &[&'static str],
) -> ThresholdEcdsaResult<()> {
    assert_eq!(shares.len(), hashes.len());

    for (index, hash) in hashes.iter().enumerate() {
        let index = index as u32;
        let share = shares.get(&index).expect("Unable to find signature share");
        verify_data(
            format!("share {}", index),
            hash,
            &share.serialize().expect("Serialization failed"),
        )
    }

    Ok(())
}

#[test]
fn verify_protocol_output_remains_unchanged_over_time_k256() -> Result<(), ThresholdEcdsaError> {
    let nodes = 5;
    let threshold = 2;

    let seed = Seed::from_bytes(b"ic-crypto-tecdsa-fixed-seed");

    let setup = EcdsaSignatureProtocolSetup::new(
        TestConfig::new(EccCurveType::K256),
        nodes,
        threshold,
        0,
        seed.derive("setup"),
        true,
    )?;

    check_dealings(
        "key",
        &setup.key,
        "807f3b29bcc421d0",
        "623080845e685b35",
        &[
            "e7b8624cab606930",
            "cddb63df18157ad5",
            "0ac600f863097584",
            "4dac6c3962e19dce",
            "cedbbc9aaaf2d96d",
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "bd4aef1e3a7e276c",
        "4b7f2a867ae0bcc9",
        &[
            "22ac5e63a4173871",
            "18886ac194f10ad5",
            "d94fdc34c13dd05d",
            "08358b27f6b1a468",
            "7a98c577d0d60157",
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "aba9665ec91be63f",
        "f1ad398f50c227bb",
        &[
            "50263c87c5e40a97",
            "b373947bc56351f1",
            "89a5675e9da945c1",
            "f29909f897055378",
            "54dc1c1d08b43c1c",
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "edb74de7f815bac2",
        "bc499e84a8fcc8f7",
        &[
            "d995b6d7b09b03e5",
            "93a704077bfdcee3",
            "8142af1b57f13b37",
            "d334beb1a1c7eecd",
            "83ac317a94224d0b",
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "2e1b78f8e8eeed00",
        "9857c340a75e717a",
        &[
            "a7ea009231aae6d7",
            "d915e472ed668d5e",
            "f40eba254efcd63d",
            "2198c38ec025e544",
            "4d3a0efca97fbab1",
        ],
    )?;

    let signed_message = seed.derive("message").into_rng().gen::<[u8; 32]>().to_vec();
    let random_beacon =
        ic_types::Randomness::from(seed.derive("beacon").into_rng().gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto =
        EcdsaSignatureProtocolExecution::new(setup, signed_message, random_beacon, derivation_path);

    let shares = proto.generate_shares()?;

    check_shares(
        &shares,
        &[
            "a5828d246e927eae",
            "b5add43f02086e16",
            "743a39c677fc02d3",
            "d4d7a73a628c8391",
            "4dfe21a4e768bda5",
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "ebe9b02e33da8224",
        &sig.serialize(),
    );

    Ok(())
}

#[test]
fn verify_protocol_output_remains_unchanged_over_time_k256_unmasked_kappa(
) -> Result<(), ThresholdEcdsaError> {
    let nodes = 5;
    let threshold = 2;

    let seed =
        Seed::from_bytes(b"ic-crypto-tecdsa-fixed-seed-for-k256-unmasked-kappa-stability-test");

    let setup = EcdsaSignatureProtocolSetup::new(
        TestConfig::new(EccCurveType::K256),
        nodes,
        threshold,
        0,
        seed.derive("setup"),
        false,
    )?;

    check_dealings(
        "key",
        &setup.key,
        "1b695972da7debde",
        "22fcea8c0b62da6e",
        &[
            "50eade001e4e500d",
            "b7468e47e9655612",
            "d2095feb23ce69be",
            "febf1231ec7b471d",
            "6a19d4d84271c84d",
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "62f61c35bb158b28",
        "bb9af35cf798c16c",
        &[
            "23ee5214cece25c7",
            "e7554ad26b724d9c",
            "7d117762d84e6506",
            "7ddc803ebfd2c803",
            "5ff448f7caf2d9b9",
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "ef762c6d78ea2747",
        "02241969d18660c2",
        &[
            "2e7381433a40d8a3",
            "1ebc787d67fe4612",
            "417fee2675869184",
            "bfb773afcf6e453e",
            "0e803f76e66b94d6",
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "6795262920893111",
        "75b2650561454923",
        &[
            "eb7ce60afb0ee13c",
            "3a020856c02b2412",
            "adb24da2a8637048",
            "f08b9cbcdbda9c00",
            "a57e5b2f50b291c5",
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "22f4337015cdd35c",
        "9ca0f07c390e7a2e",
        &[
            "4a437e07606d6b01",
            "e828202ec39da0df",
            "f1cccd204a254464",
            "55d2ad653ba83f1d",
            "8c27d75099421f6b",
        ],
    )?;

    let signed_message = seed.derive("message").into_rng().gen::<[u8; 32]>().to_vec();
    let random_beacon =
        ic_types::Randomness::from(seed.derive("beacon").into_rng().gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto =
        EcdsaSignatureProtocolExecution::new(setup, signed_message, random_beacon, derivation_path);

    let shares = proto.generate_shares()?;

    check_shares(
        &shares,
        &[
            "ce80c75481040807",
            "7b3ad01f1a8ecfdf",
            "723003552d3e75a3",
            "da03420ba1b2aeab",
            "aac3b74631ed4210",
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "8ca9653e88075122",
        &sig.serialize(),
    );

    Ok(())
}

#[test]
fn verify_protocol_output_remains_unchanged_over_time_p256() -> Result<(), ThresholdEcdsaError> {
    let nodes = 5;
    let threshold = 2;

    let seed = Seed::from_bytes(b"ic-crypto-tecdsa-fixed-seed-for-p256-stability-test");

    let setup = EcdsaSignatureProtocolSetup::new(
        TestConfig::new(EccCurveType::P256),
        nodes,
        threshold,
        0,
        seed.derive("setup"),
        true,
    )?;

    check_dealings(
        "key",
        &setup.key,
        "dc918ee1d73355e5",
        "f8bbd6baf59737c6",
        &[
            "e86a88a44f693f00",
            "f46e7cef32a25a0b",
            "b9498502dabac019",
            "afee7214cc5f3699",
            "91ee02132762390d",
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "d80ba060e9d626ee",
        "19d079d4653de58a",
        &[
            "89edf2b0c56e2973",
            "62737b2926c8459c",
            "657fe16995b9e60d",
            "19bbaa2ec157b080",
            "b5f00531d057abe2",
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "526fc2021f8437b9",
        "fcf8db82d75a2721",
        &[
            "cc8222bf553ba800",
            "80d9b8d52a64060d",
            "56ebb454140f84d0",
            "a14f4e83ca79ec5f",
            "356a4e85b188afb9",
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "5ac536fcb96011e7",
        "9ee8551c0a991ace",
        &[
            "191bd6e1a3049b2d",
            "23c892f03b2b6681",
            "5119183f814da146",
            "010eb6aa49124a01",
            "f1ec18388ea33870",
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "d147b2e286a0601f",
        "39eee21a5fca606b",
        &[
            "d1f72446c7d1e70d",
            "9a2d6e1f48c38cfb",
            "77a2e31612dc689d",
            "b726a8253f12e6b0",
            "1c4624d5b02e91f9",
        ],
    )?;

    let signed_message = seed.derive("message").into_rng().gen::<[u8; 32]>().to_vec();
    let random_beacon =
        ic_types::Randomness::from(seed.derive("beacon").into_rng().gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto =
        EcdsaSignatureProtocolExecution::new(setup, signed_message, random_beacon, derivation_path);

    let shares = proto.generate_shares()?;

    check_shares(
        &shares,
        &[
            "dcd41127ca62253e",
            "d14ed8886a1cb164",
            "bb8bbcd522414b82",
            "e63f19db064fd61b",
            "83033dc640e40a83",
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "751198d811154531",
        &sig.serialize(),
    );

    Ok(())
}

#[test]
fn verify_protocol_output_remains_unchanged_over_time_p256_sig_with_k256_mega(
) -> Result<(), ThresholdEcdsaError> {
    let nodes = 5;
    let threshold = 2;

    let seed = Seed::from_bytes(b"ic-crypto-tecdsa-fixed-seed-for-p256-sig-and-k256-mega");

    let setup = EcdsaSignatureProtocolSetup::new(
        TestConfig::new_mixed(EccCurveType::P256, EccCurveType::K256),
        nodes,
        threshold,
        0,
        seed.derive("setup"),
        true,
    )?;

    check_dealings(
        "key",
        &setup.key,
        "4d9040a1feeec927",
        "4bf89efcb451357e",
        &[
            "1a2aaa14df6a9f94",
            "3ae09ff1b237fa72",
            "671cd863a272c52d",
            "5f06286179bddad7",
            "ddaeec0c1c078794",
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "7a73f78ed62eef95",
        "0fddc53737adbdfe",
        &[
            "dd0502015735bc00",
            "4ecb20719862a1e5",
            "2b468d8042cd0610",
            "f7732f23ce42839a",
            "c6c51f23968c9eed",
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "e8b34856638342f4",
        "95c003633b20c504",
        &[
            "9495b2456e5ef5b6",
            "b1816dc6a89c4f76",
            "9b125b5fdbfaa750",
            "59b0cd35f87e8928",
            "cc9f2d420f2c208b",
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "71fe8d76f790e4d9",
        "f0e92fcf6ad2623f",
        &[
            "697115459c795774",
            "3139ee79fe726241",
            "e5dda8ab6919d7f4",
            "13100f6d0cfe9e12",
            "7907d0f49a92df09",
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "956b943e0c856668",
        "e3751d0d2a9b3bc7",
        &[
            "a6798556cb3a72b7",
            "aec9625b6ca14d07",
            "f7c40b4cec507004",
            "44ac292c7e9185b9",
            "89c3575da08a7e09",
        ],
    )?;

    let signed_message = seed.derive("message").into_rng().gen::<[u8; 32]>().to_vec();
    let random_beacon =
        ic_types::Randomness::from(seed.derive("beacon").into_rng().gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto =
        EcdsaSignatureProtocolExecution::new(setup, signed_message, random_beacon, derivation_path);

    let shares = proto.generate_shares()?;

    check_shares(
        &shares,
        &[
            "ec49c07026fad455",
            "204a07eaecef9521",
            "395636ecd1a40ee0",
            "d4c1a235edb058d4",
            "074a90109c969974",
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "b1522949be1e9cab",
        &sig.serialize(),
    );

    Ok(())
}

#[test]
fn verify_fixed_serialization_continues_to_be_accepted() -> Result<(), ThresholdEcdsaError> {
    let dealing_bits = [
        include_str!("data/dealing_random.hex"),
        include_str!("data/dealing_random_unmasked.hex"),
        include_str!("data/dealing_reshare_of_masked.hex"),
        include_str!("data/dealing_reshare_of_unmasked.hex"),
        include_str!("data/dealing_multiply.hex"),
    ];

    for dealing_encoding in dealing_bits {
        let dealing_encoding = hex::decode(dealing_encoding).expect("Invalid hex");
        let _dealing = IDkgDealingInternal::deserialize(&dealing_encoding)
            .expect("Was unable to deserialize a fixed dealing encoding");
    }

    let transcript_bits = [
        include_str!("data/transcript_random.hex"),
        include_str!("data/transcript_random_unmasked.hex"),
        include_str!("data/transcript_reshare_of_masked.hex"),
        include_str!("data/transcript_reshare_of_unmasked.hex"),
        include_str!("data/transcript_multiply.hex"),
    ];

    for transcript_encoding in transcript_bits {
        let transcript_encoding = hex::decode(transcript_encoding).expect("Invalid hex");
        let _transcript = IDkgTranscriptInternal::deserialize(&transcript_encoding)
            .expect("Was unable to deserialize a fixed transcript encoding");
    }

    let opening_bits = [
        include_str!("data/opening_simple.hex"),
        include_str!("data/opening_pedersen.hex"),
    ];

    for opening_encoding in opening_bits {
        let opening_encoding = hex::decode(opening_encoding).expect("Invalid hex");
        let _opening = CommitmentOpening::deserialize(&opening_encoding)
            .expect("Was unable to deserialize a fixed opening encoding");
    }

    let complaint_bits = [include_str!("data/complaint.hex")];

    for complaint_encoding in complaint_bits {
        let complaint_encoding = hex::decode(complaint_encoding).expect("Invalid hex");
        let _complaint = IDkgComplaintInternal::deserialize(&complaint_encoding)
            .expect("Was unable to deserialize a fixed complaint encoding");
    }

    let sig_share_bits = [include_str!("data/sig_share.hex")];

    for sig_share_encoding in sig_share_bits {
        let sig_share_encoding = hex::decode(sig_share_encoding).expect("Invalid hex");
        let _sig_share = ThresholdEcdsaSigShareInternal::deserialize(&sig_share_encoding)
            .expect("Was unable to deserialize a fixed sig_share encoding");
    }

    Ok(())
}

#[test]
fn mega_k256_keyset_serialization_is_stable() -> Result<(), ThresholdEcdsaError> {
    let seed = Seed::from_bytes(b"ic-crypto-k256-keyset-serialization-stability-test");

    let (pk, sk) = gen_keypair(EccCurveType::K256, seed);

    assert_eq!(
        hex::encode(sk.serialize()),
        "3ec1862141d91394894af980fff6280d84794a224615bf3ad96caaf416d9471c"
    );
    assert_eq!(
        hex::encode(pk.serialize()),
        "0281c5d1fa035eed47bc3149dd91127d99d15121a1be3c22ca268150b4a9997d6f"
    );

    let sk_bytes = MEGaPrivateKeyK256Bytes::try_from(&sk).expect("Deserialization failed");

    let pk_bytes = MEGaPublicKeyK256Bytes::try_from(&pk).expect("Deserialization failed");

    assert_eq!(
        hex::encode(serde_cbor::to_vec(&sk_bytes).unwrap()),
        "58203ec1862141d91394894af980fff6280d84794a224615bf3ad96caaf416d9471c"
    );

    assert_eq!(
        hex::encode(serde_cbor::to_vec(&pk_bytes).unwrap()),
        "58210281c5d1fa035eed47bc3149dd91127d99d15121a1be3c22ca268150b4a9997d6f"
    );

    Ok(())
}

#[test]
fn commitment_opening_k256_serialization_is_stable() -> Result<(), ThresholdEcdsaError> {
    let rng = &mut Seed::from_bytes(b"ic-crypto-commitment-opening-serialization-stability-test")
        .into_rng();

    let s1 = EccScalar::random(EccCurveType::K256, rng);
    let s2 = EccScalar::random(EccCurveType::K256, rng);

    assert_eq!(
        hex::encode(s1.serialize()),
        "533db71736dbb11c23fd9a6cd703d37afd5173b943dc932d387dc17c89aaad84"
    );
    assert_eq!(
        hex::encode(s2.serialize()),
        "431fb614454b7c1f2ec2bd76832daf4ec6cadaa38bfbfb801a6d209b275af28d"
    );

    let s1_bytes = EccScalarBytes::try_from(&s1).expect("Serialization failed");
    let s2_bytes = EccScalarBytes::try_from(&s2).expect("Serialization failed");

    let simple = CommitmentOpeningBytes::Simple(s1_bytes.clone());

    assert_eq!(hex::encode(serde_cbor::to_vec(&simple).unwrap()),
            "a16653696d706c65a1644b32353698201853183d18b717183618db18b1181c182318fd189a186c18d70318d3187a18fd1851187318b9184318dc1893182d1838187d18c1187c188918aa18ad1884");

    let pedersen = CommitmentOpeningBytes::Pedersen(s1_bytes, s2_bytes);

    assert_eq!(hex::encode(serde_cbor::to_vec(&pedersen).unwrap()),
            "a168506564657273656e82a1644b32353698201853183d18b717183618db18b1181c182318fd189a186c18d70318d3187a18fd1851187318b9184318dc1893182d1838187d18c1187c188918aa18ad1884a1644b32353698201843181f18b6141845184b187c181f182e18c218bd18761883182d18af184e18c618ca18da18a3188b18fb18fb1880181a186d1820189b1827185a18f2188d");

    Ok(())
}

#[test]
fn commitment_opening_p256_serialization_is_stable() -> Result<(), ThresholdEcdsaError> {
    let rng = &mut Seed::from_bytes(b"ic-crypto-commitment-opening-serialization-stability-test")
        .into_rng();

    let s1 = EccScalar::random(EccCurveType::P256, rng);
    let s2 = EccScalar::random(EccCurveType::P256, rng);

    assert_eq!(
        hex::encode(s1.serialize()),
        "533db71736dbb11c23fd9a6cd703d37afd5173b943dc932d387dc17c89aaad84"
    );
    assert_eq!(
        hex::encode(s2.serialize()),
        "431fb614454b7c1f2ec2bd76832daf4ec6cadaa38bfbfb801a6d209b275af28d"
    );

    let s1_bytes = EccScalarBytes::try_from(&s1).expect("Serialization failed");
    let s2_bytes = EccScalarBytes::try_from(&s2).expect("Serialization failed");

    let simple = CommitmentOpeningBytes::Simple(s1_bytes.clone());

    assert_eq!(hex::encode(serde_cbor::to_vec(&simple).unwrap()),
               "a16653696d706c65a1645032353698201853183d18b717183618db18b1181c182318fd189a186c18d70318d3187a18fd1851187318b9184318dc1893182d1838187d18c1187c188918aa18ad1884");

    let pedersen = CommitmentOpeningBytes::Pedersen(s1_bytes, s2_bytes);

    assert_eq!(hex::encode(serde_cbor::to_vec(&pedersen).unwrap()),
               "a168506564657273656e82a1645032353698201853183d18b717183618db18b1181c182318fd189a186c18d70318d3187a18fd1851187318b9184318dc1893182d1838187d18c1187c188918aa18ad1884a1645032353698201843181f18b6141845184b187c181f182e18c218bd18761883182d18af184e18c618ca18da18a3188b18fb18fb1880181a186d1820189b1827185a18f2188d");

    Ok(())
}
