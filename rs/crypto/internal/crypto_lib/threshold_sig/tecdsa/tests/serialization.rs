use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;

use ic_crypto_internal_threshold_sig_ecdsa_test_utils::*;

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
) -> CanisterThresholdResult<()> {
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

fn check_ecdsa_shares(
    shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
    hashes: &[&'static str],
) -> CanisterThresholdResult<()> {
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

fn check_bip340_shares(
    shares: &BTreeMap<NodeIndex, ThresholdBip340SignatureShareInternal>,
    hashes: &[&'static str],
) -> CanisterThresholdResult<()> {
    assert_eq!(shares.len(), hashes.len());

    for (index, hash) in hashes.iter().enumerate() {
        let index = index as u32;
        let share = shares.get(&index).expect("Unable to find signature share");
        verify_data(
            format!("share {}", index),
            hash,
            &share.serialize().unwrap(),
        )
    }

    Ok(())
}

fn check_ed25519_shares(
    shares: &BTreeMap<NodeIndex, ThresholdEd25519SignatureShareInternal>,
    hashes: &[&'static str],
) -> CanisterThresholdResult<()> {
    assert_eq!(shares.len(), hashes.len());

    for (index, hash) in hashes.iter().enumerate() {
        let index = index as u32;
        let share = shares.get(&index).expect("Unable to find signature share");
        verify_data(format!("share {}", index), hash, &share.serialize())
    }

    Ok(())
}

#[test]
fn verify_protocol_output_remains_unchanged_over_time_k256_unmasked_kappa(
) -> Result<(), CanisterThresholdError> {
    let nodes = 5;
    let threshold = 2;

    let seed =
        Seed::from_bytes(b"ic-crypto-tecdsa-fixed-seed-for-k256-unmasked-kappa-stability-test");

    let setup = EcdsaSignatureProtocolSetup::new(
        TestConfig::new(IdkgProtocolAlgorithm::EcdsaSecp256k1, EccCurveType::K256),
        nodes,
        threshold,
        0,
        seed.derive("setup"),
    )?;

    check_dealings(
        "key",
        &setup.key,
        "2c93b6332a9c6240",
        "e1b2d7cd95af1947",
        &[
            "12bca12d4f4218ab",
            "8ca948a1403aa385",
            "353673e17329b19b",
            "e382cbe4721fa702",
            "8fc469c804f86f83",
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "80dce0c3d3ef09f4",
        "5526543951fa6de7",
        &[
            "b1d65663b54fd933",
            "fb239470ad4b4fcc",
            "0206a9bfe753cb95",
            "273a94d7e2264d71",
            "bacfdc15a7336409",
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "a76bfc66d8a61271",
        "c82ff9135d5114a0",
        &[
            "3aca8ac7d76b9e19",
            "53b67c24bfbd8512",
            "4e2b62cddc310638",
            "a82fecdc913c887a",
            "2d15e950e7e31803",
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "8b0bb3fea680336c",
        "7fdeeded4adfa043",
        &[
            "695127beef5990ce",
            "330870feb7be9a51",
            "d3a896c6fdfc9356",
            "044308cf6810d66f",
            "1a3c0733b51a5ff8",
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "df6c747a3ad7660c",
        "759a7de6fe47e00d",
        &[
            "08205bac7733b875",
            "035f2b0c04986a31",
            "a83a5e0c4a279d13",
            "5af5850e20878bb6",
            "ef5b33b9e4f4af9e",
        ],
    )?;

    let signed_message = seed.derive("message").into_rng().gen::<[u8; 32]>().to_vec();
    let random_beacon =
        ic_types::Randomness::from(seed.derive("beacon").into_rng().gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto =
        EcdsaSignatureProtocolExecution::new(setup, signed_message, random_beacon, derivation_path);

    let shares = proto.generate_shares()?;

    check_ecdsa_shares(
        &shares,
        &[
            "384a64d769c10d24",
            "5dfff524c45d2f3a",
            "04ac8f2c18edb66e",
            "67b12a971ae86089",
            "db5f5fb81d812132",
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "c5a91fa180554d5e",
        &sig.serialize(),
    );

    Ok(())
}

#[test]
fn verify_protocol_output_remains_unchanged_over_time_p256() -> Result<(), CanisterThresholdError> {
    let nodes = 5;
    let threshold = 2;

    let seed = Seed::from_bytes(b"ic-crypto-tecdsa-fixed-seed-for-p256-stability-test");

    let setup = EcdsaSignatureProtocolSetup::new(
        TestConfig::new(IdkgProtocolAlgorithm::EcdsaSecp256r1, EccCurveType::P256),
        nodes,
        threshold,
        0,
        seed.derive("setup"),
    )?;

    check_dealings(
        "key",
        &setup.key,
        "57aca428a42a3774",
        "0b45f8ac30391fc1",
        &[
            "84223bc65fa597ad",
            "e6305e9c308fb599",
            "caf01b8138a46e76",
            "fd4fdb5832a66368",
            "0c0631e7b2a88660",
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "94accc13810a7f08",
        "2e62e0e0ea396799",
        &[
            "fd3113df5ba579c4",
            "deb9a94966751daf",
            "452281aa5065a47b",
            "682bfcf20ce0156b",
            "5803615e08950d9f",
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "a3c15cf8fc91ac59",
        "4aa76a784787afca",
        &[
            "4c12e43d8fcc2fe0",
            "ddbed36a446fc478",
            "8a374349bb48a029",
            "b6d99f9c207ad7eb",
            "86cdd6170652ae81",
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "494ae0a2b2c0a714",
        "5037c3840f64a1ce",
        &[
            "c3116e3df02220c7",
            "2596def94c9a2572",
            "dbae6fdecb7f1928",
            "8c5759fd01bd2bc7",
            "ec1ad2eab886bd8e",
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "b9d9a94a8aa428c2",
        "048c6c90783ac001",
        &[
            "70fe7cda709b5c11",
            "ed95fdda935e2ca5",
            "ebb82c5e901c76e2",
            "23fc37f98e0e4796",
            "8450c212acb0470f",
        ],
    )?;

    let signed_message = seed.derive("message").into_rng().gen::<[u8; 32]>().to_vec();
    let random_beacon =
        ic_types::Randomness::from(seed.derive("beacon").into_rng().gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto =
        EcdsaSignatureProtocolExecution::new(setup, signed_message, random_beacon, derivation_path);

    let shares = proto.generate_shares()?;

    check_ecdsa_shares(
        &shares,
        &[
            "4e59ae873eae8156",
            "251a4336838a56d2",
            "a8d1abdf5f7f8c95",
            "c4ef98791f7ed7a3",
            "cfdb1af1257ae2c3",
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "bb02bf80a51dd013",
        &sig.serialize(),
    );

    Ok(())
}

#[test]
fn verify_protocol_output_remains_unchanged_over_time_p256_sig_with_k256_mega(
) -> Result<(), CanisterThresholdError> {
    let nodes = 5;
    let threshold = 2;

    let seed = Seed::from_bytes(b"ic-crypto-tecdsa-fixed-seed-for-p256-sig-and-k256-mega");

    let setup = EcdsaSignatureProtocolSetup::new(
        TestConfig::new(IdkgProtocolAlgorithm::EcdsaSecp256r1, EccCurveType::K256),
        nodes,
        threshold,
        0,
        seed.derive("setup"),
    )?;

    check_dealings(
        "key",
        &setup.key,
        "c9875afb79900e44",
        "94365159a32b2331",
        &[
            "ff9738598036bfcb",
            "3e544e898e8556ef",
            "73baf9fb3d008e42",
            "3d7d9f63fb7a314c",
            "ad6594c48bd74174",
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "42566e0604e35e0a",
        "2b940e3696a06931",
        &[
            "a66c060cf022a552",
            "ee44c495bbb55e91",
            "c206961397951926",
            "da5b58473f2970ab",
            "2f170bf7e04617b2",
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "e533a3d24221b8ef",
        "f4949dc28348b02c",
        &[
            "05919c0698fb6f13",
            "d8fda7f4fd6f711d",
            "5d68570cd2e82c24",
            "d69fd9c55bec90bd",
            "1c41ab5d8f62607a",
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "46cd1385e6e7645a",
        "cac96382452e1eb9",
        &[
            "e3faa392aa28d24b",
            "ab3e7d37e19e30e4",
            "7d84b24afc3c77ae",
            "d38ac43cd3f2ac30",
            "7bfe4297b6ce1c42",
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "9be435bcb7efb22f",
        "cc02a94a53e0be88",
        &[
            "0adbd3c9c0950bba",
            "e27cb5a9b6c7b12d",
            "526d37786a2ba2d5",
            "dd4f1ad3759ff996",
            "c88121198c237a99",
        ],
    )?;

    let signed_message = seed.derive("message").into_rng().gen::<[u8; 32]>().to_vec();
    let random_beacon =
        ic_types::Randomness::from(seed.derive("beacon").into_rng().gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto =
        EcdsaSignatureProtocolExecution::new(setup, signed_message, random_beacon, derivation_path);

    let shares = proto.generate_shares()?;

    check_ecdsa_shares(
        &shares,
        &[
            "12d3b0330cb53c14",
            "714ae2e914f8c017",
            "6d95a53e918f6497",
            "3cfb7dc937f9c603",
            "ab53d3c68db4f06e",
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "07ec19ab78215b25",
        &sig.serialize(),
    );

    Ok(())
}

#[test]
fn verify_protocol_output_remains_unchanged_over_time_bip340_sig_with_k256_mega(
) -> Result<(), CanisterThresholdError> {
    let nodes = 5;
    let threshold = 2;

    let seed = Seed::from_bytes(b"ic-crypto-fixed-seed-for-bip340-with-k256-mega");

    let setup = SchnorrSignatureProtocolSetup::new(
        TestConfig::new(IdkgProtocolAlgorithm::Bip340, EccCurveType::K256),
        nodes,
        threshold,
        0,
        seed.derive("setup"),
    )?;

    check_dealings(
        "key",
        &setup.key,
        "1c9c1ae081f01333",
        "a5a39ea1368a7eaf",
        &[
            "381968318ce1a972",
            "a64b36f75ab54e21",
            "8130efaa7a966d2b",
            "7c0fda52e3638cbb",
            "09c86538386a2373",
        ],
    )?;

    check_dealings(
        "presignature",
        &setup.presig,
        "2ee7c97f0c3aa2d0",
        "708015ca0764b96b",
        &[
            "e1bda72a2363c83e",
            "033a4b7d3c6d7b35",
            "0d883aca685b888d",
            "babed7a860f38993",
            "c541088384582f9e",
        ],
    )?;

    let signed_message = seed.derive("message").into_rng().gen::<[u8; 32]>().to_vec();
    let random_beacon =
        ic_types::Randomness::from(seed.derive("beacon").into_rng().gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto = Bip340SignatureProtocolExecution::new(
        setup,
        signed_message,
        random_beacon,
        derivation_path,
    );

    let shares = proto.generate_shares()?;

    check_bip340_shares(
        &shares,
        &[
            "12e004e15a48699b",
            "5233d7a0f522d41a",
            "d3c478beef7fcf69",
            "7b43000b5fb724d2",
            "69b109d0bc023c50",
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "49a5195e5ac54a6d",
        &sig.serialize().unwrap(),
    );

    Ok(())
}

#[test]
fn verify_protocol_output_remains_unchanged_over_time_ed25519_sig_with_k256_mega(
) -> Result<(), CanisterThresholdError> {
    let nodes = 5;
    let threshold = 2;

    let seed = Seed::from_bytes(b"ic-crypto-fixed-seed-for-ed25519-with-k256-mega");

    let setup = SchnorrSignatureProtocolSetup::new(
        TestConfig::new(IdkgProtocolAlgorithm::Ed25519, EccCurveType::K256),
        nodes,
        threshold,
        0,
        seed.derive("setup"),
    )?;

    check_dealings(
        "key",
        &setup.key,
        "de28aec1408afb48",
        "7797fa45df1fcd13",
        &[
            "f36040a6b41e3908",
            "3eb6ac994d151800",
            "4af0cad4ad64e34b",
            "a625f366fb63867d",
            "a2ef0bbf4c6d2f6c",
        ],
    )?;

    check_dealings(
        "presignature",
        &setup.presig,
        "effd5d953be5452f",
        "c1d97f34370ed3c9",
        &[
            "a58e4c739e56920c",
            "601805cd26f7c1e2",
            "0416173015da91be",
            "af45434844419435",
            "037b1e9b2409060d",
        ],
    )?;

    let signed_message = seed.derive("message").into_rng().gen::<[u8; 32]>().to_vec();
    let random_beacon =
        ic_types::Randomness::from(seed.derive("beacon").into_rng().gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto = Ed25519SignatureProtocolExecution::new(
        setup,
        signed_message,
        random_beacon,
        derivation_path,
    );

    let shares = proto.generate_shares()?;

    check_ed25519_shares(
        &shares,
        &[
            "fff354b51e340f21",
            "1bdc843038096cbd",
            "92df60247f781e56",
            "2a4cbf5672d728d5",
            "eea7a9410ea5e773",
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "9fae525b533ec83a",
        &sig.serialize(),
    );

    Ok(())
}

#[test]
fn verify_fixed_serialization_continues_to_be_accepted() -> Result<(), CanisterThresholdError> {
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
fn mega_k256_keyset_serialization_is_stable() -> Result<(), CanisterThresholdError> {
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
fn commitment_opening_k256_serialization_is_stable() -> Result<(), CanisterThresholdError> {
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
fn commitment_opening_p256_serialization_is_stable() -> Result<(), CanisterThresholdError> {
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

#[test]
fn commitment_opening_ed25519_serialization_is_stable() -> Result<(), CanisterThresholdError> {
    let rng = &mut Seed::from_bytes(b"ic-crypto-commitment-opening-serialization-stability-test")
        .into_rng();

    let s1 = EccScalar::random(EccCurveType::Ed25519, rng);
    let s2 = EccScalar::random(EccCurveType::Ed25519, rng);

    assert_eq!(
        hex::encode(s1.serialize()),
        "7ca9cd1fdcffd3181170bf8c4829a2729f8b4b63d4ef4026b045bb95d82a020d"
    );
    assert_eq!(
        hex::encode(s2.serialize()),
        "4d31412bf594aab8202fa091aa8a1693a30217c9c5ce89129e7b00c0b1b2510c"
    );

    let s1_bytes = EccScalarBytes::try_from(&s1).expect("Serialization failed");
    let s2_bytes = EccScalarBytes::try_from(&s2).expect("Serialization failed");

    let simple = CommitmentOpeningBytes::Simple(s1_bytes.clone());

    assert_eq!(hex::encode(serde_cbor::to_vec(&simple).unwrap()),
               "a16653696d706c65a167456432353531399820187c18a918cd181f18dc18ff18d3181811187018bf188c1848182918a21872189f188b184b186318d418ef1840182618b0184518bb189518d8182a020d");

    let pedersen = CommitmentOpeningBytes::Pedersen(s1_bytes, s2_bytes);

    assert_eq!(hex::encode(serde_cbor::to_vec(&pedersen).unwrap()),
               "a168506564657273656e82a167456432353531399820187c18a918cd181f18dc18ff18d3181811187018bf188c1848182918a21872189f188b184b186318d418ef1840182618b0184518bb189518d8182a020da167456432353531399820184d18311841182b18f5189418aa18b81820182f18a0189118aa188a16189318a3021718c918c518ce188912189e187b0018c018b118b218510c");

    Ok(())
}

#[test]
fn bip340_combined_share_serialization_roundtrip_works_correctly() {
    let nodes = 5;
    let threshold = 2;
    let rng = &mut reproducible_rng();
    let signed_message = random_bytes(rng);
    let random_beacon = ic_types::Randomness::from(rng.gen::<[u8; 32]>());
    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);

    let cfg = TestConfig::new(IdkgProtocolAlgorithm::Bip340, EccCurveType::K256);

    let seed = Seed::from_bytes(&random_bytes(rng));
    let setup = SchnorrSignatureProtocolSetup::new(cfg, nodes, threshold, 0, seed).unwrap();

    let proto = Bip340SignatureProtocolExecution::new(
        setup,
        signed_message,
        random_beacon,
        derivation_path,
    );
    let shares = proto.generate_shares().unwrap();
    let comb_share = proto.generate_signature(&shares).unwrap();

    let serialized_comb_share = comb_share.serialize().unwrap();
    let deserialized_comb_share =
        ThresholdBip340CombinedSignatureInternal::deserialize(&serialized_comb_share).unwrap();

    // `ThresholdBip340CombinedSignatureInternal` does not implement
    // PartialEq, so we need to compare the serialized bytes.
    assert_eq!(
        serialized_comb_share,
        deserialized_comb_share.serialize().unwrap()
    );
}

#[test]
fn ed25519_combined_share_serialization_roundtrip_works_correctly() {
    let nodes = 5;
    let threshold = 2;
    let rng = &mut reproducible_rng();
    let signed_message = random_bytes(rng);
    let random_beacon = ic_types::Randomness::from(rng.gen::<[u8; 32]>());
    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);

    let cfg = TestConfig::new(IdkgProtocolAlgorithm::Ed25519, EccCurveType::K256);

    let seed = Seed::from_bytes(&random_bytes(rng));
    let setup =
        SchnorrSignatureProtocolSetup::new(cfg, nodes, threshold, 0, seed.derive("setup")).unwrap();

    let proto = Ed25519SignatureProtocolExecution::new(
        setup,
        signed_message,
        random_beacon,
        derivation_path,
    );
    let shares = proto.generate_shares().unwrap();
    let comb_share = proto.generate_signature(&shares).unwrap();

    let serialized_comb_share = comb_share.serialize();
    let deserialized_comb_share =
        ThresholdEd25519CombinedSignatureInternal::deserialize(&serialized_comb_share).unwrap();

    // `ThresholdEd25519CombinedSignatureInternal`` does not implement
    // PartialEq, so we need to compare the serialized bytes.
    assert_eq!(serialized_comb_share, deserialized_comb_share.serialize());
}

fn random_bytes<R: Rng + CryptoRng>(rng: &mut R) -> Vec<u8> {
    let size = rng.gen_range(0..100);
    let mut bytes = vec![0; size];
    rng.fill_bytes(&mut bytes);
    bytes
}
