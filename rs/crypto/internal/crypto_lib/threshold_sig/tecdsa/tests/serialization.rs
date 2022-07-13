use ic_crypto_internal_threshold_sig_ecdsa::*;
use rand::Rng;
use std::collections::BTreeMap;

mod test_utils;

use crate::test_utils::*;

fn verify_data(tag: String, expected: &str, serialized: &[u8]) {
    let hash = ic_crypto_sha::Sha256::hash(serialized);
    let hex_encoding = hex::encode(&hash[0..8]);

    if hex_encoding != expected {
        /*
        Should updating the values in this test be required (eg because you have
        *intentionally* made a change which changed the serialization of some
        of the tECDSA artifacts), then comment out the below assert, uncomment
        the println, and then run

        $ cargo test verify_protocol_output_remains_unchanged_over_time -- --nocapture | grep ^perl | parallel -j1

        which will update this file with the produced values.
         */
        assert_eq!(hex_encoding, expected, "{}", tag);
        // println!("perl -pi -e s/{}/{}/g tests/serialization.rs", expected, hex_encoding);
    }
}

fn check_dealings(
    name: &str,
    round: &ProtocolRound,
    commitment_hash: &str,
    transcript_hash: &str,
    dealing_hashes: &[(u32, &str)],
) -> ThresholdEcdsaResult<()> {
    verify_data(
        format!("{} commitment", name),
        commitment_hash,
        &round.commitment.serialize()?,
    );

    verify_data(
        format!("{} transcript", name),
        transcript_hash,
        &round.transcript.serialize()?,
    );

    assert_eq!(round.dealings.len(), dealing_hashes.len());

    for (dealer_index, hash) in dealing_hashes {
        let dealing = round.dealings.get(dealer_index).expect("Missing dealing");
        verify_data(
            format!("{} dealing {}", name, dealer_index),
            hash,
            &dealing.serialize()?,
        );
    }

    Ok(())
}

fn check_shares(
    shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
    hashes: &[(u32, &str)],
) -> ThresholdEcdsaResult<()> {
    assert_eq!(shares.len(), hashes.len());

    for (index, hash) in hashes {
        let share = shares.get(index).expect("Unable to find signature share");
        verify_data(format!("share {}", index), hash, &share.serialize()?)
    }

    Ok(())
}

#[test]
fn verify_protocol_output_remains_unchanged_over_time() -> Result<(), ThresholdEcdsaError> {
    let nodes = 5;
    let threshold = 2;

    let seed = Seed::from_bytes(b"ic-crypto-tecdsa-fixed-seed");

    let setup = SignatureProtocolSetup::new(
        EccCurveType::K256,
        nodes,
        threshold,
        0,
        seed.derive("setup"),
    )?;

    check_dealings(
        "key",
        &setup.key,
        "807f3b29bcc421d0",
        "623080845e685b35",
        &[
            (0, "e7b8624cab606930"),
            (1, "cddb63df18157ad5"),
            (2, "0ac600f863097584"),
            (3, "4dac6c3962e19dce"),
            (4, "cedbbc9aaaf2d96d"),
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "bd4aef1e3a7e276c",
        "4b7f2a867ae0bcc9",
        &[
            (0, "22ac5e63a4173871"),
            (1, "18886ac194f10ad5"),
            (2, "d94fdc34c13dd05d"),
            (3, "08358b27f6b1a468"),
            (4, "7a98c577d0d60157"),
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "aba9665ec91be63f",
        "f1ad398f50c227bb",
        &[
            (0, "50263c87c5e40a97"),
            (1, "b373947bc56351f1"),
            (2, "89a5675e9da945c1"),
            (3, "f29909f897055378"),
            (4, "54dc1c1d08b43c1c"),
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "edb74de7f815bac2",
        "bc499e84a8fcc8f7",
        &[
            (0, "d995b6d7b09b03e5"),
            (1, "93a704077bfdcee3"),
            (2, "8142af1b57f13b37"),
            (3, "d334beb1a1c7eecd"),
            (4, "83ac317a94224d0b"),
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "2e1b78f8e8eeed00",
        "9857c340a75e717a",
        &[
            (0, "a7ea009231aae6d7"),
            (1, "d915e472ed668d5e"),
            (2, "f40eba254efcd63d"),
            (3, "2198c38ec025e544"),
            (4, "4d3a0efca97fbab1"),
        ],
    )?;

    let signed_message = seed.derive("message").into_rng().gen::<[u8; 32]>().to_vec();
    let random_beacon =
        ic_types::Randomness::from(seed.derive("beacon").into_rng().gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto =
        SignatureProtocolExecution::new(setup, signed_message, random_beacon, derivation_path);

    let shares = proto.generate_shares()?;

    check_shares(
        &shares,
        &[
            (0, "a5828d246e927eae"),
            (1, "b5add43f02086e16"),
            (2, "743a39c677fc02d3"),
            (3, "d4d7a73a628c8391"),
            (4, "4dfe21a4e768bda5"),
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
fn verify_fixed_serialization_continues_to_be_accepted() -> Result<(), ThresholdEcdsaError> {
    let dealing_bits = [
        include_str!("data/dealing_random.hex"),
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
