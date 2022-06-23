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
        //println!("perl -pi -e s/{}/{}/g tests/serialization.rs", expected, hex_encoding);
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
        "da6286338edd7d4d",
        "e662d96ce64b7f99",
        &[
            (0, "d46016e61131e59f"),
            (1, "ce7b7b7ad2ea7279"),
            (2, "222ad624c89a9196"),
            (3, "019f742040b0a551"),
            (4, "94c4405df048f449"),
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "dcd58ba515be5259",
        "65dbb537693b73bd",
        &[
            (0, "b9d6a6261245998a"),
            (1, "5d46a683537172c5"),
            (2, "53d0c39c06e7078d"),
            (3, "ab56eaedc799d567"),
            (4, "78ba39219830843f"),
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "b8326892c3402d58",
        "5fcd24bf605d4cff",
        &[
            (0, "a44000d2c06b75da"),
            (1, "e7297326c85c7508"),
            (2, "28f5ab0c1b505689"),
            (3, "298648ee710ac5ba"),
            (4, "1cf1a0364b05c417"),
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "556dccc6cab404fa",
        "820694586d1a6143",
        &[
            (0, "d857d82b6ba85eeb"),
            (1, "c67bd8a94cf01ace"),
            (2, "48304371a042dd29"),
            (3, "e55062ad33957ee1"),
            (4, "e08b196f15d8538b"),
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "8a789fa03aa3a6d7",
        "62189e2343328426",
        &[
            (0, "2c5da3d260204f62"),
            (1, "2eb17422f9672608"),
            (2, "0a905e05faa7ae78"),
            (3, "d69ba7c656ca7887"),
            (4, "0aeef8cef93b2bdc"),
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
            (0, "b53432872a836550"),
            (1, "caca3ad9c96dcc20"),
            (2, "22a8dcf47325b89e"),
            (3, "a444752e464b2327"),
            (4, "f3cf837cda339990"),
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "c1abb20ffef4ae13",
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
