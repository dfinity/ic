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

        $ cargo test verify_serialization_remains_unchanged_over_time -- --nocapture | grep ^perl | parallel -j1

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
fn verify_serialization_remains_unchanged_over_time() -> Result<(), ThresholdEcdsaError> {
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
        "3b1651f91235bea0",
        "dcb0d33a0444c4da",
        &[
            (0, "ec4517ab6561913c"),
            (1, "56aa35ae8874e3a9"),
            (2, "da4b52b0e8b28c56"),
            (3, "ace0b7dc54ce98f9"),
            (4, "c170456f46da7ef8"),
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "00dd83ba807ddb8b",
        "fb73e2b787bed6a8",
        &[
            (0, "2919ed5ef005e24d"),
            (1, "d13d75c5ba452aa7"),
            (2, "051966db42301a4f"),
            (3, "8046613091b60bc4"),
            (4, "073a46541f43daa5"),
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "072e2cc0b419ed05",
        "12bdfac755057274",
        &[
            (0, "983683af4ffedddc"),
            (1, "f59f3afe3a5734a8"),
            (2, "808030e98d7f2a65"),
            (3, "571c30277c76871a"),
            (4, "4b0a9b482900ae06"),
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "2ded0f153929b9f0",
        "44f5c86382cc479c",
        &[
            (0, "9cae036e691c746c"),
            (1, "cae56922b4ffdb34"),
            (2, "8aa27cb2732f560f"),
            (3, "0dab338fe09c4b91"),
            (4, "e8c8dde553e9b676"),
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "fead521acec68d9d",
        "0400f8b432760ed3",
        &[
            (0, "43b424974b8d6ae5"),
            (1, "21bd4b7f691d8236"),
            (2, "ac5b0f9cf7ed2ee7"),
            (3, "062cf5b78c206495"),
            (4, "4a4c88f1f8fe8ee1"),
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
            (0, "6a61b6e3df84bb14"),
            (1, "b5ac8f25f0214b8b"),
            (2, "3e0fe141356581f1"),
            (3, "dec2319a9f4cb630"),
            (4, "2742a17e8238f394"),
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "1aac78183716fd7c",
        &sig.serialize(),
    );

    Ok(())
}
