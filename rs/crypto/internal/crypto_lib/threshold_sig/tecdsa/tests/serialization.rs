use ic_crypto_internal_threshold_sig_ecdsa::*;
use rand::Rng;
use std::collections::BTreeMap;

mod test_utils;

use crate::test_utils::*;

fn verify_data(tag: String, expected: &str, serialized: &[u8]) {
    let hash = ic_crypto_sha::Sha256::hash(serialized);
    assert_eq!(hex::encode(&hash[0..8]), expected, "{}", tag);
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

    let setup =
        SignatureProtocolSetup::new(EccCurveType::K256, nodes, threshold, seed.derive("setup"))?;

    check_dealings(
        "key",
        &setup.key,
        "d81bf365bcc449ae",
        "b6a77502144a501d",
        &[
            (0, "5357d0ec495b3db2"),
            (1, "769f6341db0b972f"),
            (2, "0f52dac309b0b672"),
            (3, "1d47b9521d9c38dc"),
            (4, "56f370f9bb04976c"),
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "eb81a06c0ebe3dd9",
        "3a4e03abdf31de8c",
        &[
            (0, "a00eed6d66f24e62"),
            (1, "0723cc77b6b5f559"),
            (2, "83ee87383da6ee5e"),
            (3, "81c08c1d70007366"),
            (4, "20e05fe40381443e"),
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "2e494300ce9229d7",
        "5cb31a17676257fe",
        &[
            (0, "9d83b661fb8ea7e6"),
            (1, "ced1a78a33c5a03d"),
            (2, "667ea7eb87a7d65b"),
            (3, "5a792bf6c62f8016"),
            (4, "cbe6feff7f274e5e"),
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "0e5829e1e11cf7f5",
        "21bad7d76631a6c0",
        &[
            (0, "09d3b0c78f7530c5"),
            (1, "1b9f3c61fac8348b"),
            (2, "54f2b81be50e8eb5"),
            (3, "3ed3f16f3063f624"),
            (4, "5b5d852c1708e753"),
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "9f87096af2d8673c",
        "d2d1fa319644a975",
        &[
            (0, "f0374229369fd614"),
            (1, "9352112806281c09"),
            (2, "aec82fa00b346664"),
            (3, "07316740e06c2f1f"),
            (4, "ace454e12a6eeb62"),
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
            (0, "b6cf5b8d7aac3128"),
            (1, "cc2bc61353c7d2c8"),
            (2, "e5477a9f47438000"),
            (3, "6b7f5c032909595e"),
            (4, "2c21e9038bd41e0e"),
        ],
    )?;

    let sig = proto.generate_signature(&shares).unwrap();

    verify_data(
        "signature".to_string(),
        "59960e59d2a46f69",
        &sig.serialize(),
    );

    Ok(())
}
