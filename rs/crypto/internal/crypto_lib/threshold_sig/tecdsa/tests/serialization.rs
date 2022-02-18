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
            (0, "35b9203df0fef455"),
            (1, "e345dc98f5775825"),
            (2, "0f52dac309b0b672"),
            (3, "1d47b9521d9c38dc"),
            (4, "f451b85212a45952"),
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "ff04d0458f4cd09a",
        "083c9793cd7a16e0",
        &[
            (0, "676a41730fac6174"),
            (1, "eeb77186c9ad31f1"),
            (2, "7bb3192035a67245"),
            (3, "00f56c9321a0af3a"),
            (4, "9ff253c2437b19f2"),
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "2e494300ce9229d7",
        "5cb31a17676257fe",
        &[
            (0, "8184a0a747823e9e"),
            (1, "66ed853b2622483d"),
            (2, "667ea7eb87a7d65b"),
            (3, "e2dc7b3dd741c0a1"),
            (4, "cbe6feff7f274e5e"),
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "46117e02faef5a24",
        "9453c8bda561f21f",
        &[
            (0, "d7b52618b38fcc04"),
            (1, "462f8efc23d05f0a"),
            (2, "6d96b186ab11d35e"),
            (3, "989bb902462ad762"),
            (4, "f7a29a29c9748b6e"),
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "9f87096af2d8673c",
        "d2d1fa319644a975",
        &[
            (0, "3175466f32d509a2"),
            (1, "4667027734ce6bd5"),
            (2, "a59e5546a6453eda"),
            (3, "3e9950c6f4b9347b"),
            (4, "83ae0613049af2d2"),
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
            (0, "ec3a990db5a279c8"),
            (1, "40d233f94d861818"),
            (2, "6b08a4717f9c1da0"),
            (3, "3b7c441e10db7bac"),
            (4, "d5278a0078c95dfe"),
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
