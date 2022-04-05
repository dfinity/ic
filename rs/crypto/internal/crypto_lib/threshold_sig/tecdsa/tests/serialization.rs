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

        cargo test verify_serialization_remains_unchanged_over_time -- --nocapture | grep ^perl | parallel -j1
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
            (0, "cdb3774cf1fc4d32"),
            (1, "6f65179a607eed92"),
            (2, "654b3581d9fd2aef"),
            (3, "52b2b0f8f42c8628"),
            (4, "7bdd2609a3d62fad"),
        ],
    )?;

    check_dealings(
        "key*lambda",
        &setup.key_times_lambda,
        "00dd83ba807ddb8b",
        "fb73e2b787bed6a8",
        &[
            (0, "fdf08318386cd9ee"),
            (1, "cfdc426d579b8ccb"),
            (2, "9444cd74284ac8e2"),
            (3, "b345efd1475c6173"),
            (4, "dc58053be29a5f39"),
        ],
    )?;

    check_dealings(
        "lambda",
        &setup.lambda,
        "072e2cc0b419ed05",
        "12bdfac755057274",
        &[
            (0, "5f66d246f78a6523"),
            (1, "f9107252b93d6bc9"),
            (2, "e44f6c4bab4acfce"),
            (3, "edced8f70dce8d5f"),
            (4, "3d170817dda1e6e1"),
        ],
    )?;

    check_dealings(
        "kappa",
        &setup.kappa,
        "2ded0f153929b9f0",
        "44f5c86382cc479c",
        &[
            (0, "0bd58d1dc1ea5394"),
            (1, "23901fcc0a49a4e5"),
            (2, "92fb0d6770c1eec8"),
            (3, "c1e3a00405475fbb"),
            (4, "cd1533ec8a96540b"),
        ],
    )?;

    check_dealings(
        "kappa*lambda",
        &setup.kappa_times_lambda,
        "fead521acec68d9d",
        "0400f8b432760ed3",
        &[
            (0, "b25daca699ed741a"),
            (1, "ca307ea916c62411"),
            (2, "a129528acf78eccc"),
            (3, "0b221a208519f149"),
            (4, "e104343cee3218d8"),
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
