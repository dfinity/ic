use ic_crypto_internal_threshold_sig_ecdsa::*;
use rand::Rng;
use std::convert::{TryFrom, TryInto};

#[allow(dead_code)]
mod test_utils;

use crate::test_utils::*;

#[test]
fn test_index_next_behavior() {
    fn check_next(input: &[u8], output: &[u8]) {
        let index = DerivationIndex(input.to_vec());
        let next = index.next();
        assert_eq!(next.0, output);
    }

    check_next(&[], &[1]);
    check_next(&[1], &[2]);
    check_next(&[0xFF], &[1, 0]);
    check_next(&[0, 0, 0, 5], &[0, 0, 0, 6]);
    check_next(&[0x7F, 0xFF, 0xFF, 0xFF], &[0x80, 0x00, 0x00, 0x00]);
}

#[test]
fn test_that_key_derivation_on_secp256r1_currently_fails() -> Result<(), ThresholdEcdsaError> {
    let mut rng = rand::thread_rng();
    let path = DerivationPath::new_bip32(&[1, 2, 3]);
    let master_key = EccPoint::hash_to_point(
        EccCurveType::P256,
        &rng.gen::<[u8; 32]>(),
        "public_key".as_bytes(),
    )?;

    assert_eq!(
        path.derive_tweak(&master_key),
        Err(ThresholdEcdsaError::InvalidArguments(
            "Currently key derivation not defined for secp256r1".to_string()
        ))
    );

    Ok(())
}

#[test]
fn verify_bip32_extended_key_derivation() -> Result<(), ThresholdEcdsaError> {
    let nodes = 10;
    let threshold = nodes / 3;

    let seed = Seed::from_bytes(b"verify_bip32_extended_key_derivation");
    let setup = SignatureProtocolSetup::new(EccCurveType::K256, nodes, threshold, threshold, seed)?;

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
fn should_bip32_derivation_match_external_lib() -> Result<(), ThresholdEcdsaError> {
    let nodes = 9;
    let threshold = 2;
    let setup = SignatureProtocolSetup::new(
        EccCurveType::K256,
        nodes,
        threshold,
        threshold,
        random_seed(),
    )?;

    let key_1 = setup.public_key(&DerivationPath::new_bip32(&[1]))?;
    let key_1_2 = setup.public_key(&DerivationPath::new_bip32(&[1, 2]))?;
    let key_1_2_3 = setup.public_key(&DerivationPath::new_bip32(&[1, 2, 3]))?;
    let key_1_2_3_4 = setup.public_key(&DerivationPath::new_bip32(&[1, 2, 3, 4]))?;

    let attrs = bip32::ExtendedKeyAttrs {
        depth: 1,
        parent_fingerprint: [0u8; 4],
        child_number: bip32::ChildNumber(1),
        chain_code: key_1.chain_key.try_into().expect("Unexpected size"),
    };

    let ext = bip32::ExtendedKey {
        prefix: bip32::Prefix::XPUB,
        attrs,
        key_bytes: key_1.public_key.try_into().expect("Unexpected size"),
    };

    let bip32_1 = bip32::XPub::try_from(ext).expect("Failed to accept BIP32");

    let bip32_1_2 = bip32_1
        .derive_child(bip32::ChildNumber(2))
        .expect("Failed to derive child");
    assert_eq!(bip32_1_2.to_bytes().to_vec(), key_1_2.public_key);

    let bip32_1_2_3 = bip32_1_2
        .derive_child(bip32::ChildNumber(3))
        .expect("Failed to derive child");
    assert_eq!(bip32_1_2_3.to_bytes().to_vec(), key_1_2_3.public_key);

    let bip32_1_2_3_4 = bip32_1_2_3
        .derive_child(bip32::ChildNumber(4))
        .expect("Failed to derive child");
    assert_eq!(bip32_1_2_3_4.to_bytes().to_vec(), key_1_2_3_4.public_key);

    Ok(())
}
