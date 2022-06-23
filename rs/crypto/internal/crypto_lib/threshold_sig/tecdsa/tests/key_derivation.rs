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
        "02aab10ba2f09b79f712726f9fa697811facd778dac10b543c42cc7e7c78e9db21"
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
        "03effbb1f5199bd6372a5f297e1787b1749297f97e0614eabdb6b668e57771dc8d"
    );
    assert_eq!(
        hex::encode(key.chain_key),
        "9b51621c5a011a5b2857df82c75071ae446b091b7cfeba00fa646591ba2045a1"
    );

    let key = setup.public_key(&DerivationPath::new(vec![index2.clone()]))?;
    assert_eq!(
        hex::encode(key.public_key),
        "03a7827a3b1449e3f0f8114ce6d92f9a9da0aede44a911c44aa15d2633895a6005"
    );
    assert_eq!(
        hex::encode(key.chain_key),
        "380827cbbcc3cb9b1e810bbc9ed5497141bd61fc199fe92a10cd832bf66601f0"
    );

    let key = setup.public_key(&DerivationPath::new(vec![index1, index2]))?;
    assert_eq!(
        hex::encode(key.public_key),
        "021714eb5c8c8a0b010f494243b1e5272d67d79fa9cd12de301aad847bba8aa7f3"
    );
    assert_eq!(
        hex::encode(key.chain_key),
        "006cc2146eedc68e85947dccd9d0b3aa7a794f9dd928bb9415fc0aa96ed9a45d"
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
