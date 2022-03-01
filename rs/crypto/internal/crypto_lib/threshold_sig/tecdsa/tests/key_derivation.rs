use ic_crypto_internal_threshold_sig_ecdsa::{
    DerivationIndex, DerivationPath, EccCurveType, EccPoint, Seed, ThresholdEcdsaError,
};
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
    let setup = SignatureProtocolSetup::new(EccCurveType::K256, nodes, threshold, seed)?;

    let master_key = setup.public_key(&DerivationPath::new(vec![]))?;
    assert_eq!(
        hex::encode(master_key.public_key),
        "038cc78aa6040c5f269351939a05aad3a31f86902d0b8cf3085244bb58b6d4337a"
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
        "0216ce1e78a8477d41351c31d0a9f70286935a96bdd5544356d8ecf63a4120979c"
    );
    assert_eq!(
        hex::encode(key.chain_key),
        "0811cb2a510b05fedcfb7ba49a5ceb4d48d9ed1210b6a85839e36c53105d3308"
    );

    let key = setup.public_key(&DerivationPath::new(vec![index2.clone()]))?;
    assert_eq!(
        hex::encode(key.public_key),
        "02a9a19dc211db7ec0cbc5883bbc70eedef9d95fed51d950d2fe350e66fbb542aa"
    );
    assert_eq!(
        hex::encode(key.chain_key),
        "979ab6baf82d9e4b0793236f61012a48d9b3bfa9b6f30c86a0b5d01c1fab300d"
    );

    let key = setup.public_key(&DerivationPath::new(vec![index1, index2]))?;
    assert_eq!(
        hex::encode(key.public_key),
        "0312ea4418122888ddd95b15261053864861f46f6081a0374c73918c3957b7f35b"
    );
    assert_eq!(
        hex::encode(key.chain_key),
        "53ab3ab4ba311976dfae6e7f38fe2131dd5cb72ceff178b06a19b8ad92d1f2d3"
    );

    Ok(())
}

#[test]
fn should_bip32_derivation_match_external_lib() -> Result<(), ThresholdEcdsaError> {
    let nodes = 9;
    let threshold = 2;
    let setup = SignatureProtocolSetup::new(EccCurveType::K256, nodes, threshold, random_seed())?;

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
