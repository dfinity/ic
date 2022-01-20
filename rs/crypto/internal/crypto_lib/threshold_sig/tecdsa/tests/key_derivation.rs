use rand::Rng;
use std::convert::{TryFrom, TryInto};
use tecdsa::{DerivationPath, EccCurveType, EccPoint, ThresholdEcdsaError};

#[allow(dead_code)]
mod test_utils;

use crate::test_utils::*;

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
        Err(ThresholdEcdsaError::InvalidDerivationPath)
    );
    Ok(())
}

#[test]
fn should_bip32_derivation_match_external_lib() -> Result<(), ThresholdEcdsaError> {
    let nodes = 6;
    let threshold = 2;
    let setup = SignatureProtocolSetup::new(EccCurveType::K256, nodes, threshold)?;

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
