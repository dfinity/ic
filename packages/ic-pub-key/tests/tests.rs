use hex_literal::hex;
use ic_pub_key::*;

#[cfg(feature = "ed25519")]
#[test]
fn test_ed25519_derivation_key1() {
    use std::str::FromStr;

    let canister_id = ic_pub_key::CanisterId::from_str("h5jwf-5iaaa-aaaan-qmvoa-cai").unwrap();

    let args = SchnorrPublicKeyArgs {
        canister_id: Some(canister_id),
        derivation_path: vec![hex!("ABCDEF").to_vec(), hex!("012345").to_vec()],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "key_1".to_string(),
        },
    };

    let dpk = derive_schnorr_key(&args).unwrap();

    assert_eq!(
        hex::encode(dpk.public_key),
        "43f0008b26564b6da51f585ad47669dfeb1db6d94d7dd216bd304fc1f5f5e997"
    );
}

#[cfg(feature = "ed25519")]
#[test]
fn test_ed25519_derivation_test_key1() {
    use std::str::FromStr;

    let canister_id = ic_pub_key::CanisterId::from_str("h5jwf-5iaaa-aaaan-qmvoa-cai").unwrap();

    let args = SchnorrPublicKeyArgs {
        canister_id: Some(canister_id),
        derivation_path: vec![
            "Hello".as_bytes().to_vec(),
            "Threshold".as_bytes().to_vec(),
            "Signatures".as_bytes().to_vec(),
        ],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "test_key_1".to_string(),
        },
    };

    let dpk = derive_schnorr_key(&args).unwrap();

    assert_eq!(
        hex::encode(dpk.public_key),
        "d9a2ce6a3cd33fe16dce37e045609e51ff516e93bb51013823d6d7a915e3cfb9"
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_bip340_derivation_key1() {
    use std::str::FromStr;

    let canister_id = ic_pub_key::CanisterId::from_str("h5jwf-5iaaa-aaaan-qmvoa-cai").unwrap();

    let args = SchnorrPublicKeyArgs {
        canister_id: Some(canister_id),
        derivation_path: vec![hex!("ABCDEF").to_vec(), hex!("012345").to_vec()],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340secp256k1,
            name: "key_1".to_string(),
        },
    };

    let dpk = derive_schnorr_key(&args).unwrap();

    assert_eq!(
        hex::encode(dpk.public_key),
        "03e5e92c2399985f82521b110ac3dbf697a6b9522002c0d31d0b7cd5352c343457",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_bip340_derivation_test_key1() {
    use std::str::FromStr;

    let canister_id = ic_pub_key::CanisterId::from_str("h5jwf-5iaaa-aaaan-qmvoa-cai").unwrap();

    let args = SchnorrPublicKeyArgs {
        canister_id: Some(canister_id),
        derivation_path: vec![
            "Hello".as_bytes().to_vec(),
            "Threshold".as_bytes().to_vec(),
            "Signatures".as_bytes().to_vec(),
        ],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340secp256k1,
            name: "test_key_1".to_string(),
        },
    };

    let dpk = derive_schnorr_key(&args).unwrap();

    assert_eq!(
        hex::encode(dpk.public_key),
        "0237ca6a41c1db8ab40410445250a5d46fbec7f3e449c8f40f86d8622a4106cebd",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_ecdsa_secp256k1_derivation_key1() {
    use std::str::FromStr;

    let canister_id = ic_pub_key::CanisterId::from_str("h5jwf-5iaaa-aaaan-qmvoa-cai").unwrap();

    let args = EcdsaPublicKeyArgs {
        canister_id: Some(canister_id),
        derivation_path: vec![hex!("ABCDEF").to_vec(), hex!("012345").to_vec()],
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "key_1".to_string(),
        },
    };

    let dpk = derive_ecdsa_key(&args).unwrap();

    assert_eq!(
        hex::encode(dpk.public_key),
        "02735ca28b5c3e380016d7f28bf4703b540a8bbe8e24beffdc021455ca2ab93fe3",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_ecdsa_secp256k1_derivation_test_key1() {
    use std::str::FromStr;

    let canister_id = ic_pub_key::CanisterId::from_str("h5jwf-5iaaa-aaaan-qmvoa-cai").unwrap();

    let args = EcdsaPublicKeyArgs {
        canister_id: Some(canister_id),
        derivation_path: vec![
            "Hello".as_bytes().to_vec(),
            "Threshold".as_bytes().to_vec(),
            "Signatures".as_bytes().to_vec(),
        ],
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_1".to_string(),
        },
    };

    let dpk = derive_ecdsa_key(&args).unwrap();

    assert_eq!(
        hex::encode(dpk.public_key),
        "0315ae8bb8c6e9f78eec2167f5ac773067f37a39da1a1efbc585f9e90658d1c620"
    );
}

#[test]
fn test_vetkd_derivation_using_test_key_1() {
    // This test data was generated on mainnet using test_key_1

    let canister_id = CanisterId::from_text("urq22-tyaaa-aaaag-audia-cai").unwrap();

    let args = VetKDPublicKeyArgs {
        canister_id: Some(canister_id),
        context: vec![],
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381_G2,
            name: "test_key_1".to_string(),
        },
    };

    let canister_key = derive_vetkd_key(&args).unwrap();

    assert_eq!(
        hex::encode(canister_key.public_key),
        "8b961f06d392367e84136088971c4808b434e5d6b928b60fa6177f811db9930e4f2a911ef517db40f7e7897588ae0e2316500dbef3abf08ad7f63940af0cf816c2c1c234943c9bb6f4d53da121dceed093d118d0bd5552740da315eac3b59b0f",
    );

    let args = VetKDPublicKeyArgs {
        canister_id: Some(canister_id),
        context: b"context-string".to_vec(),
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381_G2,
            name: "test_key_1".to_string(),
        },
    };

    let derived_key = derive_vetkd_key(&args).unwrap();

    assert_eq!(
        hex::encode(derived_key.public_key),
        "958a2700438db39cf848f99c80d4d1c0f42b5e6783c35abffe5acda4fdb09548a025fdf85aad8980fcf6e20c1082596310c2612a3f3034c56445ddfc32a0c3cd34a7d0fea8df06a2996c54e21e3f8361a6e633d706ff58e979858fe436c7edf3",
    );
}

#[test]
fn test_vetkd_derivation_using_key1() {
    // This test data was generated on mainnet using key_1

    let canister_id = CanisterId::from_text("urq22-tyaaa-aaaag-audia-cai").unwrap();

    let args = VetKDPublicKeyArgs {
        canister_id: Some(canister_id),
        context: vec![],
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381_G2,
            name: "key_1".to_string(),
        },
    };

    let canister_key = derive_vetkd_key(&args).unwrap();

    assert_eq!(
        hex::encode(canister_key.public_key),
        "a4df5fb733dc53ba0b3f8dab3f7538b2f345052072f69a5749d630d9c2b2b1c4b00af09fa1d993e1ce533996961575ad027e058e2a279ab05271c115ef27d750b6b233f12bc9f1973b203e338d43b6a7617be58d5c7195dfb809d756413bc006",
    );

    let args = VetKDPublicKeyArgs {
        canister_id: Some(canister_id),
        context: b"context-string".to_vec(),
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381_G2,
            name: "key_1".to_string(),
        },
    };

    let derived_key = derive_vetkd_key(&args).unwrap();

    assert_eq!(
        hex::encode(derived_key.public_key),
        "aa45fccb82432315e39fedb1b1f150d2e895fb1f7399cc593b826ac151b519f0966b92aef49a89efe60570ef325f0f7e1974ac3519d2e127a52c013e246aedbff2158bdd0bb9f26c763c88c0b8ec796f401d057eab276d0a34384a8a97b1937f",
    );
}
