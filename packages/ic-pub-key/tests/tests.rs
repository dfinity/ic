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
        key_id: SchnorrKeyId { algorithm: SchnorrAlgorithm::Ed25519, name: "key_1".to_string() }
    };

    let dpk = derive_schnorr_key(args).unwrap();

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
        derivation_path: vec!["Hello".as_bytes().to_vec(), "Threshold".as_bytes().to_vec(), "Signatures".as_bytes().to_vec()],
        key_id: SchnorrKeyId { algorithm: SchnorrAlgorithm::Ed25519, name: "test_key_1".to_string() }
    };

    let dpk = derive_schnorr_key(args).unwrap();

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
        key_id: SchnorrKeyId { algorithm: SchnorrAlgorithm::Bip340secp256k1, name: "key_1".to_string() }
    };

    let dpk = derive_schnorr_key(args).unwrap();

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
        derivation_path: vec!["Hello".as_bytes().to_vec(), "Threshold".as_bytes().to_vec(), "Signatures".as_bytes().to_vec()],
        key_id: SchnorrKeyId { algorithm: SchnorrAlgorithm::Bip340secp256k1, name: "test_key_1".to_string() }
    };

    let dpk = derive_schnorr_key(args).unwrap();

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
        key_id: EcdsaKeyId { curve: EcdsaCurve::Secp256k1, name: "key_1".to_string() }
    };

    let dpk = derive_ecdsa_key(args).unwrap();

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
        derivation_path: vec!["Hello".as_bytes().to_vec(), "Threshold".as_bytes().to_vec(), "Signatures".as_bytes().to_vec()],
        key_id: EcdsaKeyId { curve: EcdsaCurve::Secp256k1, name: "test_key_1".to_string() }
    };

    let dpk = derive_ecdsa_key(args).unwrap();

    assert_eq!(
        hex::encode(dpk.public_key),
        "0315ae8bb8c6e9f78eec2167f5ac773067f37a39da1a1efbc585f9e90658d1c620"
    );
}
