use ic_pub_key::*;

#[cfg(any(feature = "secp256k1", feature = "secp256r1"))]
fn test_ecdsa_derivation(
    curve: EcdsaCurve,
    key_name: &'static str,
    canister_id: &'static str,
    derivation_path: &[&'static str],
    expected_dpk: &'static str,
    expected_chain_code: &'static str,
) {
    use std::str::FromStr;

    let derivation_path = derivation_path
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    let args = EcdsaPublicKeyArgs {
        canister_id: Some(ic_pub_key::CanisterId::from_str(canister_id).unwrap()),
        derivation_path,
        key_id: EcdsaKeyId {
            curve,
            name: key_name.to_string(),
        },
    };

    let dpk = derive_ecdsa_key(&args).unwrap();

    assert_eq!(hex::encode(dpk.public_key), expected_dpk);
    assert_eq!(hex::encode(dpk.chain_code), expected_chain_code);
}

#[cfg(feature = "secp256k1")]
fn test_ecdsa_secp256k1_derivation(
    key_name: &'static str,
    canister_id: &'static str,
    derivation_path: &[&'static str],
    expected_dpk: &'static str,
    expected_chain_code: &'static str,
) {
    test_ecdsa_derivation(
        EcdsaCurve::Secp256k1,
        key_name,
        canister_id,
        derivation_path,
        expected_dpk,
        expected_chain_code,
    );
}

#[cfg(feature = "secp256r1")]
fn test_ecdsa_secp256r1_derivation(
    key_name: &'static str,
    canister_id: &'static str,
    derivation_path: &[&'static str],
    expected_dpk: &'static str,
    expected_chain_code: &'static str,
) {
    test_ecdsa_derivation(
        EcdsaCurve::Secp256r1,
        key_name,
        canister_id,
        derivation_path,
        expected_dpk,
        expected_chain_code,
    );
}

#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
fn test_schnorr_derivation(
    algorithm: SchnorrAlgorithm,
    key_name: &'static str,
    canister_id: &'static str,
    derivation_path: &[&'static str],
    expected_dpk: &'static str,
) {
    use std::str::FromStr;

    let derivation_path = derivation_path
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    let args = SchnorrPublicKeyArgs {
        canister_id: Some(ic_pub_key::CanisterId::from_str(canister_id).unwrap()),
        derivation_path,
        key_id: SchnorrKeyId {
            algorithm,
            name: key_name.to_string(),
        },
    };

    let dpk = derive_schnorr_key(&args).unwrap();

    assert_eq!(hex::encode(dpk.public_key), expected_dpk,);
}

#[cfg(feature = "ed25519")]
fn test_ed25519_derivation(
    key_name: &'static str,
    canister_id: &'static str,
    derivation_path: &[&'static str],
    expected_dpk: &'static str,
) {
    test_schnorr_derivation(
        SchnorrAlgorithm::Ed25519,
        key_name,
        canister_id,
        derivation_path,
        expected_dpk,
    );
}

#[cfg(feature = "secp256k1")]
fn test_bip340_derivation(
    key_name: &'static str,
    canister_id: &'static str,
    derivation_path: &[&'static str],
    expected_dpk: &'static str,
) {
    test_schnorr_derivation(
        SchnorrAlgorithm::Bip340secp256k1,
        key_name,
        canister_id,
        derivation_path,
        expected_dpk,
    );
}

#[cfg(feature = "ed25519")]
#[test]
fn test_ed25519_derivation_key1() {
    test_ed25519_derivation(
        "key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &["Test", "Derivation", "For", "Mainnet", "Ed25519", "key_1"],
        "cf261202d0c17f5592cf405242bcf94f8c991aa9422bd883dcfc19f610851151",
    );
}

#[cfg(feature = "ed25519")]
#[test]
fn test_ed25519_derivation_test_key1() {
    test_ed25519_derivation(
        "test_key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &["Hello", "Threshold", "Signatures"],
        "d9a2ce6a3cd33fe16dce37e045609e51ff516e93bb51013823d6d7a915e3cfb9",
    );

    test_ed25519_derivation(
        "test_key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "Mainnet",
            "Ed25519",
            "test_key_1",
        ],
        "064e78c285d836b64dfe6d55add48212537ee32f34d35da149479cf03bd040e9",
    );
}

#[cfg(feature = "ed25519")]
#[test]
fn test_ed25519_derivation_pocketic_key1() {
    test_ed25519_derivation(
        "pocketic_key_1",
        "uzt4z-lp777-77774-qaabq-cai",
        &["Test", "Derivation", "For", "PocketIC", "Ed25519", "key_1"],
        "41a958daab5eded78e32e06be097ff85563a0d71230114bf52cfb7d633110393",
    );
}

#[cfg(feature = "ed25519")]
#[test]
fn test_ed25519_derivation_pocketic_test_key1() {
    test_ed25519_derivation(
        "pocketic_test_key_1",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "Ed25519",
            "test_key_1",
        ],
        "6a0d9ea275f24797b451a42b824bda2a8576d35c73de08417092cbe0128849dc",
    );
}

#[cfg(feature = "ed25519")]
#[test]
fn test_ed25519_derivation_pocketic_dfx_test_key() {
    test_ed25519_derivation(
        "dfx_test_key",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "Ed25519",
            "dfx_test_key",
        ],
        "3e9346f7c29d9c3a651309edbf92afbe1ac2eb6c02f2d384f6c105a5b6e8c75f",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_bip340_derivation_key1() {
    test_bip340_derivation(
        "key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "Mainnet",
            "Bip340secp256k1",
            "key_1",
        ],
        "03743bccf4e532c3de0d52d6556b769dc18c3cc534217ec4d98fc5a7efdda9a253",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_bip340_derivation_test_key1() {
    test_bip340_derivation(
        "test_key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &["Hello", "Threshold", "Signatures"],
        "0237ca6a41c1db8ab40410445250a5d46fbec7f3e449c8f40f86d8622a4106cebd",
    );

    test_bip340_derivation(
        "test_key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "Mainnet",
            "Bip340secp256k1",
            "test_key_1",
        ],
        "037fbabc0e6a22444d395f100cb35a3565eef953436e7397ce0e0bf2671bd4fd36",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_bip340_derivation_pocketic_key1() {
    test_bip340_derivation(
        "pocketic_key_1",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "Bip340secp256k1",
            "key_1",
        ],
        "024f77f16549f46e56ef2d33223487dddce3ca4fab7368e2b2cb5c03286d59756a",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_bip340_derivation_pocketic_test_key1() {
    test_bip340_derivation(
        "pocketic_test_key_1",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "Bip340secp256k1",
            "test_key_1",
        ],
        "029b3356b7f6070eb611f88a9a0ea1071131269ed4a6765ce8809796d048aafb33",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_bip340_derivation_pocketic_dfx_test_key() {
    test_bip340_derivation(
        "dfx_test_key",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "Bip340secp256k1",
            "dfx_test_key",
        ],
        "02cf1cf363bf09db82d48a8e18a58abbc7d95a9c9e85167a6cc5dea5d81cac2904",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_ecdsa_secp256k1_derivation_key1() {
    test_ecdsa_secp256k1_derivation(
        "key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "Mainnet",
            "ECDSA",
            "secp256k1",
            "key_1",
        ],
        "03e99cc5403dfefbc1de767ab34b637ab93c11cecffe89d6475e9701cffa2d51b4",
        "e4613655c9f0c9daa769ac5215cd4ef28d02f424c32a0b702a9cd89cbfbf28d7",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_ecdsa_secp256k1_derivation_test_key1() {
    test_ecdsa_secp256k1_derivation(
        "test_key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &["Hello", "Threshold", "Signatures"],
        "0315ae8bb8c6e9f78eec2167f5ac773067f37a39da1a1efbc585f9e90658d1c620",
        "366057592ee6212c33dd76f5b4de2ac44a20e861078347fc77d252cbc9d70a5c",
    );

    test_ecdsa_secp256k1_derivation(
        "test_key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "Mainnet",
            "ECDSA",
            "secp256k1",
            "test_key_1",
        ],
        "0262c4eb6534f278ceebcc8f4172d38acf7d76e1c74ee1e10f362d59f73658ae50",
        "95040337537953fc480879186261f689c7fa6a99aab1d1c27c1245692cfa8455",
    );
}

#[cfg(feature = "secp256r1")]
#[test]
fn test_ecdsa_secp256r1_derivation_key1() {
    test_ecdsa_secp256r1_derivation(
        "key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "Mainnet",
            "ECDSA",
            "secp256r1",
            "key_1",
        ],
        "02cda0a98456eaf736d750a6b3885433df81b9a5e76c2ee74e4552d9de1a3b38a5",
        "a06fa0ac7c5d36631ee816b70a423d35c50af364d589c3e71e956a5b5e4457b4",
    );
}

#[cfg(feature = "secp256r1")]
#[test]
fn test_ecdsa_secp256r1_derivation_test_key1() {
    test_ecdsa_secp256r1_derivation(
        "test_key_1",
        "h5jwf-5iaaa-aaaan-qmvoa-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "Mainnet",
            "ECDSA",
            "secp256r1",
            "test_key_1",
        ],
        "038bee03c1155d5b11e08b90fbdebb584c84ba617b916498b9c3d7bdc7a3d32eb8",
        "5bea193fe95011f0274a55679d441b9f822abfd829a6482a9b259dc3ed9215e5",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_ecdsa_secp256k1_derivation_pocketic_key1() {
    test_ecdsa_secp256k1_derivation(
        "pocketic_key_1",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "ECDSA",
            "secp256k1",
            "key_1",
        ],
        "03bca84b5629dc70a37cadb5b3cda0bfc35abc5658f1d9bf8335b10199785a3836",
        "69797aab9c7b3d2498669bab8c5c77656ba168159c9173544d60a6e9c3d7cf25",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_ecdsa_secp256k1_derivation_pocketic_test_key1() {
    test_ecdsa_secp256k1_derivation(
        "pocketic_test_key_1",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "ECDSA",
            "secp256k1",
            "test_key_1",
        ],
        "022ff35c84bd4cf899707789cfe5db76ce4a650563e678c53e8b128cb4bf4c3763",
        "603256c83731d211d638aacfbb82b1964eaabf257dbdcfcf8c2bce5d8c41a425",
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_ecdsa_secp256k1_derivation_pocketic_dfx_test_key() {
    test_ecdsa_secp256k1_derivation(
        "dfx_test_key",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "ECDSA",
            "secp256k1",
            "dfx_test_key",
        ],
        "03f005cf69911ae75f622ce0a621ccddba1a30ea1f6c3d67dd56acbbddb88a9374",
        "a0898d1325d632c5851045f32a70f9b635ac74d6eb42a0d4029e8bb5570f4b14",
    );
}

#[cfg(feature = "secp256r1")]
#[test]
fn test_ecdsa_secp256r1_derivation_pocketic_key1() {
    test_ecdsa_secp256r1_derivation(
        "pocketic_key_1",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "ECDSA",
            "secp256r1",
            "key_1",
        ],
        "02d3536db48ecef1eb8249f04553046902fbe7d979140530e5294452b94f0e38ad",
        "5bda5d523723999fcac4a482118b98b23faef6a9a0968c8984393891ca10a11b",
    );
}

#[cfg(feature = "secp256r1")]
#[test]
fn test_ecdsa_secp256r1_derivation_pocketic_test_key1() {
    test_ecdsa_secp256r1_derivation(
        "pocketic_test_key_1",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "ECDSA",
            "secp256r1",
            "test_key_1",
        ],
        "03080d5850ca18f277d7f39c3cfd37635b6527a73ba63b774d26d4cdf725e1ce39",
        "2ceb3a125d9d9a936b6da671f8b185da23d295ee84855adbca671598c728ff75",
    );
}

#[cfg(feature = "secp256r1")]
#[test]
fn test_ecdsa_secp256r1_derivation_pocketic_dfx_test_key() {
    test_ecdsa_secp256r1_derivation(
        "dfx_test_key",
        "uzt4z-lp777-77774-qaabq-cai",
        &[
            "Test",
            "Derivation",
            "For",
            "PocketIC",
            "ECDSA",
            "secp256r1",
            "dfx_test_key",
        ],
        "036cd2e52401b60ec8b86041f9c624438eb69ab271def9c9a439bd9fb49fa88ac7",
        "3599e883d6781d34d0bf342c0ac973d67fd06e72a93a6fbad691da461d4076f2",
    );
}

#[cfg(any(feature = "secp256k1", feature = "secp256r1"))]
fn test_ecdsa_derivation_rejects_unknown_key(curve: EcdsaCurve) {
    use std::str::FromStr;

    let args = EcdsaPublicKeyArgs {
        canister_id: Some(ic_pub_key::CanisterId::from_str("h5jwf-5iaaa-aaaan-qmvoa-cai").unwrap()),
        derivation_path: vec![],
        key_id: EcdsaKeyId {
            curve,
            name: "key_2".to_string(),
        },
    };

    assert_eq!(
        derive_ecdsa_key(&args).unwrap_err(),
        Error::UnknownKeyIdentifier
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_ecdsa_secp256k1_derivation_rejects_unknown_key() {
    test_ecdsa_derivation_rejects_unknown_key(EcdsaCurve::Secp256k1);
}

#[cfg(feature = "secp256r1")]
#[test]
fn test_ecdsa_secp256r1_derivation_rejects_unknown_key() {
    test_ecdsa_derivation_rejects_unknown_key(EcdsaCurve::Secp256r1);
}

#[test]
fn test_vetkd_derivation_using_test_key_1() {
    // This test data was generated on mainnet using test_key_1

    let canister_id = CanisterId::from_text("urq22-tyaaa-aaaag-audia-cai").unwrap();

    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "test_key_1".to_string(),
    };

    let args = VetKDPublicKeyArgs {
        canister_id: Some(canister_id),
        context: vec![],
        key_id: key_id.clone(),
    };

    let master_key = MasterPublicKey::try_from(&key_id).expect("Bad key id");
    let canister_key = derive_vetkd_key(&args).unwrap();

    assert_eq!(
        hex::encode(&canister_key.public_key),
        "8b961f06d392367e84136088971c4808b434e5d6b928b60fa6177f811db9930e4f2a911ef517db40f7e7897588ae0e2316500dbef3abf08ad7f63940af0cf816c2c1c234943c9bb6f4d53da121dceed093d118d0bd5552740da315eac3b59b0f",
    );

    assert_eq!(
        hex::encode(master_key.derive_canister_key(&canister_id).serialize()),
        hex::encode(&canister_key.public_key),
    );

    assert_eq!(
        hex::encode(
            master_key
                .derive_canister_key(&canister_id)
                .derive_key_with_context(&[])
                .serialize()
        ),
        hex::encode(&canister_key.public_key),
    );

    let args = VetKDPublicKeyArgs {
        canister_id: Some(canister_id),
        context: b"context-string".to_vec(),
        key_id: key_id.clone(),
    };

    let derived_key = derive_vetkd_key(&args).unwrap();

    assert_eq!(
        hex::encode(&derived_key.public_key),
        "958a2700438db39cf848f99c80d4d1c0f42b5e6783c35abffe5acda4fdb09548a025fdf85aad8980fcf6e20c1082596310c2612a3f3034c56445ddfc32a0c3cd34a7d0fea8df06a2996c54e21e3f8361a6e633d706ff58e979858fe436c7edf3",
    );

    assert_eq!(
        hex::encode(
            master_key
                .derive_canister_key(&canister_id)
                .derive_key_with_context(b"context-string")
                .serialize()
        ),
        hex::encode(&derived_key.public_key),
    );
}

#[test]
fn test_vetkd_derivation_using_key1() {
    // This test data was generated on mainnet using key_1

    let canister_id = CanisterId::from_text("urq22-tyaaa-aaaag-audia-cai").unwrap();

    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "key_1".to_string(),
    };
    let master_key = MasterPublicKey::try_from(&key_id).expect("Bad key id");

    let args = VetKDPublicKeyArgs {
        canister_id: Some(canister_id),
        context: vec![],
        key_id: key_id.clone(),
    };

    let canister_key = derive_vetkd_key(&args).unwrap();

    assert_eq!(
        hex::encode(&canister_key.public_key),
        "a4df5fb733dc53ba0b3f8dab3f7538b2f345052072f69a5749d630d9c2b2b1c4b00af09fa1d993e1ce533996961575ad027e058e2a279ab05271c115ef27d750b6b233f12bc9f1973b203e338d43b6a7617be58d5c7195dfb809d756413bc006",
    );

    assert_eq!(
        hex::encode(master_key.derive_canister_key(&canister_id).serialize()),
        hex::encode(&canister_key.public_key),
    );

    assert_eq!(
        hex::encode(
            master_key
                .derive_canister_key(&canister_id)
                .derive_key_with_context(&[])
                .serialize()
        ),
        hex::encode(&canister_key.public_key),
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
