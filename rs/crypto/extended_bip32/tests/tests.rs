use ic_crypto_extended_bip32::*;

fn assert_ebip32_result(
    result: ExtendedBip32DerivationOutput,
    expected_public_key: &'static str,
    expected_chain_code: &'static str,
) {
    assert_eq!(hex::encode(result.derived_public_key), expected_public_key);
    assert_eq!(hex::encode(result.chain_code), expected_chain_code);
}

#[test]
fn verify_bip32_extended_key_derivation() -> ExtendedBip32DerivationResult<()> {
    let index1 = DerivationIndex(vec![1, 2, 3, 4, 5]);
    let index2 = DerivationIndex(vec![8, 0, 2, 8, 0, 2]);

    let chain_code = [0u8; 32];

    let master_key =
        hex::decode("02bef39a470a0fe179cd18509a791e9c5312c07d1346a223a93f723fd90c9690f2").unwrap();

    let path1 = DerivationPath::new(vec![index1.clone()]);

    assert_ebip32_result(
        path1.key_derivation(&master_key, &chain_code).unwrap(),
        "026b299d834bbb242a961192ba5a1d5663b5fa8d76d88aff93fd2a6044a524ce70",
        "5b37a4f4f656bbe83497232deab1be3a468535ca55c296f123ee8339d56100f5",
    );

    let path2 = DerivationPath::new(vec![index2.clone()]);

    assert_ebip32_result(
        path2.key_derivation(&master_key, &chain_code).unwrap(),
        "03bbe7150acce76b3d155a840a5096e334cddc6a129bd3d481a200518efa066098",
        "68db4ee9e71a592c463e70202b4d49f4408530a7e783c43625360956e6180052",
    );

    let path12 = DerivationPath::new(vec![index1, index2]);

    assert_ebip32_result(
        path12.key_derivation(&master_key, &chain_code).unwrap(),
        "02acd25bb5fbd517e5141aa5bc9b58554a96b9e9436bb285abb2090598cdcf850e",
        "8e808ba4caebadca661fd647fcc8ab5e80a1b538b7ffee7bccf3f3a01a35d19e",
    );

    Ok(())
}

fn check_bip32_result(
    input_public_key: &'static str,
    input_chain_code: &'static str,
    path: &[u32],
    expected_public_key: &'static str,
    expected_chain_code: &'static str,
) -> ExtendedBip32DerivationResult<()> {
    let input_public_key = hex::decode(input_public_key).expect("Invalid hex");
    let input_chain_code = hex::decode(input_chain_code).expect("Invalid hex");
    let path = DerivationPath::new_bip32(path);
    let result = path.key_derivation(&input_public_key, &input_chain_code)?;
    assert_eq!(hex::encode(result.derived_public_key), expected_public_key);
    assert_eq!(hex::encode(result.chain_code), expected_chain_code);

    Ok(())
}

#[test]
fn verify_bip32_standard_key_derivation() -> ExtendedBip32DerivationResult<()> {
    // See https://en.bitcoin.it/wiki/BIP_0032_TestVectors

    check_bip32_result(
        "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
        "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
        &[1],
        "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
        "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
    )?;

    check_bip32_result(
        "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
        "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
        &[2],
        "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
        "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
    )?;

    check_bip32_result(
        "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
        "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
        &[2, 1000000000],
        "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
        "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
    )?;

    check_bip32_result(
        "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
        "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
        &[0],
        "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
        "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
    )?;

    Ok(())
}
