use ic_crypto_internal_threshold_sig_ecdsa::*;

fn xmd_check(msg: &str, dst: &str, want: &str) {
    let x = expand_message_xmd(msg.as_bytes(), dst.as_bytes(), want.len() / 2).expect("XMD failed");
    assert_eq!(hex::encode(x), want);
}

#[test]
fn expand_message_xmd_test() {
    // Check we can handle lengths that are not a perfect multiple of 32.
    let x = expand_message_xmd(b"foo", b"bar", 123).expect("XMD failed");
    assert_eq!(x.len(), 123);

    // Test cases from Appendix K.
    xmd_check(
        "",
        "QUUX-V01-CS02-with-expander-SHA256-128",
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
    );
    xmd_check(
        "abc",
        "QUUX-V01-CS02-with-expander-SHA256-128",
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
    );
    xmd_check("", "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
              "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3");
    xmd_check("abc", "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
              "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12");
}

#[test]
fn test_hash2curve_kat_p256() -> Result<(), ThresholdEcdsaError> {
    let curve = EccCurveType::P256;

    /*
    The following tests are taken from section J.1.1 of the hash to curve draft:
    https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-14.html#name-p256_xmdsha-256_sswu_ro_

    For all tests in the draft, the same domain separator is used.
    */

    let dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

    let test_vectors = [
        (
            "".to_string(),
            "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
            "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
        ),
        (
            "abc".to_string(),
            "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
            "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
        ),
        (
            "abcdef0123456789".to_string(),
            "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
            "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
        ),
        (
            format!("q128_{}", vec!['q'; 128].iter().collect::<String>()),
            "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
            "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e",
        ),
        (
            format!("a512_{}", vec!['a'; 512].iter().collect::<String>()),
            "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
            "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc",
        ),
    ];

    for (input, pt_x, pt_y) in &test_vectors {
        let pt = EccPoint::hash_to_point(curve, input.as_bytes(), dst.as_bytes())?;
        assert_eq!(&hex::encode(pt.affine_x()?.as_bytes()), pt_x);
        assert_eq!(&hex::encode(pt.affine_y()?.as_bytes()), pt_y);
    }

    Ok(())
}

#[test]
fn test_hash2curve_kat_k256() -> Result<(), ThresholdEcdsaError> {
    let curve = EccCurveType::K256;
    let dst = "QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

    /*
    The following tests are taken from section J.8.1 of the hash to curve draft:
    https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-14.html#name-secp256k1_xmdsha-256_sswu_r

    For all tests in the draft, the same domain separator is used.
    */

    let test_vectors = [
        (
            "".to_string(),
            "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
            "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067",
        ),
        (
            "abc".to_string(),
            "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
            "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6",
        ),
        (
            "abcdef0123456789".to_string(),
            "bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a",
            "4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828",
        ),
        (
            format!("q128_{}", vec!['q'; 128].iter().collect::<String>()),
            "e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9",
            "f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873",
        ),
        (
            format!("a512_{}", vec!['a'; 512].iter().collect::<String>()),
            "e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998",
            "8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6",
        ),
    ];

    for (input, pt_x, pt_y) in &test_vectors {
        let pt = EccPoint::hash_to_point(curve, input.as_bytes(), dst.as_bytes())?;
        assert_eq!(&hex::encode(pt.affine_x()?.as_bytes()), pt_x);
        assert_eq!(&hex::encode(pt.affine_y()?.as_bytes()), pt_y);
    }
    Ok(())
}
