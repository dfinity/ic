use ic_crypto_internal_threshold_sig_canister_threshold_sig::*;

#[test]
fn test_hash2curve_kat_p256() -> Result<(), CanisterThresholdError> {
    let curve = EccCurveType::P256;

    /*
    The following tests are taken from section J.1.1 of RFC 9380
    https://www.rfc-editor.org/rfc/rfc9380.html#name-p256_xmdsha-256_sswu_ro_

    For all tests in the draft, the same domain separator is used.
    */

    let dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

    let test_vectors = [
        (
            "".to_string(),
            "032c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
        ),
        (
            "abc".to_string(),
            "020bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
        ),
        (
            "abcdef0123456789".to_string(),
            "0365038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
        ),
        (
            format!("q128_{}", vec!['q'; 128].iter().collect::<String>()),
            "024be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
        ),
        (
            format!("a512_{}", vec!['a'; 512].iter().collect::<String>()),
            "02457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
        ),
    ];

    for (input, pt) in &test_vectors {
        let h2c = EccPoint::hash_to_point(curve, input.as_bytes(), dst.as_bytes())?;
        assert_eq!(&hex::encode(h2c.serialize()), pt);
    }

    Ok(())
}

#[test]
fn test_hash2curve_kat_k256() -> Result<(), CanisterThresholdError> {
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
            "03c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
        ),
        (
            "abc".to_string(),
            "023377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
        ),
        (
            "abcdef0123456789".to_string(),
            "02bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a",
        ),
        (
            format!("q128_{}", vec!['q'; 128].iter().collect::<String>()),
            "03e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9",
        ),
        (
            format!("a512_{}", vec!['a'; 512].iter().collect::<String>()),
            "02e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998",
        ),
    ];

    for (input, pt) in &test_vectors {
        let h2c = EccPoint::hash_to_point(curve, input.as_bytes(), dst.as_bytes())?;
        assert_eq!(&hex::encode(h2c.serialize()), pt);
    }
    Ok(())
}

#[test]
fn test_hash2curve_kat_ed25519() -> Result<(), CanisterThresholdError> {
    let curve = EccCurveType::Ed25519;
    let dst = "QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_";

    /*
    The following tests are taken from section J.5.1 of RFC 9380
    https://www.rfc-editor.org/rfc/rfc9380.html#name-edwards25519_xmdsha-512_ell

    For all tests in the draft, the same domain separator is used.

    Unlike SEC1, Ed25519 uses the full encoding of y plus the sign of x.
    The sign of x appears in the high bit of the encoding.
    */

    let test_vectors = [
        (
            "".to_string(),
            "09a6c8561a0b22bef63124c588ce4c62ea83a3c899763af26d795302e115dc21",
        ),
        (
            "abc".to_string(),
            // 9a not 1a because x is odd so the high bit is set
            "9a8395b88338f22e435bbd301183e7f20a5f9de643f11882fb237f88268a5531",
        ),
        (
            "abcdef0123456789".to_string(),
            "53060a3d140e7fbcda641ed3cf42c88a75411e648a1add71217f70ea8ec561a6",
        ),
        (
            format!("q128_{}", vec!['q'; 128].iter().collect::<String>()),
            "2eca15e355fcfa39d2982f67ddb0eea138e2994f5956ed37b7f72eea5e89d2f7",
        ),
        (
            format!("a512_{}", vec!['a'; 512].iter().collect::<String>()),
            "6dc2fc04f266c5c27f236a80b14f92ccd051ef1ff027f26a07f8c0f327d8f995",
        ),
    ];

    for (input, pt) in &test_vectors {
        let h2c = EccPoint::hash_to_point(curve, input.as_bytes(), dst.as_bytes())?;
        /*

        RFC 9380 prints the x and y coordinates in big endian, while
        Ed25519 uses little endian.

        We hardcode the vectors following RFC 9380 and then reverse the
        value here.
         */

        let mut pt_bytes = h2c.serialize();
        pt_bytes.reverse();

        assert_eq!(&hex::encode(pt_bytes), pt);
    }
    Ok(())
}
