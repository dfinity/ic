use ic_crypto_internal_seed::xmd::expand_message_xmd;
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
