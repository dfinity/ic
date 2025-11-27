use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_utils_threshold_sig_der::*;

#[test]
fn can_parse_pem_file() {
    use std::io::Write;

    let contents = r#"-----BEGIN PUBLIC KEY-----
MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAKOY3Qk9qTesCRaL
GY4Bb/WQ5wfxhiUca4hbVIRfOkPlNtXSg/AHff5QIckWPifeyRB/S9A1jjg1XdKP
5lSemYM6VVTrGhjShUwHqVmdOBJ8ofpb2+qV/2ppvxc+3OFBvA==
-----END PUBLIC KEY-----
"#;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(contents.as_bytes()).unwrap();
    let pk = parse_threshold_sig_key(tmpfile.path()).unwrap();
    assert_eq!(
        hex::encode(&pk.into_bytes()[..]),
        "a398dd093da937ac09168b198e016ff590e707f186251c6b885b54845f3a43e536d5d283f0077dfe5021c9163e27dec9107f4bd0358e38355dd28fe6549e99833a5554eb1a18d2854c07a9599d38127ca1fa5bdbea95ff6a69bf173edce141bc"
    );
}

#[test]
fn base64_decode_fails() {
    use std::io::Write;

    let contents = r#"-----BEGIN PUBLIC KEY-----
MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAKOY3Qk9qTesCRaL
GY4Bb/WQ5wfxhiUca4hbVIRfOkPlNtXSg/AHff5QIckWPifeyRB/S9A1jjg1XdKP
5lSemYM6VVTGhjShUwHqVmdOBJ8ofpb2+qV/2ppvxc+3OFBvA==
-----END PUBLIC KEY-----
"#;

    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(contents.as_bytes()).unwrap();
    let pk = parse_threshold_sig_key(tmpfile.path());
    assert!(pk.is_err());
}

#[test]
fn should_use_correct_key_size_in_der_utils() {
    assert_eq!(PUBLIC_KEY_SIZE, PublicKeyBytes::SIZE);
}

#[test]
fn test_public_key_to_der() {
    // Test vectors generated from Haskell as follows:
    // ic-ref/impl $ cabal repl ic-ref
    // …
    // Ok, 35 modules loaded.
    // *Main> import IC.Types (prettyBlob)
    // *Main IC.Types> import qualified IC.Crypto.DER as DER
    // *Main IC.Types DER> import qualified IC.Crypto.BLS as BLS
    // *Main IC.Types DER BLS> :set -XOverloadedStrings
    // *Main IC.Types DER BLS> let pk1 = BLS.toPublicKey (BLS.createKey "testseed1")
    // *Main IC.Types DER BLS> putStrLn (prettyBlob pk1)
    // 0xa7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5
    // *Main IC.Types DER BLS> putStrLn (prettyBlob (DER.encode DER.BLS pk1))
    // 0x308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100a7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5
    // *Main IC.Types DER BLS> let pk2 = BLS.toPublicKey (BLS.createKey "testseed2")
    // *Main IC.Types DER BLS> putStrLn (prettyBlob pk2)
    // 0xb613303bda180e6b474bc15183870828c54999ee3a4797c9dd00cabe59ce78e307b212884878ec437ae9fd73f5c1f13d01f34edf1e746c192f7f6e9614bc950b705b5d2825d87499c9778db2b032955badb5b4eb103b46b0f4fa476b45b784ed
    // *Main IC.Types DER BLS> putStrLn (prettyBlob (DER.encode DER.BLS pk2))
    // 0x308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100b613303bda180e6b474bc15183870828c54999ee3a4797c9dd00cabe59ce78e307b212884878ec437ae9fd73f5c1f13d01f34edf1e746c192f7f6e9614bc950b705b5d2825d87499c9778db2b032955badb5b4eb103b46b0f4fa476b45b784edu
    struct BlsPublicKey<'a> {
        raw_hex: &'a str,
        der_hex: &'a str,
    }

    let test_vectors = [
        BlsPublicKey {
            raw_hex: "a7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5",
            der_hex: "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100a7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5",
        },
        BlsPublicKey {
            raw_hex: "b613303bda180e6b474bc15183870828c54999ee3a4797c9dd00cabe59ce78e307b212884878ec437ae9fd73f5c1f13d01f34edf1e746c192f7f6e9614bc950b705b5d2825d87499c9778db2b032955badb5b4eb103b46b0f4fa476b45b784ed",
            der_hex: "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100b613303bda180e6b474bc15183870828c54999ee3a4797c9dd00cabe59ce78e307b212884878ec437ae9fd73f5c1f13d01f34edf1e746c192f7f6e9614bc950b705b5d2825d87499c9778db2b032955badb5b4eb103b46b0f4fa476b45b784ed",
        },
    ];

    for public_key in test_vectors.iter() {
        let mut bytes = [0u8; PublicKeyBytes::SIZE];
        bytes.copy_from_slice(&hex::decode(public_key.raw_hex).unwrap());
        let public_key_raw = PublicKeyBytes(bytes);
        let der = hex::decode(public_key.der_hex).unwrap();

        assert_eq!(public_key_to_der(&public_key_raw.0).unwrap(), der);
        assert_eq!(
            public_key_raw,
            PublicKeyBytes(public_key_from_der(&der[..]).unwrap())
        );

        let mut buf = der.clone();
        for i in 0..der.len() {
            buf[i] = !buf[i];
            assert_ne!(public_key_from_der(&buf), Ok(public_key_raw.0));
            buf[i] = !buf[i];
        }
    }
}
