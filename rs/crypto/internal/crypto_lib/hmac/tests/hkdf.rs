use ic_crypto_internal_hmac::*;
use wycheproof::hkdf::*;

fn test_wycheproof_hkdf_tests<H: HmacHashFunction>(test: TestName) {
    let test_set = TestSet::load(test).expect("Could not load tests");

    for test_group in test_set.test_groups {
        for test in test_group.tests {
            let output_len = test.okm.len();

            let output = hkdf::<H>(output_len, &test.ikm, &test.salt, &test.info).unwrap();

            assert_eq!(output, test.okm.as_ref());
        }
    }
}

#[test]
fn should_pass_wycheproof_hkdf_sha256_tests() {
    test_wycheproof_hkdf_tests::<Sha256>(TestName::HkdfSha256);
}

#[test]
fn should_pass_wycheproof_hkdf_sha512_tests() {
    test_wycheproof_hkdf_tests::<Sha512>(TestName::HkdfSha512);
}

#[test]
fn should_pass_rfc5869_test() {
    let ikm = vec![0x0b; 22];
    let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];

    let okm = hkdf::<Sha256>(42, &ikm, &salt, &info).unwrap();

    assert_eq!(
        hex::encode(okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}
