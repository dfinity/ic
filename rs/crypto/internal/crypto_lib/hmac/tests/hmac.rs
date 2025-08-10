use ic_crypto_internal_hmac::*;
use wycheproof::mac::*;

fn check_tag<H: HmacHashFunction>(hmac: Hmac<H>, expected: &[u8], must_fail: bool) {
    let mut tag = hmac.finish();
    // truncate tag to match the tests as required:
    tag.truncate(expected.len());

    if must_fail {
        assert_ne!(hex::encode(tag), hex::encode(expected));
    } else {
        assert_eq!(hex::encode(tag), hex::encode(expected));
    }
}

fn test_wycheproof_hmac_tests<H: HmacHashFunction>(test: TestName) {
    let test_set = TestSet::load(test).expect("Could not load tests");

    for test_group in test_set.test_groups {
        for test in test_group.tests {
            let mut hmac = Hmac::<H>::new(&test.key);
            hmac.write(&test.msg);
            check_tag(hmac, &test.tag, test.result.must_fail());

            // If possible, split the input into two pieces to test
            // that incremental updating works as expected
            if test.msg.len() > 1 {
                let mut hmac = Hmac::<H>::new(&test.key);
                let split = test.msg.len() / 2;
                hmac.write(&test.msg[..split]);
                hmac.write(&test.msg[split..]);
                check_tag(hmac, &test.tag, test.result.must_fail());
            }
        }
    }
}

#[test]
fn should_pass_wycheproof_hmac_sha224_tests() {
    test_wycheproof_hmac_tests::<Sha224>(TestName::HmacSha224);
}

#[test]
fn should_pass_wycheproof_hmac_sha256_tests() {
    test_wycheproof_hmac_tests::<Sha256>(TestName::HmacSha256);
}

#[test]
fn should_pass_wycheproof_hmac_sha512_tests() {
    test_wycheproof_hmac_tests::<Sha512>(TestName::HmacSha512);
}
