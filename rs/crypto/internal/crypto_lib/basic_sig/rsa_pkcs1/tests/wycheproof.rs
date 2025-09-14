use ic_crypto_internal_basic_sig_rsa_pkcs1::*;
use ic_types::crypto::CryptoError;
use wycheproof::rsa_pkcs1_verify::{Test, TestGroup};
use wycheproof::{HashFunction, TestResult, rsa_pkcs1_verify};

#[test]
fn should_pass_wycheproof_tests() {
    execute_rsa_pkcs1_verify_wycheproof_tests(rsa_pkcs1_verify::TestName::Rsa2048Sha256);
    execute_rsa_pkcs1_verify_wycheproof_tests(rsa_pkcs1_verify::TestName::Rsa3072Sha256);
    execute_rsa_pkcs1_verify_wycheproof_tests(rsa_pkcs1_verify::TestName::Rsa4096Sha256);
}

fn execute_rsa_pkcs1_verify_wycheproof_tests(test_name: rsa_pkcs1_verify::TestName) {
    let test_set = rsa_pkcs1_verify::TestSet::load(test_name).expect("Unable to load test data");
    for test_group in &test_set.test_groups {
        execute_test_group(test_group)
    }
}

fn execute_test_group(test_group: &TestGroup) {
    if test_group.hash != HashFunction::Sha2_256 {
        return;
    }
    if let Some(public_key) = public_key_of_supported_size(test_group) {
        let public_key_from_components =
            RsaPublicKey::from_components(&test_group.key.e, &test_group.key.n)
                .expect("Unable to parse test key");
        assert_eq!(public_key.as_der(), public_key_from_components.as_der());

        for test in &test_group.tests {
            verify_signature(&public_key, test);
        }
    }
}

fn verify_signature(public_key: &RsaPublicKey, test: &Test) {
    let verification_result = public_key.verify_pkcs1_sha256(&test.msg, &test.sig);

    let expected_ok = test.result == TestResult::Valid;

    assert_eq!(
        verification_result.is_ok(),
        expected_ok,
        "Test failed: {test:?}\nVerification result: {verification_result:?}"
    );
}

fn public_key_of_supported_size(test_group: &TestGroup) -> Option<RsaPublicKey> {
    match RsaPublicKey::from_der_spki(&test_group.der) {
        Ok(public_key) => Some(public_key),
        Err(CryptoError::MalformedPublicKey { .. }) => {
            assert!(
                test_group.key_size < RsaPublicKey::MINIMUM_RSA_KEY_SIZE
                    || test_group.key_size > RsaPublicKey::MAXIMUM_RSA_KEY_SIZE
            );
            None
        }
        Err(e) => panic!("Unexpected error {e:?}"),
    }
}
