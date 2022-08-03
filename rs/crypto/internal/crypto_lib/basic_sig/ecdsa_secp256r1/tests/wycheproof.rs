use ic_crypto_internal_basic_sig_ecdsa_secp256r1::*;
use openssl::sha::sha256;
use std::convert::TryFrom;
use wycheproof::ecdsa::*;

#[test]
fn should_pass_wycheproof_test_vectors() {
    let test_name = TestName::EcdsaSecp256r1Sha256P1363;

    let test_set = TestSet::load(test_name).expect("Unable to load test data");

    for test_group in &test_set.test_groups {
        let key = match api::public_key_from_der(&test_group.der).ok() {
            Some(key) => key,
            None => {
                assert_eq!(test_group.tests.len(), 0);
                continue;
            }
        };

        for test in &test_group.tests {
            let sig = match types::SignatureBytes::try_from(test.sig.clone()).ok() {
                None => {
                    assert!(test.result.must_fail() || test.flags.contains(&TestFlag::SigSize));
                    continue;
                }
                Some(sig) => sig,
            };

            let msg_hash = sha256(&test.msg);

            let sig_accepted = api::verify(&sig, &msg_hash, &key).is_ok();

            assert_eq!(!sig_accepted, test.result.must_fail());
        }
    }
}
