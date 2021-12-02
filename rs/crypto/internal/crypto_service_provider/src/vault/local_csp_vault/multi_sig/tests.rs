//! Tests of Multi-Signature operations in the CSP vault.
use crate::vault::local_csp_vault::test_utils::new_csp_vault;
use crate::vault::test_utils;

#[test]
fn should_generate_key_ok() {
    test_utils::should_generate_multi_bls12_381_key_pair(new_csp_vault());
}

#[test]
fn should_fail_to_generate_key_for_wrong_algorithm_id() {
    test_utils::should_fail_to_generate_multi_sig_key_for_wrong_algorithm_id(new_csp_vault());
}

#[test]
fn should_generate_verifiable_pop() {
    test_utils::should_generate_verifiable_pop(new_csp_vault());
}

#[test]
fn should_multi_sign_and_verify_with_generated_key() {
    test_utils::should_multi_sign_and_verify_with_generated_key(new_csp_vault());
}

#[test]
fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
    test_utils::should_not_multi_sign_with_unsupported_algorithm_id(new_csp_vault());
}

#[test]
fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
    test_utils::should_not_multi_sign_if_secret_key_in_store_has_wrong_type(new_csp_vault());
}
