//! Tests of Multi-Signature operations in the CSP vault.
use crate::vault::test_utils;
use crate::vault::test_utils::local_csp_vault::new_local_csp_vault;

#[test]
fn should_generate_key_ok() {
    test_utils::multi_sig::should_generate_multi_bls12_381_key_pair(new_local_csp_vault());
}

#[test]
fn should_fail_to_generate_key_for_wrong_algorithm_id() {
    test_utils::multi_sig::should_fail_to_generate_multi_sig_key_for_wrong_algorithm_id(
        new_local_csp_vault(),
    );
}

#[test]
fn should_generate_verifiable_pop() {
    test_utils::multi_sig::should_generate_verifiable_pop(new_local_csp_vault());
}

#[test]
fn should_multi_sign_and_verify_with_generated_key() {
    test_utils::multi_sig::should_multi_sign_and_verify_with_generated_key(new_local_csp_vault());
}

#[test]
fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
    test_utils::multi_sig::should_not_multi_sign_with_unsupported_algorithm_id(
        new_local_csp_vault(),
    );
}

#[test]
fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
    test_utils::multi_sig::should_not_multi_sign_if_secret_key_in_store_has_wrong_type(
        new_local_csp_vault(),
    );
}
