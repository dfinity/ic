//! Verifies the implementation of SecretKeyStoreCspVault for LocalCspVault.
use crate::vault::test_utils;
use crate::vault::test_utils::local_csp_vault::new_local_csp_vault;

#[test]
fn key_should_be_present_only_after_generation() {
    test_utils::sks::sks_should_contain_keys_only_after_generation(
        new_local_csp_vault(),
        new_local_csp_vault(),
    );
}

#[test]
fn tls_key_should_be_present_only_after_generation() {
    test_utils::sks::sks_should_contain_tls_keys_only_after_generation(
        new_local_csp_vault(),
        new_local_csp_vault(),
    );
}
