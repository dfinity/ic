//! Verifies the implementation of SecretKeyStoreCspVault for LocalCspVault.
use crate::vault::local_csp_vault::test_utils::new_csp_vault;
use crate::vault::test_utils;

#[test]
fn key_should_be_present_only_after_generation() {
    test_utils::sks_should_contain_keys_only_after_generation(new_csp_vault(), new_csp_vault());
}
