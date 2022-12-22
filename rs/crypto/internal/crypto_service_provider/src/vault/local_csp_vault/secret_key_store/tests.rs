//! Verifies the implementation of SecretKeyStoreCspVault for LocalCspVault.
use crate::vault::test_utils;
use crate::LocalCspVault;

#[test]
fn key_should_be_present_only_after_generation() {
    test_utils::sks::sks_should_contain_keys_only_after_generation(
        LocalCspVault::builder().build_into_arc(),
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn tls_key_should_be_present_only_after_generation() {
    test_utils::sks::sks_should_contain_tls_keys_only_after_generation(
        LocalCspVault::builder().build_into_arc(),
        LocalCspVault::builder().build_into_arc(),
    );
}
