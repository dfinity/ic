use crate::vault::test_utils;
use crate::vault::test_utils::local_csp_vault::new_local_csp_vault;

#[test]
fn should_retrieve_current_public_keys() {
    test_utils::public_key_store::should_retrieve_current_public_keys(new_local_csp_vault());
}

#[test]
fn should_retrieve_last_idkg_public_key() {
    test_utils::public_key_store::should_retrieve_last_idkg_public_key(new_local_csp_vault());
}
