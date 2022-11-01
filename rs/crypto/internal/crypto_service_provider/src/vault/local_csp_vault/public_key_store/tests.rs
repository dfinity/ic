use crate::vault::test_utils;
use crate::vault::test_utils::local_csp_vault::new_local_csp_vault;

#[test]
fn should_fail_on_unimplemented_get_current_node_public_keys() {
    // TODO: CRP-1719 add more tests
    test_utils::public_key_store::should_fail_on_unimplemented_get_current_node_public_keys(
        new_local_csp_vault(),
    );
}
