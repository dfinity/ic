use ic_crypto_internal_csp_proptest_utils::{
    arb_csp_public_key_store_error, arb_current_node_public_keys,
};
use ic_crypto_temp_crypto_vault::RemoteVaultEnvironment;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use proptest::prelude::any;
use proptest::result::maybe_err;
use proptest::{prop_assert_eq, proptest};
use std::sync::Arc;

mod common;
use common::proptest_config_for_delegation;

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_current_node_public_keys(
        expected_result in maybe_err(arb_current_node_public_keys(), arb_csp_public_key_store_error())
    ) {
        let mut local_vault = MockLocalCspVault::new();
        local_vault
            .expect_current_node_public_keys()
            .times(1)
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.current_node_public_keys();

        prop_assert_eq!(result, expected_result);
    }
}

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_current_node_public_keys_with_timestamps(
        expected_result in maybe_err(arb_current_node_public_keys(), arb_csp_public_key_store_error())
    ) {
        let mut local_vault = MockLocalCspVault::new();
        local_vault
            .expect_current_node_public_keys_with_timestamps()
            .times(1)
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.current_node_public_keys_with_timestamps();

        prop_assert_eq!(result, expected_result);
    }
}

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_idkg_dealing_encryption_pubkeys_count(
        expected_result in maybe_err(any::<usize>(), arb_csp_public_key_store_error())
    ) {
        let mut local_vault = MockLocalCspVault::new();
        local_vault
            .expect_idkg_dealing_encryption_pubkeys_count()
            .times(1)
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.idkg_dealing_encryption_pubkeys_count();

        prop_assert_eq!(result, expected_result);
    }
}
