use ic_crypto_temp_crypto_vault::RemoteVaultEnvironment;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use proptest::prelude::any;
use proptest::result::maybe_err;
use proptest::{prop_assert_eq, proptest};
use std::sync::Arc;

mod common;
use common::proptest_config_for_delegation;

use ic_crypto_internal_csp_proptest_utils::arb_csp_secret_key_store_contains_error;
use ic_crypto_internal_csp_proptest_utils::arb_key_id;

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_sks_contains(
        key_id in arb_key_id(),
        expected_result in maybe_err(any::<bool>(), arb_csp_secret_key_store_contains_error())
    ) {
        let mut local_vault = MockLocalCspVault::new();
        local_vault
            .expect_sks_contains()
            .times(1)
            .withf(move |key_id_| {
                 *key_id_ == key_id
            })
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.sks_contains(key_id);

        prop_assert_eq!(result, expected_result);
    }
}
