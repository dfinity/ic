use ic_crypto_temp_crypto_vault::RemoteVaultEnvironment;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use proptest::collection::vec;
use proptest::prelude::any;
use proptest::result::maybe_err;
use proptest::{prop_assert_eq, proptest};
use std::sync::Arc;

mod common;
use common::proptest_config_for_delegation;
use ic_crypto_internal_csp_proptest_utils::{
    arb_csp_signature, arb_csp_tls_keygen_error, arb_csp_tls_sign_error, arb_key_id, arb_node_id,
};
use ic_crypto_test_utils_keys::public_keys::valid_tls_certificate_and_validation_time;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use proptest::{prelude::Just, result::maybe_err_weighted};

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_gen_tls_key_pair(
        node_id in arb_node_id(),
        expected_result in maybe_err_weighted(0.95, Just(valid_tls_public_key_cert()), arb_csp_tls_keygen_error())
    ) {
        let mut local_vault = MockLocalCspVault::new();
        local_vault
            .expect_gen_tls_key_pair()
            .times(1)
            .withf(move |node_id_| {
                *node_id_ == node_id
            })
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.gen_tls_key_pair(node_id);

        prop_assert_eq!(result, expected_result);
    }
}

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_tls_sign(
        message in vec(any::<u8>(), 0..1024),
        key_id in arb_key_id(),
        expected_result in maybe_err(arb_csp_signature(), arb_csp_tls_sign_error())
    ) {
        let expected_message = message.clone();
        let mut local_vault = MockLocalCspVault::new();
        local_vault
            .expect_tls_sign()
            .times(1)
            .withf(move |message_, key_id_| {
                *message_ == expected_message && *key_id_ == key_id
            })
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.tls_sign(message, key_id);

        prop_assert_eq!(result, expected_result);
    }
}

fn valid_tls_public_key_cert() -> TlsPublicKeyCert {
    TlsPublicKeyCert::try_from(valid_tls_certificate_and_validation_time().0)
        .expect("valid TLS certificate")
}
