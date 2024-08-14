use ic_crypto_temp_crypto_vault::RemoteVaultEnvironment;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use proptest::prelude::any;
use proptest::result::maybe_err;
use proptest::{prop_assert_eq, proptest};
use std::sync::Arc;

mod common;
use common::proptest_config_for_delegation;

use ic_crypto_internal_csp_proptest_utils::{
    arb_external_public_keys, arb_pks_and_sks_contains_errors, arb_validate_pks_and_sks_error,
};
use ic_crypto_node_key_validation::{ValidNodePublicKeys, ValidNodeSigningPublicKey};
use ic_crypto_test_utils_keys::public_keys::{
    valid_committee_signing_public_key, valid_dkg_dealing_encryption_public_key,
    valid_idkg_dealing_encryption_public_key, valid_node_signing_public_key,
    valid_tls_certificate_and_validation_time,
};
use ic_types::crypto::CurrentNodePublicKeys;
use proptest::prelude::Just;
use proptest::result::maybe_err_weighted;

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_pks_and_sks_contains(
        external_public_keys in arb_external_public_keys(),
        expected_result in maybe_err(any::<()>(), arb_pks_and_sks_contains_errors())
    ) {
        let mut local_vault = MockLocalCspVault::new();
        let expected_external_public_keys = external_public_keys.clone();
        local_vault
            .expect_pks_and_sks_contains()
            .times(1)
            .withf(move |external_public_keys_| {
                 *external_public_keys_ == expected_external_public_keys
            })
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.pks_and_sks_contains(external_public_keys);

        prop_assert_eq!(result, expected_result);
    }
}

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_validate_pks_and_sks(
        expected_result in maybe_err_weighted(0.95, Just(valid_node_public_keys()), arb_validate_pks_and_sks_error())
    ) {
        let mut local_vault = MockLocalCspVault::new();
        local_vault
            .expect_validate_pks_and_sks()
            .times(1)
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.validate_pks_and_sks();

        prop_assert_eq!(result, expected_result);
    }
}

fn valid_node_public_keys() -> ValidNodePublicKeys {
    let node_id = *ValidNodeSigningPublicKey::try_from(valid_node_signing_public_key())
        .expect("invalid node signing public key")
        .derived_node_id();
    let (valid_tls_certificate, validation_time) = valid_tls_certificate_and_validation_time();
    ValidNodePublicKeys::try_from(
        CurrentNodePublicKeys {
            node_signing_public_key: Some(valid_node_signing_public_key()),
            committee_signing_public_key: Some(valid_committee_signing_public_key()),
            tls_certificate: Some(valid_tls_certificate),
            dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
            idkg_dealing_encryption_public_key: Some(valid_idkg_dealing_encryption_public_key()),
        },
        node_id,
        validation_time,
    )
    .expect("invalid node public keys")
}
