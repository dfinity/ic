use assert_matches::assert_matches;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_csp::types::{CspPublicKey, CspSignature};
use ic_crypto_internal_csp_proptest_utils::{
    arb_csp_basic_signature_error, arb_csp_basic_signature_keygen_error, arb_csp_public_key,
    arb_csp_signature,
};
use ic_crypto_temp_crypto_vault::RemoteVaultEnvironment;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use proptest::collection::vec;
use proptest::prelude::any;
use proptest::result::maybe_err;
use proptest::{prop_assert_eq, proptest};
use std::sync::Arc;

mod common;
use common::{local_vault_in_temp_dir, proptest_config_for_delegation};

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_sign(
        message in vec(any::<u8>(), 0..1024),
        expected_result in maybe_err(arb_csp_signature(), arb_csp_basic_signature_error())
    ) {
        let expected_message = message.clone();
        let mut local_vault = MockLocalCspVault::new();
        local_vault
            .expect_sign()
            .times(1)
            .withf(move |message_| {
                message_ == &expected_message
            })
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.sign(message);

        prop_assert_eq!(result, expected_result);
    }
}

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_gen_node_signing_key_pair(
        expected_result in maybe_err(arb_csp_public_key(), arb_csp_basic_signature_keygen_error())
    ) {
        let mut local_vault = MockLocalCspVault::new();
        local_vault
            .expect_gen_node_signing_key_pair()
            .times(1)
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.gen_node_signing_key_pair();

        prop_assert_eq!(result, expected_result);
    }
}

#[test]
fn should_sign_a_large_hundred_megabytes_message() {
    const HUNDRED_MEGA_BYTES: usize = 100 * 1024 * 1024;
    let message = vec![0_u8; HUNDRED_MEGA_BYTES];
    let (vault, _temp_dir) = local_vault_in_temp_dir();
    let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(vault));
    let remote_vault = env.new_vault_client();

    let node_signing_public_key = remote_vault
        .gen_node_signing_key_pair()
        .expect("failed to generate keys");

    let signature = remote_vault
        .sign(message.clone())
        .expect("could not sign large message");

    match (node_signing_public_key, signature) {
        (CspPublicKey::Ed25519(public_key_bytes), CspSignature::Ed25519(signature_bytes)) => {
            let verification = ed25519::verify(&signature_bytes, &message, &public_key_bytes);
            assert_matches!(verification, Ok(()))
        }
        _ => panic!("unexpected type for node signing public key or signature"),
    }
}
