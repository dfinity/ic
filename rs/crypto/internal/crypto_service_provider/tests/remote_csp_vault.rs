use assert_matches::assert_matches;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use ic_crypto_internal_csp::secret_key_store::proto_store::ProtoSecretKeyStore;
use ic_crypto_internal_csp::LocalCspVault;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_temp_crypto_vault::RemoteVaultEnvironment;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use ic_logger::replica_logger::no_op_logger;
use ic_types::crypto::AlgorithmId;
use proptest::collection::vec;
use proptest::prelude::any;
use proptest::prelude::ProptestConfig;
use proptest::result::maybe_err;
use proptest::{prop_assert_eq, proptest};
use rand::rngs::OsRng;
use std::sync::Arc;
use tempfile::TempDir;

mod rpc_connection {
    use super::*;
    use crate::rpc_connection::MessageLength::{Small, TooLarge};
    use ic_crypto_internal_csp::api::CspCreateMEGaKeyError;
    use ic_crypto_internal_csp::types::CspSignature;
    use ic_crypto_internal_csp::vault::api::CspBasicSignatureError::InternalError;
    use ic_crypto_internal_csp::vault::api::{
        BasicSignatureCspVault, CspBasicSignatureError, CspPublicKeyStoreError,
        IDkgProtocolCspVault, PublicKeyStoreCspVault,
    };
    use ic_crypto_internal_csp::vault::remote_csp_vault::{
        RemoteCspVault, RemoteCspVaultBuilder, TarpcCspVaultServerImplBuilder,
    };
    use std::time::Duration;

    const MAX_FRAME_LENGTH_FOR_TEST: usize = 1_000;

    #[test]
    fn should_reconnect_after_request_from_client_cannot_be_sent_because_too_large() {
        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(vault));
        let client_cannot_send_large_request = vault_client_with_short_timeouts(&env)
            .with_max_frame_length(MAX_FRAME_LENGTH_FOR_TEST)
            .build_expecting_ok();
        let node_signing_public_key = client_cannot_send_large_request
            .gen_node_signing_key_pair()
            .expect("failed generating node signing key pair");
        let key_id = KeyId::try_from(&node_signing_public_key).unwrap();

        let signature = sign_message(Small, key_id, &client_cannot_send_large_request);
        assert_matches!(signature, Ok(_));

        let signature = sign_message(TooLarge, key_id, &client_cannot_send_large_request);
        assert_matches!(signature, Err(InternalError {internal_error}) if internal_error.contains("the client failed to send the request"));

        let signature = sign_message(Small, key_id, &client_cannot_send_large_request);
        assert_matches!(signature, Ok(_));
    }

    #[test]
    fn should_reconnect_after_request_from_client_cannot_be_received_by_server_because_too_large() {
        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let server_cannot_receive_large_request =
            TarpcCspVaultServerImplBuilder::new_with_local_csp_vault(Arc::new(vault))
                .with_max_frame_length(MAX_FRAME_LENGTH_FOR_TEST);
        let env = RemoteVaultEnvironment::start_server(server_cannot_receive_large_request);
        let client = vault_client_with_short_timeouts(&env).build_expecting_ok();
        let node_signing_public_key = client
            .gen_node_signing_key_pair()
            .expect("failed generating node signing key pair");
        let key_id = KeyId::try_from(&node_signing_public_key).unwrap();

        let signature = sign_message(Small, key_id, &client);
        assert_matches!(signature, Ok(_));

        let signature = sign_message(TooLarge, key_id, &client);
        assert_matches!(signature, Err(InternalError {internal_error}) if internal_error.contains("the connection to the server was already shutdown"));

        let signature = sign_message(Small, key_id, &client);
        // TODO CRP-1822: with reconnection feature this should now be an `Ok(_)` result
        assert_matches!(signature, Err(InternalError {internal_error}) if internal_error.contains("the connection to the server was already shutdown"));
    }

    #[test]
    fn should_reconnect_after_response_from_server_cannot_be_received_by_client_because_too_large()
    {
        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(vault));
        let client_cannot_receive_large_response = vault_client_with_short_timeouts(&env)
            .with_max_frame_length(40)
            .build_expecting_ok();
        let client = &client_cannot_receive_large_response;

        assert_matches!(client.gen_node_signing_key_pair(), Ok(_)); //encoded response from server has 38 bytes
        assert_matches!(client.idkg_gen_dealing_encryption_key_pair(), Ok(_)); //encoded response from server has 39 bytes

        let keys = client.current_node_public_keys_with_timestamps(); //encoded response from server has 93 bytes
        assert_matches!(keys, Err(CspPublicKeyStoreError::TransientInternalError(msg)) if msg.contains("an error occurred while waiting for the server response"));

        // TODO CRP-1822: with reconnection feature this should now be an `Ok(_)` result
        assert_matches!(client.idkg_gen_dealing_encryption_key_pair(),
        Err(CspCreateMEGaKeyError::TransientInternalError {internal_error}) if internal_error.contains("the connection to the server was already shutdown"));
    }

    #[test]
    fn should_reconnect_after_response_from_server_cannot_be_sent_because_too_large() {
        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let server_cannot_send_large_response =
            TarpcCspVaultServerImplBuilder::new_with_local_csp_vault(Arc::new(vault))
                .with_max_frame_length(40);
        let env = RemoteVaultEnvironment::start_server(server_cannot_send_large_response);
        let client = vault_client_with_short_timeouts(&env).build_expecting_ok();
        assert_matches!(&client.gen_node_signing_key_pair(), Ok(_)); //encoded response from server has 38 bytes
        assert_matches!(&client.idkg_gen_dealing_encryption_key_pair(), Ok(_)); //encoded response from server has 39 bytes

        let keys = &client.current_node_public_keys_with_timestamps(); //encoded response from server has 93 bytes
        assert_matches!(keys, Err(CspPublicKeyStoreError::TransientInternalError(msg)) if msg.contains("the connection to the server was already shutdown"));

        // TODO CRP-1822: with reconnection feature this should now be an `Ok(_)` result
        assert_matches!(&client.idkg_gen_dealing_encryption_key_pair(),
        Err(CspCreateMEGaKeyError::TransientInternalError {internal_error}) if internal_error.contains("the connection to the server was already shutdown"));
    }

    #[test]
    fn should_reconnect_with_existing_client_after_server_killed_and_restarted() {
        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let vault = Arc::new(vault);
        let mut env = RemoteVaultEnvironment::start_server_with_local_csp_vault(vault);
        let client = vault_client_with_short_timeouts(&env).build_expecting_ok();
        let node_signing_public_key = client
            .gen_node_signing_key_pair()
            .expect("failed generating node signing key pair");
        let key_id = KeyId::try_from(&node_signing_public_key).unwrap();

        let signature = sign_message(Small, key_id, &client);
        assert_matches!(signature, Ok(_));

        env.shutdown_server_now();
        let signature = sign_message(Small, key_id, &client);
        assert_matches!(signature, Err(InternalError {internal_error}) if internal_error.contains("the connection to the server was already shutdown"));

        env.restart_server();
        let signature = sign_message(Small, key_id, &client);
        // TODO CRP-1822: with reconnection feature this should now be an `Ok(_)` result
        assert_matches!(signature, Err(InternalError {internal_error}) if internal_error.contains("the connection to the server was already shutdown"));
    }

    #[test]
    fn should_connect_with_new_client_after_server_killed_and_restarted() {
        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let vault = Arc::new(vault);
        let mut env = RemoteVaultEnvironment::start_server_with_local_csp_vault(vault);
        let client = vault_client_with_short_timeouts(&env).build_expecting_ok();
        let node_signing_public_key = client
            .gen_node_signing_key_pair()
            .expect("failed generating node signing key pair");
        let key_id = KeyId::try_from(&node_signing_public_key).unwrap();

        env.shutdown_server_now();
        env.restart_server();
        let client = vault_client_with_short_timeouts(&env).build_expecting_ok();

        let signature = sign_message(Small, key_id, &client);
        assert_matches!(signature, Ok(_));
    }

    fn vault_client_with_short_timeouts<B>(
        env: &RemoteVaultEnvironment<B>,
    ) -> RemoteCspVaultBuilder {
        env.new_vault_client_builder()
            .with_rpc_timeout(Duration::from_millis(1000))
            .with_long_rpc_timeout(Duration::from_millis(1000))
    }

    enum MessageLength {
        Small,
        TooLarge,
    }

    impl MessageLength {
        fn number_of_bytes(&self) -> usize {
            match self {
                Small => 10,
                TooLarge => MAX_FRAME_LENGTH_FOR_TEST + 1,
            }
        }
    }

    fn sign_message(
        message_length: MessageLength,
        key_id: KeyId,
        client: &RemoteCspVault,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        sign_message_of_length(message_length.number_of_bytes(), key_id, client)
    }

    fn sign_message_of_length(
        number_of_bytes: usize,
        key_id: KeyId,
        client: &RemoteCspVault,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        client.sign(AlgorithmId::Ed25519, &vec![0_u8; number_of_bytes], key_id)
    }
}

mod basic_signature_csp_vault {
    use super::*;
    use ic_crypto_internal_csp::types::{CspPublicKey, CspSignature};
    use ic_crypto_internal_csp_proptest_utils::arb_algorithm_id;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_basic_signature_error;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_basic_signature_keygen_error;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_public_key;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_signature;
    use ic_crypto_internal_csp_proptest_utils::arb_key_id;

    proptest! {
        #![proptest_config(proptest_config_for_delegation())]
        #[test]
        fn should_delegate_for_sign(
            algorithm_id in arb_algorithm_id(),
            key_id in arb_key_id(),
            message in vec(any::<u8>(), 0..1024),
            expected_result in maybe_err(arb_csp_signature(), arb_csp_basic_signature_error())
        ) {
            let expected_message = message.clone();
            let mut local_vault = MockLocalCspVault::new();
            local_vault
                .expect_sign()
                .times(1)
                .withf(move |algorithm_id_, message_, key_id_| {
                    *algorithm_id_ == algorithm_id && message_ == expected_message && *key_id_ == key_id
                })
                .return_const(expected_result.clone());
            let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
            let remote_vault = env.new_vault_client();

            let result = remote_vault.sign(algorithm_id, &message, key_id);

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
            .sign(
                AlgorithmId::Ed25519,
                &message,
                KeyId::try_from(&node_signing_public_key).unwrap(),
            )
            .expect("could not sign large message");

        match (node_signing_public_key, signature) {
            (CspPublicKey::Ed25519(public_key_bytes), CspSignature::Ed25519(signature_bytes)) => {
                let verification = ed25519::verify(&signature_bytes, &message, &public_key_bytes);
                assert_matches!(verification, Ok(()))
            }
            _ => panic!("unexpected type for node signing public key or signature"),
        }
    }
}

mod multi_signature_csp_vault {
    use super::*;
    use ic_crypto_internal_csp_proptest_utils::arb_algorithm_id;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_multi_signature_error;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_multi_signature_keygen_error;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_pop;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_public_key;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_signature;
    use ic_crypto_internal_csp_proptest_utils::arb_key_id;

    proptest! {
        #![proptest_config(proptest_config_for_delegation())]
        #[test]
        fn should_delegate_for_multi_sign(
            algorithm_id in arb_algorithm_id(),
            key_id in arb_key_id(),
            message in vec(any::<u8>(), 0..1024),
            expected_result in maybe_err(arb_csp_signature(), arb_csp_multi_signature_error())
        ) {
            let expected_message = message.clone();
            let mut local_vault = MockLocalCspVault::new();
            local_vault
                .expect_multi_sign()
                .times(1)
                .withf(move |algorithm_id_, message_, key_id_| {
                    *algorithm_id_ == algorithm_id && message_ == expected_message && *key_id_ == key_id
                })
                .return_const(expected_result.clone());
            let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
            let remote_vault = env.new_vault_client();

            let result = remote_vault.multi_sign(algorithm_id, &message, key_id);

            prop_assert_eq!(result, expected_result);
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_delegation())]
        #[test]
        fn should_delegate_for_gen_committee_signing_key_pair(
            expected_result in maybe_err((arb_csp_public_key(), arb_csp_pop()), arb_csp_multi_signature_keygen_error())
        ) {
            let mut local_vault = MockLocalCspVault::new();
            local_vault
                .expect_gen_committee_signing_key_pair()
                .times(1)
                .return_const(expected_result.clone());
            let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
            let remote_vault = env.new_vault_client();

            let result = remote_vault.gen_committee_signing_key_pair();

            prop_assert_eq!(result, expected_result);
        }
    }
}

mod threshold_signature_csp_vault {
    use super::*;
    use ic_crypto_internal_csp_proptest_utils::arb_algorithm_id;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_signature;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_threshold_sign_error;
    use ic_crypto_internal_csp_proptest_utils::arb_key_id;

    proptest! {
        #![proptest_config(proptest_config_for_delegation())]
        #[test]
        fn should_delegate_for_threshold_sign(
            algorithm_id in arb_algorithm_id(),
            key_id in arb_key_id(),
            message in vec(any::<u8>(), 0..1024),
            expected_result in maybe_err(arb_csp_signature(), arb_csp_threshold_sign_error())
        ) {
            let expected_message = message.clone();
            let mut local_vault = MockLocalCspVault::new();
            local_vault
                .expect_threshold_sign()
                .times(1)
                .withf(move |algorithm_id_, message_, key_id_| {
                    *algorithm_id_ == algorithm_id && message_ == expected_message && *key_id_ == key_id
                })
                .return_const(expected_result.clone());
            let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
            let remote_vault = env.new_vault_client();

            let result = remote_vault.threshold_sign(algorithm_id, &message, key_id);

            prop_assert_eq!(result, expected_result);
        }
    }
}

fn local_vault_in_temp_dir() -> (
    LocalCspVault<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore, ProtoPublicKeyStore>,
    TempDir,
) {
    use ic_config::crypto::CryptoConfig;

    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let local_vault = LocalCspVault::new_in_dir(
        &config.crypto_root,
        Arc::new(CryptoMetrics::none()),
        no_op_logger(),
    );
    (local_vault, _temp_dir)
}

fn proptest_config_for_delegation() -> ProptestConfig {
    ProptestConfig {
        //default uses FileFailurePersistence::SourceParallel which expects a main.rs or a lib.rs,
        //which does not work for a Rust integration test and results in a warning being printed.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}
