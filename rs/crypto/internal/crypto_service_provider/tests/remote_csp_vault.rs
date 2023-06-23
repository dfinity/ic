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
    use ic_config::logger::Config as LoggerConfig;
    use ic_crypto_internal_csp::api::CspCreateMEGaKeyError;
    use ic_crypto_internal_csp::types::CspSignature;
    use ic_crypto_internal_csp::vault::api::CspBasicSignatureError::TransientInternalError;
    use ic_crypto_internal_csp::vault::api::{
        BasicSignatureCspVault, CspBasicSignatureError, CspPublicKeyStoreError,
        IDkgProtocolCspVault, PublicKeyStoreCspVault,
    };
    use ic_crypto_internal_csp::vault::remote_csp_vault::{
        RemoteCspVault, RemoteCspVaultBuilder, TarpcCspVaultServerImplBuilder,
    };
    use ic_logger::{info, new_logger, new_replica_logger_from_config, ReplicaLogger};
    use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
    use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
    use slog::Level;
    use std::sync::Mutex;
    use std::thread;
    use std::thread::sleep;
    use std::time::Duration;

    const MAX_FRAME_LENGTH_FOR_TEST: usize = 1_000;

    #[test]
    fn should_reconnect_after_request_from_client_cannot_be_sent_because_too_large() {
        activate_tracing();
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
        assert_matches!(signature, Err(TransientInternalError {internal_error}) if internal_error.contains("the client failed to send the request"));

        let signature = sign_message(Small, key_id, &client_cannot_send_large_request);
        assert_matches!(signature, Ok(_));
    }

    #[test]
    fn should_reconnect_after_request_from_client_cannot_be_received_by_server_because_too_large() {
        activate_tracing();
        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let server_cannot_receive_large_request =
            TarpcCspVaultServerImplBuilder::new_with_local_csp_vault(Arc::new(vault))
                .with_max_frame_length(MAX_FRAME_LENGTH_FOR_TEST);
        let env = RemoteVaultEnvironment::start_server(server_cannot_receive_large_request);
        let client = env
            .new_vault_client_builder()
            .with_rpc_timeouts(Duration::from_secs(3))
            .build_expecting_ok();
        let node_signing_public_key = client
            .gen_node_signing_key_pair()
            .expect("failed generating node signing key pair");
        let key_id = KeyId::try_from(&node_signing_public_key).unwrap();

        let signature_before_error = sign_message(Small, key_id, &client);
        assert_matches!(signature_before_error, Ok(_));

        let signature = sign_message(TooLarge, key_id, &client);
        assert_matches!(signature, Err(TransientInternalError {internal_error}) if internal_error.contains("the request exceeded its deadline"));

        let signature_after_error = sign_message(Small, key_id, &client);
        assert_eq!(signature_before_error, signature_after_error);
    }

    #[test]
    fn should_unfortunately_be_dead_after_response_from_server_cannot_be_received_by_client_because_too_large(
    ) {
        activate_tracing();
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

        assert_matches!(client.idkg_gen_dealing_encryption_key_pair(),
        Err(CspCreateMEGaKeyError::TransientInternalError {internal_error}) if internal_error.contains("the connection to the server was already shutdown"));
    }

    #[test]
    fn should_reconnect_after_response_from_server_cannot_be_sent_because_too_large() {
        activate_tracing();
        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let server_cannot_send_large_response =
            TarpcCspVaultServerImplBuilder::new_with_local_csp_vault(Arc::new(vault))
                .with_max_frame_length(40);
        let env = RemoteVaultEnvironment::start_server(server_cannot_send_large_response);
        let client = env
            .new_vault_client_builder()
            .with_rpc_timeouts(Duration::from_secs(3))
            .build_expecting_ok();
        assert_matches!(&client.gen_node_signing_key_pair(), Ok(_)); //encoded response from server has 38 bytes
        assert_matches!(&client.idkg_gen_dealing_encryption_key_pair(), Ok(_)); //encoded response from server has 39 bytes

        let keys = &client.current_node_public_keys_with_timestamps(); //encoded response from server has 93 bytes
        assert_matches!(keys, Err(CspPublicKeyStoreError::TransientInternalError(msg)) if msg.contains("the request exceeded its deadline"));

        assert_matches!(&client.idkg_gen_dealing_encryption_key_pair(), Ok(_));
    }

    #[test]
    fn should_reconnect_with_existing_client_after_server_killed_and_restarted() {
        activate_tracing();
        let (logger, _guard) = new_replica_logger_from_config(&LoggerConfig::default());

        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let vault = Arc::new(vault);
        let mut env = RemoteVaultEnvironment::start_server(
            TarpcCspVaultServerImplBuilder::new_with_local_csp_vault(vault)
                .with_logger(new_logger!(&logger)),
        );
        let client = vault_client_with_short_timeouts(&env)
            .with_logger(new_logger!(&logger))
            .build_expecting_ok();
        let node_signing_public_key = client
            .gen_node_signing_key_pair()
            .expect("failed generating node signing key pair");
        let key_id = KeyId::try_from(&node_signing_public_key).unwrap();

        let signature_before_shutdown = sign_message(Small, key_id, &client);
        assert_matches!(signature_before_shutdown, Ok(_));

        env.shutdown_server_now();
        let env = Arc::new(Mutex::new(env));
        thread::spawn({
            let env_to_restart = Arc::clone(&env);
            move || {
                sleep(Duration::from_secs(5));
                info!(logger, "restarting server async");
                env_to_restart.lock().expect("failed").restart_server();
                info!(logger, "server restarted async");
            }
        });
        let _ensure_env_is_not_dropped = Arc::clone(&env);

        //will block until connection is back
        let signature_during_shutdown = sign_message(Small, key_id, &client);
        assert_eq!(signature_before_shutdown, signature_during_shutdown);

        let signature_after_restart = sign_message(Small, key_id, &client);
        assert_eq!(signature_before_shutdown, signature_after_restart);
    }

    #[test]
    fn should_connect_with_new_client_after_server_killed_and_restarted() {
        activate_tracing();
        let (logger, _guard) = new_replica_logger_from_config(&LoggerConfig::default());
        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let vault = Arc::new(vault);
        let mut env = RemoteVaultEnvironment::start_server_with_local_csp_vault(vault);
        let client = vault_client_with_short_timeouts(&env)
            .with_logger(logger)
            .build_expecting_ok();
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

    #[test]
    fn should_automatically_detect_disconnection() {
        activate_tracing();
        let in_memory_logger = InMemoryReplicaLogger::new();

        let (vault, _temp_dir) = local_vault_in_temp_dir();
        let vault = Arc::new(vault);
        let mut env = RemoteVaultEnvironment::start_server(
            TarpcCspVaultServerImplBuilder::new_with_local_csp_vault(vault),
        );
        let client = vault_client_with_short_timeouts(&env)
            .with_logger(ReplicaLogger::from(&in_memory_logger))
            .build_expecting_ok();
        let _ensure_client_can_contact_server = client
            .current_node_public_keys()
            .expect("should successfully get current node public keys");

        env.shutdown_server_now();

        sleep(Duration::from_secs(1));
        let logs = in_memory_logger.drain_logs();

        LogEntriesAssert::assert_that(logs)
            .has_only_one_message_containing(&Level::Warning, "Detected disconnection from socket");
    }

    fn vault_client_with_short_timeouts<B>(
        env: &RemoteVaultEnvironment<B>,
    ) -> RemoteCspVaultBuilder {
        env.new_vault_client_builder()
            .with_rpc_timeout(Duration::from_secs(10))
            .with_long_rpc_timeout(Duration::from_secs(10))
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

    /// Activate [tracing](https://github.com/tokio-rs/tracing) used by the
    /// [Tarpc framework](https://github.com/google/tarpc).
    /// Useful for debugging purposes and following the various asynchronous operations.
    ///
    /// **Warning**: This is quite verbose and should therefore not be activated when merged
    /// to avoid storing a huge amount of logs on CI (with tracing activated tests under
    /// `/rs/crypto/internal/crypto_service_provider/` produce around 67MB of logs
    /// vs 1.5MB when tracing is disabled)!
    fn activate_tracing() {
        const IS_TRACING_ACTIVATED: bool = false;
        if IS_TRACING_ACTIVATED {
            use tracing::Level;
            let _ = tracing_subscriber::fmt()
                .with_max_level(Level::TRACE)
                .try_init();
        }
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

mod secret_key_store_csp_vault {
    use super::*;
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

            let result = remote_vault.sks_contains(&key_id);

            prop_assert_eq!(result, expected_result);
        }
    }
}

mod public_key_store_csp_vault {
    use super::*;
    use ic_crypto_internal_csp_proptest_utils::{
        arb_csp_public_key_store_error, arb_current_node_public_keys,
    };

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
}

mod public_and_secret_key_store_csp_vault {
    use super::*;
    use ic_crypto_internal_csp_proptest_utils::{
        arb_external_public_keys, arb_pks_and_sks_contains_errors, arb_validate_pks_and_sks_error,
    };
    use ic_crypto_node_key_validation::{ValidNodePublicKeys, ValidNodeSigningPublicKey};
    use ic_crypto_test_utils_keys::public_keys::{
        valid_committee_signing_public_key, valid_dkg_dealing_encryption_public_key,
        valid_idkg_dealing_encryption_public_key, valid_node_signing_public_key,
        valid_tls_certificate,
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
        ValidNodePublicKeys::try_from(
            CurrentNodePublicKeys {
                node_signing_public_key: Some(valid_node_signing_public_key()),
                committee_signing_public_key: Some(valid_committee_signing_public_key()),
                tls_certificate: Some(valid_tls_certificate()),
                dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
                idkg_dealing_encryption_public_key: Some(valid_idkg_dealing_encryption_public_key()),
            },
            node_id,
        )
            .expect("invalid node public keys")
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
