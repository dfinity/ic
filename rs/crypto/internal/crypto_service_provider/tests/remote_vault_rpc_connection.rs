use crate::MessageLength::{Small, TooLarge};
use assert_matches::assert_matches;
use ic_config::logger::Config as LoggerConfig;
use ic_crypto_internal_csp::api::CspCreateMEGaKeyError;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::CspSignature;
use ic_crypto_internal_csp::vault::api::CspBasicSignatureError::TransientInternalError;
use ic_crypto_internal_csp::vault::api::{
    BasicSignatureCspVault, CspBasicSignatureError, CspPublicKeyStoreError, IDkgProtocolCspVault,
    PublicKeyStoreCspVault,
};
use ic_crypto_internal_csp::vault::remote_csp_vault::{
    RemoteCspVault, RemoteCspVaultBuilder, TarpcCspVaultServerImplBuilder,
};
use ic_crypto_temp_crypto_vault::RemoteVaultEnvironment;
use ic_logger::{ReplicaLogger, info, new_logger, new_replica_logger_from_config};
use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
use ic_types::crypto::AlgorithmId;
use slog::Level;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::thread::sleep;
use std::time::Duration;

mod common;
use common::local_vault_in_temp_dir;

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
    let key_id = KeyId::from(&node_signing_public_key);

    let signature = sign_message(Small, key_id, &client_cannot_send_large_request);
    assert_matches!(signature, Ok(_));

    let signature = sign_message(TooLarge, key_id, &client_cannot_send_large_request);
    assert_matches!(signature, Err(TransientInternalError {internal_error})
        if internal_error.contains("the client failed to send the request")
        && internal_error.contains("Caused by: could not write to the transport")
        && internal_error.contains("Caused by: frame size too big")
    );

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
    let key_id = KeyId::from(&node_signing_public_key);

    let signature_before_error = sign_message(Small, key_id, &client);
    assert_matches!(signature_before_error, Ok(_));

    let signature = sign_message(TooLarge, key_id, &client);
    assert_matches!(signature, Err(TransientInternalError {internal_error}) if internal_error.contains("the request exceeded its deadline"));

    let signature_after_error = sign_message(Small, key_id, &client);
    assert_eq!(signature_before_error, signature_after_error);
}

#[test]
fn should_unfortunately_be_dead_after_response_from_server_cannot_be_received_by_client_because_too_large()
 {
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

    // `tarpc` seems to have a race condition in this particular, very rare
    // case: https://github.com/google/tarpc/issues/415. Adding a delay
    // in this test temporarily fixes the issue until it is fixed in
    // `tarpc`.
    // TODO(CRP-2348): bump `tarpc` version when there is a fix and remove
    // the `sleep`.
    std::thread::sleep(std::time::Duration::from_millis(100));

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
    let key_id = KeyId::from(&node_signing_public_key);

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
    let key_id = KeyId::from(&node_signing_public_key);

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

fn vault_client_with_short_timeouts<B>(env: &RemoteVaultEnvironment<B>) -> RemoteCspVaultBuilder {
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
    client.sign(AlgorithmId::Ed25519, vec![0_u8; number_of_bytes], key_id)
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
