use ic_config::crypto::CryptoConfig;
use ic_crypto::{CryptoComponent, CryptoComponentImpl};
use ic_crypto_internal_csp::Csp;
use ic_crypto_internal_csp_test_utils::remote_csp_vault::start_new_remote_csp_vault_server_in_temp_dir;
use ic_crypto_node_key_generation::generate_node_keys_once;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_interfaces::crypto::KeyManager;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use std::sync::Arc;

#[test]
fn should_generate_all_keys_for_new_node() {
    CryptoConfig::run_with_temp_config(|config| {
        let generated_pks =
            generate_node_keys_once(&config, None).expect("error generating node public keys");
        let node_id = generated_pks.node_id();

        let crypto = local_crypto_component(&config);
        let retrieved_keys = ValidNodePublicKeys::try_from(
            crypto
                .current_node_public_keys()
                .expect("Failed to retrieve node public keys"),
            node_id,
            ic_types::time::current_time(),
        )
        .expect("retrieved public keys are invalid");

        assert_eq!(generated_pks, retrieved_keys);
    })
}

#[test]
fn should_generate_all_keys_for_new_node_with_remote_csp_vault() {
    let tokio_rt = new_tokio_runtime();
    let (temp_dir, socket_path) = start_new_remote_csp_vault_server_in_temp_dir(tokio_rt.handle());
    let config =
        CryptoConfig::new_with_unix_socket_vault(temp_dir.path().to_path_buf(), socket_path, None);

    let generated_pks = generate_node_keys_once(&config, Some(tokio_rt.handle().clone()))
        .expect("error generating node public keys");
    let node_id = generated_pks.node_id();

    let crypto = remote_crypto_component(&config, tokio_rt.handle().clone());
    let retrieved_keys = ValidNodePublicKeys::try_from(
        crypto
            .current_node_public_keys()
            .expect("Failed to retrieve node public keys"),
        node_id,
        ic_types::time::current_time(),
    )
    .expect("retrieved public keys are invalid");

    assert_eq!(generated_pks, retrieved_keys);
}

#[test]
fn should_not_generate_new_keys_if_all_keys_are_present() {
    CryptoConfig::run_with_temp_config(|config| {
        let orig_node_pks = generate_node_keys_once(&config, None);
        let new_node_pks = generate_node_keys_once(&config, None);
        assert_eq!(orig_node_pks, new_node_pks);
    })
}

fn local_crypto_component(config: &CryptoConfig) -> Arc<CryptoComponentImpl<Csp>> {
    crypto_component(config, None)
}
fn remote_crypto_component(
    config: &CryptoConfig,
    tokio_runtime_handle: tokio::runtime::Handle,
) -> Arc<CryptoComponentImpl<Csp>> {
    crypto_component(config, Some(tokio_runtime_handle))
}
fn crypto_component(
    config: &CryptoConfig,
    tokio_runtime_handle: Option<tokio::runtime::Handle>,
) -> Arc<CryptoComponentImpl<Csp>> {
    let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    let logger = no_op_logger();
    let metrics_registry = MetricsRegistry::new();
    Arc::new(CryptoComponent::new(
        config,
        tokio_runtime_handle,
        Arc::new(registry_client),
        logger,
        Some(&metrics_registry),
    ))
}

fn new_tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("failed to create runtime")
}
