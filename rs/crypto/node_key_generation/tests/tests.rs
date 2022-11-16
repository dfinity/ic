use ic_base_types::NodeId;
use ic_config::crypto::CryptoConfig;
use ic_crypto::{CryptoComponent, CryptoComponentFatClient};
use ic_crypto_internal_csp::Csp;
use ic_crypto_internal_csp_test_utils::remote_csp_vault::start_new_remote_csp_vault_server_in_temp_dir;
use ic_crypto_node_key_generation::{
    derive_node_id, get_node_keys_or_generate_if_missing, mega_public_key_from_proto,
    MEGaPublicKeyFromProtoError,
};
use ic_interfaces::crypto::KeyManager;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::CurrentNodePublicKeys;
use std::sync::Arc;

#[test]
fn should_generate_all_keys_for_new_node() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, node_id) = get_node_keys_or_generate_if_missing(&config, None);
        ensure_node_keys_are_generated_correctly(&node_pks, &node_id);

        let crypto = local_crypto_component(&config);
        assert_eq!(node_pks, crypto.current_node_public_keys());
    })
}

#[test]
fn should_generate_all_keys_for_new_node_with_remote_csp_vault() {
    let tokio_rt = new_tokio_runtime();
    let (temp_dir, socket_path) = start_new_remote_csp_vault_server_in_temp_dir(tokio_rt.handle());
    let config =
        CryptoConfig::new_with_unix_socket_vault(temp_dir.path().to_path_buf(), socket_path);

    let (node_pks, node_id) =
        get_node_keys_or_generate_if_missing(&config, Some(tokio_rt.handle().clone()));
    ensure_node_keys_are_generated_correctly(&node_pks, &node_id);

    let crypto = remote_crypto_component(&config, tokio_rt.handle().clone());

    assert_eq!(node_pks, crypto.current_node_public_keys());
}

#[test]
fn should_not_generate_new_keys_if_all_keys_are_present() {
    CryptoConfig::run_with_temp_config(|config| {
        let (orig_node_pks, orig_node_id) = get_node_keys_or_generate_if_missing(&config, None);
        assert!(all_node_keys_are_present(&orig_node_pks));
        let (new_node_pks, new_node_id) = get_node_keys_or_generate_if_missing(&config, None);
        assert!(all_node_keys_are_present(&new_node_pks));
        assert_eq!(orig_node_pks, new_node_pks);
        assert_eq!(orig_node_id, new_node_id);
    })
}

#[test]
fn should_correctly_generate_node_signing_key() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
        let nspk = node_pks.node_signing_public_key.expect("missing key");
        assert_eq!(nspk.version, 0);
        assert_eq!(nspk.algorithm, AlgorithmIdProto::Ed25519 as i32);
        assert!(!nspk.key_value.is_empty());
        assert!(nspk.proof_data.is_none());
    })
}

#[test]
fn should_correctly_generate_committee_signing_key() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
        let cspk = node_pks.committee_signing_public_key.expect("missing key");
        assert_eq!(cspk.version, 0);
        assert_eq!(cspk.algorithm, AlgorithmIdProto::MultiBls12381 as i32);
        assert!(!cspk.key_value.is_empty());
        assert!(cspk.proof_data.is_some());
        assert!(!cspk.proof_data.unwrap().is_empty());
    })
}

#[test]
fn should_correctly_generate_dkg_dealing_encryption_key() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
        let ni_dkg_de_pk = node_pks
            .dkg_dealing_encryption_public_key
            .expect("missing key");
        assert_eq!(ni_dkg_de_pk.version, 0);
        assert_eq!(
            ni_dkg_de_pk.algorithm,
            AlgorithmIdProto::Groth20Bls12381 as i32
        );
        assert!(!ni_dkg_de_pk.key_value.is_empty());
        assert!(ni_dkg_de_pk.proof_data.is_some());
        assert!(!ni_dkg_de_pk.proof_data.unwrap().is_empty());
    })
}

#[test]
fn should_correctly_generate_tls_certificate() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
        assert!(node_pks.tls_certificate.is_some());
        assert!(!node_pks.tls_certificate.unwrap().certificate_der.is_empty());
    })
}

fn all_node_keys_are_present(node_pks: &CurrentNodePublicKeys) -> bool {
    node_pks.node_signing_public_key.is_some()
        && node_pks.committee_signing_public_key.is_some()
        && node_pks.tls_certificate.is_some()
        && node_pks.dkg_dealing_encryption_public_key.is_some()
        && node_pks.idkg_dealing_encryption_public_key.is_some()
}

fn ensure_node_keys_are_generated_correctly(node_pks: &CurrentNodePublicKeys, node_id: &NodeId) {
    assert!(all_node_keys_are_present(node_pks));

    let node_signing_pk = node_pks
        .node_signing_public_key
        .as_ref()
        .expect("Missing node signing public key");
    let derived_node_id = derive_node_id(node_signing_pk);
    assert_eq!(*node_id, derived_node_id);
}

fn local_crypto_component(config: &CryptoConfig) -> Arc<CryptoComponentFatClient<Csp>> {
    crypto_component(config, None)
}
fn remote_crypto_component(
    config: &CryptoConfig,
    tokio_runtime_handle: tokio::runtime::Handle,
) -> Arc<CryptoComponentFatClient<Csp>> {
    crypto_component(config, Some(tokio_runtime_handle))
}
fn crypto_component(
    config: &CryptoConfig,
    tokio_runtime_handle: Option<tokio::runtime::Handle>,
) -> Arc<CryptoComponentFatClient<Csp>> {
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

#[test]
fn should_convert_mega_proto() {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let mega_proto = get_node_keys_or_generate_if_missing(&config, None)
        .0
        .idkg_dealing_encryption_public_key
        .expect("Missing MEGa public key");

    assert!(mega_public_key_from_proto(&mega_proto).is_ok());
}

#[test]
fn should_fail_to_convert_mega_pubkey_from_proto_if_algorithm_unsupported() {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let mut mega_proto = get_node_keys_or_generate_if_missing(&config, None)
        .0
        .idkg_dealing_encryption_public_key
        .expect("Missing MEGa public key");
    mega_proto.algorithm = AlgorithmIdProto::Ed25519 as i32;

    let result = mega_public_key_from_proto(&mega_proto);

    assert!(matches!(
        result,
        Err(MEGaPublicKeyFromProtoError::UnsupportedAlgorithm { .. })
    ))
}

#[test]
fn should_fail_to_convert_mega_pubkey_from_proto_if_pubkey_malformed() {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let mut mega_proto = get_node_keys_or_generate_if_missing(&config, None)
        .0
        .idkg_dealing_encryption_public_key
        .expect("Missing MEGa public key");
    mega_proto.key_value = b"malformed public key".to_vec();

    let result = mega_public_key_from_proto(&mega_proto);

    assert!(matches!(
        result,
        Err(MEGaPublicKeyFromProtoError::MalformedPublicKey { .. })
    ))
}
