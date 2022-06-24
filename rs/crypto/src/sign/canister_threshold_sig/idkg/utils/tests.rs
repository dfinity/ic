use crate::sign::canister_threshold_sig::idkg::utils::{
    get_mega_pubkey, mega_public_key_from_proto,
};
use crate::sign::MEGaPublicKeyFromProtoError;
use crate::utils::get_node_keys_or_generate_if_missing;
use ic_base_types::RegistryVersion;
use ic_config::crypto::CryptoConfig;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::KeyPurpose;
use std::sync::Arc;

#[test]
fn should_convert_mega_proto() {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let mega_proto = get_node_keys_or_generate_if_missing(&config, None)
        .0
        .idkg_dealing_encryption_pk
        .expect("Missing MEGa public key");

    assert!(mega_public_key_from_proto(&mega_proto).is_ok());
}

#[test]
fn should_fail_to_convert_mega_pubkey_from_proto_if_algorithm_unsupported() {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let mut mega_proto = get_node_keys_or_generate_if_missing(&config, None)
        .0
        .idkg_dealing_encryption_pk
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
        .idkg_dealing_encryption_pk
        .expect("Missing MEGa public key");
    mega_proto.key_value = b"malformed public key".to_vec();

    let result = mega_public_key_from_proto(&mega_proto);

    assert!(matches!(
        result,
        Err(MEGaPublicKeyFromProtoError::MalformedPublicKey { .. })
    ))
}

#[test]
fn should_retrieve_mega_keys_from_the_registry() {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let (node_pks, node_id) = get_node_keys_or_generate_if_missing(&config, None);
    let mega_proto = node_pks
        .idkg_dealing_encryption_pk
        .expect("Missing MEGa public key");

    let registry_version = RegistryVersion::from(1);
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(data_provider.clone()));

    data_provider
        .add(
            &make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption),
            registry_version,
            Some(mega_proto),
        )
        .expect("Could not add public key to registry");

    registry_client.update_to_latest_version();

    assert!(get_mega_pubkey(&node_id, &(registry_client as Arc<_>), registry_version).is_ok());
}
