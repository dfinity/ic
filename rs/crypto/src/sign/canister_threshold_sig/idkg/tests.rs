use crate::sign::get_mega_pubkey;
use ic_base_types::RegistryVersion;
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::get_node_keys_or_generate_if_missing;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::KeyPurpose;
use std::sync::Arc;

#[test]
fn should_retrieve_mega_keys_from_the_registry() {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let (node_pks, node_id) = get_node_keys_or_generate_if_missing(&config, None);
    let mega_proto = node_pks
        .idkg_dealing_encryption_public_key
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

    assert!(get_mega_pubkey(&node_id, registry_client.as_ref(), registry_version).is_ok());
}
