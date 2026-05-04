use crate::sign::retrieve_mega_public_key_from_registry;
use ic_base_types::RegistryVersion;
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::generate_node_keys_once;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::KeyPurpose;
use std::sync::Arc;

#[test]
fn should_retrieve_mega_keys_from_the_registry() {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let node_pks =
        generate_node_keys_once(&config, None).expect("error generating node public keys");
    let node_id = node_pks.node_id();
    let mega_proto = node_pks.idkg_dealing_encryption_key();

    let registry_version = RegistryVersion::from(1);
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(data_provider.clone()));

    data_provider
        .add(
            &make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption),
            registry_version,
            Some(mega_proto.clone()),
        )
        .expect("Could not add public key to registry");

    registry_client.update_to_latest_version();

    assert!(
        retrieve_mega_public_key_from_registry(
            &node_id,
            registry_client.as_ref(),
            registry_version
        )
        .is_ok()
    );
}
