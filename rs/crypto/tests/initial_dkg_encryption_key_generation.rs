use ic_config::crypto::CryptoConfig;
use ic_crypto::utils::dkg::InitialDkgConfig;
use ic_crypto::utils::generate_initial_dkg_encryption_keys;
use ic_crypto::CryptoComponent;
use ic_interfaces::crypto::DkgAlgorithm;
use ic_logger::replica_logger::no_op_logger;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::crypto::temp_dir::temp_dir;
use ic_test_utilities::types::ids::{subnet_test_id, NODE_1};
use ic_types::NodeId;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

#[test]
fn should_return_public_key() {
    let temp_dir = temp_dir();
    let nodes: BTreeSet<NodeId> = [NODE_1].iter().cloned().collect();
    let subnet_id = subnet_test_id(1);
    let initial_dkg_config = InitialDkgConfig::new(&nodes, subnet_id);

    let result = generate_initial_dkg_encryption_keys(temp_dir.path(), &initial_dkg_config, NODE_1);

    assert!(result.is_ok());
}

#[test]
fn should_store_private_key_so_it_can_be_used_to_verify() {
    let temp_dir = temp_dir();

    let nodes: BTreeSet<NodeId> = [NODE_1].iter().cloned().collect();
    let subnet_id = subnet_test_id(1);
    let initial_dkg_config = InitialDkgConfig::new(&nodes, subnet_id);

    let pk_with_pop =
        generate_initial_dkg_encryption_keys(temp_dir.path(), &initial_dkg_config, NODE_1)
            .expect("error in key generation");

    assert!(crypto_with_path(temp_dir.path())
        .verify_encryption_public_key(&initial_dkg_config.get(), NODE_1, &pk_with_pop)
        .is_ok());
}

fn crypto_with_path(temp_dir_path: &Path) -> Arc<CryptoComponent> {
    let config = CryptoConfig::new(temp_dir_path.to_path_buf());
    let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    Arc::new(CryptoComponent::new_with_fake_node_id(
        &config,
        Arc::new(registry_client),
        NODE_1, // The node id is currenlty irrelevant for this test
        no_op_logger(),
    ))
}
