use ic_config::crypto::CryptoConfig;
use ic_crypto::CryptoComponent;
use ic_interfaces::registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_types::NodeId;
use std::sync::Arc;

// Setup a crypto provider with the default configuration.
// Note two reasons we use a concrete type here:
//
// i) The CryptoComponent wants in particular a Arc<dyn
// CryptoRegistryTrait>. That in general should not be the
// responsibility of the consumer, the aforementioned crypto service
// component here. I am not sure if there is a particular reasoning
// for this, and given it is not a two line change, I can process this
// in a follow up commit.

// ii) Keep things Simple.

// iii) Don't want to explode this proposed patches size.
pub fn setup_crypto_provider(
    replica_logger: ReplicaLogger,
    config: &CryptoConfig,
    registry_client: Arc<dyn RegistryClient>,
    node_id: NodeId,
) -> CryptoComponent {
    std::fs::create_dir_all(&config.crypto_root).unwrap_or_else(|err| {
        panic!(
            "Failed to create crypto root directory {}: {}",
            config.crypto_root.display(),
            err
        )
    });
    CryptoConfig::set_dir_with_required_permission(&config.crypto_root).unwrap();
    CryptoComponent::new_with_fake_node_id(config, registry_client, node_id, replica_logger)
}
