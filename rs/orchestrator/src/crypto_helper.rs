use ic_config::crypto::CryptoConfig;
use ic_crypto::{CryptoComponent, CryptoComponentForNonReplicaProcess};
use ic_interfaces::registry::RegistryClient;
use ic_logger::ReplicaLogger;
use std::sync::Arc;

pub(crate) fn setup_crypto(
    config: &CryptoConfig,
    registry: Arc<dyn RegistryClient>,
    replica_logger: ReplicaLogger,
) -> impl CryptoComponentForNonReplicaProcess {
    CryptoComponent::new_for_non_replica_process(config, registry, replica_logger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto::utils::get_node_keys_or_generate_if_missing;
    use ic_logger::replica_logger::no_op_logger;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;

    #[test]
    fn should_create_crypto_with_default_config() {
        CryptoConfig::run_with_temp_config(|config| {
            // Create node keys.
            let (_created_node_pks, _node_id) =
                get_node_keys_or_generate_if_missing(&config.crypto_root);
            let registry_client =
                FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
            let _crypto = setup_crypto(&config, Arc::new(registry_client), no_op_logger());
        });
    }
}
