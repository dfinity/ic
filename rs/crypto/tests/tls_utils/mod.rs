use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_registry_client::fake::FakeRegistryClient;
use ic_types::{NodeId, RegistryVersion};
use std::sync::Arc;

pub mod registry;
pub mod test_client;
pub mod test_server;

pub const REG_V1: RegistryVersion = RegistryVersion::new(1);

pub fn temp_crypto_component_with_tls_keys(
    registry: Arc<FakeRegistryClient>,
    node_id: NodeId,
) -> (TempCryptoComponent, TlsPublicKeyCert) {
    TempCryptoComponent::new_with_tls_key_generation(registry as Arc<_>, node_id)
}
