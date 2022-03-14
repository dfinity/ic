use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_types::NodeId;
use std::sync::Arc;

// Cargo complains about this being unused even though it is used:
#[allow(unused)]
pub mod test_client;
// Cargo complains about this being unused even though it is used:
#[allow(unused)]
pub mod test_client_openssl;
// Cargo complains about this being unused even though it is used:
#[allow(unused)]
pub mod test_server;
// Cargo complains about this being unused even though it is used:
#[allow(unused)]
pub mod test_server_openssl;

pub use ic_crypto_test_utils::tls::registry::REG_V1;

pub fn temp_crypto_component_with_tls_keys(
    registry: Arc<FakeRegistryClient>,
    node_id: NodeId,
) -> (TempCryptoComponent, TlsPublicKeyCert) {
    TempCryptoComponent::new_with_tls_key_generation(registry as Arc<_>, node_id)
}
