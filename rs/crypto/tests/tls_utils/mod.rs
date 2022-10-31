use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_types::NodeId;
use std::sync::Arc;

pub mod test_client;
pub mod test_client_openssl;
pub mod test_server;
pub mod test_server_openssl;

pub use ic_crypto_test_utils::tls::registry::REG_V1;
use ic_interfaces::crypto::KeyManager;

pub fn temp_crypto_component_with_tls_keys(
    registry: Arc<FakeRegistryClient>,
    node_id: NodeId,
) -> (TempCryptoComponent, TlsPublicKeyCert) {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(registry)
        .with_node_id(node_id)
        .with_keys(NodeKeysToGenerate::only_tls_key_and_cert())
        .with_remote_vault()
        .build();
    let tls_certificate = temp_crypto
        .current_node_public_keys()
        .tls_certificate
        .expect("missing tls_certificate");
    let tls_pubkey = TlsPublicKeyCert::new_from_der(tls_certificate.certificate_der)
        .expect("failed to create X509 cert from DER");
    (temp_crypto, tls_pubkey)
}
