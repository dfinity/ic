use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_tls_cert_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::{NodeId, RegistryVersion};
use std::sync::Arc;

pub const REG_V1: RegistryVersion = RegistryVersion::new(1);

pub struct TlsRegistry {
    data_provider: Arc<ProtoRegistryDataProvider>,
    registry: Arc<FakeRegistryClient>,
}

impl TlsRegistry {
    pub fn new() -> TlsRegistry {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));
        TlsRegistry {
            data_provider,
            registry,
        }
    }

    pub fn add_cert(self, node_id: NodeId, cert: X509PublicKeyCert) -> TlsRegistry {
        self.data_provider
            .add(&make_crypto_tls_cert_key(node_id), REG_V1, Some(cert))
            .expect("failed to add TLS cert to registry");
        self
    }

    pub fn get(&self) -> Arc<FakeRegistryClient> {
        Arc::clone(&self.registry)
    }

    pub fn update(self) {
        self.registry.update_to_latest_version();
    }
}

/// Clippy requires the `Default` implementation
impl Default for TlsRegistry {
    fn default() -> Self {
        Self::new()
    }
}
