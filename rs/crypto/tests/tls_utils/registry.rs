use crate::tls_utils::REG_V1;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_client::helper::node::NodeRecord;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::{make_crypto_tls_cert_key, make_node_record_key};
use ic_types::NodeId;
use openssl::x509::X509;
use std::sync::Arc;

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

    pub fn add_node_record(self, node_id: NodeId) -> TlsRegistry {
        self.data_provider
            .add(
                &make_node_record_key(node_id),
                REG_V1,
                Some(NodeRecord {
                    ..Default::default()
                }),
            )
            .expect("Could not add node record.");
        self
    }

    #[allow(unused)]
    pub fn with_cert_from_x509(self, node_id: NodeId, cert: X509) -> TlsRegistry {
        let cert = X509PublicKeyCert {
            certificate_der: cert.to_der().expect("could not DER encode certificate"),
        };
        self.add_cert(node_id, cert)
    }

    pub fn get(&self) -> Arc<FakeRegistryClient> {
        Arc::clone(&self.registry)
    }

    pub fn update(self) {
        self.registry.update_to_latest_version();
    }
}
