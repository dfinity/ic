#![allow(clippy::unwrap_used)]
use crate::tls_utils::{temp_crypto_component_with_tls_keys, REG_V1};
use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::{TlsClientHandshakeError, TlsHandshake};
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_types::NodeId;
use std::sync::Arc;
use tokio::net::TcpStream;

pub struct OpenSslClientBuilder {
    node_id: NodeId,
    server_node_id: NodeId,
}

impl OpenSslClientBuilder {
    pub fn build(self, registry: Arc<FakeRegistryClient>) -> OpenSslClient {
        let (crypto, cert) = temp_crypto_component_with_tls_keys(registry, self.node_id);
        OpenSslClient {
            crypto,
            server_node_id: self.server_node_id,
            cert,
        }
    }
}

/// A wrapper around the crypto TLS client implementation under test. Allows for
/// easy testing.
///
/// This is for testing the OpenSSL variant of the implementation.
pub struct OpenSslClient {
    crypto: TempCryptoComponent,
    server_node_id: NodeId,
    cert: TlsPublicKeyCert,
}

impl OpenSslClient {
    pub fn builder(node_id: NodeId, server_node_id: NodeId) -> OpenSslClientBuilder {
        OpenSslClientBuilder {
            node_id,
            server_node_id,
        }
    }

    pub async fn run(&self, server_port: u16) -> Result<(), TlsClientHandshakeError> {
        let tcp_stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .expect("failed to connect");

        let _tls_stream = self
            .crypto
            .perform_tls_client_handshake(tcp_stream, self.server_node_id, REG_V1)
            .await?;

        Ok(())
    }

    pub fn cert(&self) -> X509PublicKeyCert {
        self.cert.to_proto()
    }
}
