#![allow(clippy::unwrap_used)]
use crate::tls_utils::{temp_crypto_component_with_tls_keys, REG_V1};
use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, SomeOrAllNodes, TlsHandshake, TlsServerHandshakeError,
};
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_types::NodeId;
use proptest::std_facade::BTreeSet;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

pub struct OpenSslServerBuilder {
    node_id: NodeId,
    allowed_nodes: Option<SomeOrAllNodes>,
}

impl OpenSslServerBuilder {
    pub fn add_allowed_client(mut self, client: NodeId) -> Self {
        match self.allowed_nodes {
            None => {
                self.allowed_nodes = {
                    let mut allowed = BTreeSet::new();
                    allowed.insert(client);
                    Some(SomeOrAllNodes::Some(allowed))
                };
                self
            }
            Some(SomeOrAllNodes::Some(mut nodes)) => {
                nodes.insert(client);
                self.allowed_nodes = Some(SomeOrAllNodes::Some(nodes));
                self
            }
            Some(SomeOrAllNodes::All) => {
                panic!("invalid use of builder: cannot add node if all nodes are allowed")
            }
        }
    }

    pub fn build(self, registry: Arc<FakeRegistryClient>) -> OpenSslServer {
        let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).expect("failed to bind");
        let (crypto, cert) = temp_crypto_component_with_tls_keys(registry, self.node_id);
        let allowed_clients = AllowedClients::new(
            self.allowed_nodes
                .unwrap_or_else(|| SomeOrAllNodes::Some(BTreeSet::new())),
        )
        .expect("failed to construct allowed clients");
        OpenSslServer {
            listener,
            crypto,
            allowed_clients,
            cert,
        }
    }
}

/// A wrapper around the crypto TLS server implementation under test. Allows for
/// easy testing.
///
/// This is for testing the OpenSSL variant of the implementation.
pub struct OpenSslServer {
    listener: std::net::TcpListener,
    crypto: TempCryptoComponent,
    allowed_clients: AllowedClients,
    cert: TlsPublicKeyCert,
}

impl OpenSslServer {
    pub fn builder(node_id: NodeId) -> OpenSslServerBuilder {
        OpenSslServerBuilder {
            node_id,
            allowed_nodes: None,
        }
    }

    pub async fn run(&self) -> Result<AuthenticatedPeer, TlsServerHandshakeError> {
        let tcp_stream = self.accept_connection_on_listener().await;

        let (_tls_stream, authenticated_node) = self
            .crypto
            .perform_tls_server_handshake(tcp_stream, self.allowed_clients.clone(), REG_V1)
            .await?;

        Ok(authenticated_node)
    }

    async fn accept_connection_on_listener(&self) -> TcpStream {
        self.listener
            .set_nonblocking(true)
            .expect("failed to make listener non-blocking");
        let tokio_tcp_listener = TcpListener::from_std(self.listener.try_clone().unwrap())
            .expect("failed to create tokio TcpListener");
        let (tcp_stream, _peer_address) = tokio_tcp_listener
            .accept()
            .await
            .expect("failed to accept connection");
        tcp_stream
    }

    pub fn port(&self) -> u16 {
        self.listener
            .local_addr()
            .expect("failed to get local_addr")
            .port()
    }

    pub fn cert(&self) -> X509PublicKeyCert {
        self.cert.to_proto()
    }
}
