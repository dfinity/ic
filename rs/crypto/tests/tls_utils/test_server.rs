#![allow(clippy::unwrap_used)]
use crate::tls_utils::{temp_crypto_component_with_tls_keys, REG_V1};
use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, Peer, SomeOrAllNodes, TlsHandshake, TlsReadHalf,
    TlsServerHandshakeError, TlsWriteHalf,
};
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_types::NodeId;
use proptest::std_facade::BTreeSet;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

pub struct ServerBuilder {
    node_id: NodeId,
    msg_for_client: Option<String>,
    msg_expected_from_client: Option<String>,
    allowed_nodes: Option<SomeOrAllNodes>,
    allowed_certs: HashSet<TlsPublicKeyCert>,
}

impl ServerBuilder {
    pub fn with_msg_for_client(mut self, msg: &str) -> Self {
        self.msg_for_client = Some(msg.to_string());
        self
    }

    pub fn expect_msg_from_client(mut self, msg: &str) -> Self {
        self.msg_expected_from_client = Some(msg.to_string());
        self
    }

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

    pub fn allow_all_nodes(mut self) -> Self {
        match self.allowed_nodes {
            None => {
                self.allowed_nodes = Some(SomeOrAllNodes::All);
                self
            }
            Some(SomeOrAllNodes::Some(_)) => panic!(
                "invalid use of builder: cannot allow all nodes if some individual nodes are allowed"
            ),
            Some(SomeOrAllNodes::All) => self,
        }
    }

    pub fn add_allowed_client_cert(mut self, cert: X509PublicKeyCert) -> Self {
        let cert = TlsPublicKeyCert::new_from_der(cert.certificate_der)
            .expect("failed to construct TlsPublicKeyCert from DER");
        self.allowed_certs.insert(cert);
        self
    }

    pub fn build(self, registry: Arc<FakeRegistryClient>) -> Server {
        let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).expect("failed to bind");
        let (crypto, cert) = temp_crypto_component_with_tls_keys(registry, self.node_id);
        let allowed_clients = AllowedClients::new(
            self.allowed_nodes
                .unwrap_or_else(|| SomeOrAllNodes::Some(BTreeSet::new())),
            self.allowed_certs,
        )
        .expect("failed to construct allowed clients");
        Server {
            listener,
            crypto,
            allowed_clients,
            msg_for_client: self.msg_for_client,
            msg_expected_from_client: self.msg_expected_from_client,
            cert,
        }
    }
}

/// A wrapper around the crypto TLS server implementation under test. Allows for
/// easy testing.
pub struct Server {
    listener: std::net::TcpListener,
    crypto: TempCryptoComponent,
    allowed_clients: AllowedClients,
    msg_for_client: Option<String>,
    msg_expected_from_client: Option<String>,
    cert: TlsPublicKeyCert,
}

impl Server {
    pub fn builder(node_id: NodeId) -> ServerBuilder {
        ServerBuilder {
            node_id,
            msg_for_client: None,
            msg_expected_from_client: None,
            allowed_nodes: None,
            allowed_certs: HashSet::new(),
        }
    }

    pub async fn run(self) -> Result<AuthenticatedPeer, TlsServerHandshakeError> {
        let tcp_stream = self.accept_connection_on_listener().await;

        let (tls_stream, authenticated_node) = self
            .crypto
            .perform_tls_server_handshake(tcp_stream, self.allowed_clients.clone(), REG_V1)
            .await?;
        let (mut rh, mut wh) = tls_stream.split();

        self.send_msg_to_client_if_configured(&mut wh, &mut rh)
            .await;
        self.expect_msg_from_client_if_configured(&mut rh, &mut wh)
            .await;
        Ok(authenticated_node)
    }

    pub async fn run_without_client_auth(self) -> Result<(), TlsServerHandshakeError> {
        let tcp_stream = self.accept_connection_on_listener().await;

        let tls_stream = self
            .crypto
            .perform_tls_server_handshake_without_client_auth(tcp_stream, REG_V1)
            .await?;
        let (mut rh, mut wh) = tls_stream.split();

        self.send_msg_to_client_if_configured(&mut wh, &mut rh)
            .await;
        self.expect_msg_from_client_if_configured(&mut rh, &mut wh)
            .await;
        Ok(())
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

    async fn expect_msg_from_client_if_configured(
        &self,
        rh: &mut TlsReadHalf,
        wh: &mut TlsWriteHalf,
    ) {
        if let Some(msg_expected_from_client) = &self.msg_expected_from_client {
            let mut reader = BufReader::new(rh);
            let msg = reader.lines().next_line().await.unwrap().unwrap();
            assert_eq!(&msg, msg_expected_from_client);

            const ACK: u8 = 0x06;
            wh.write_u8(ACK).await.unwrap();
        }
    }

    async fn send_msg_to_client_if_configured(&self, wh: &mut TlsWriteHalf, rh: &mut TlsReadHalf) {
        if let Some(msg_for_client) = &self.msg_for_client {
            // Append a newline (end of line, EOL, 0xA) so the peer knows where the msg ends
            let msg_with_eol = format!("{}\n", msg_for_client);
            let num_bytes_written = wh.write(msg_with_eol.as_bytes()).await.unwrap();
            assert_eq!(num_bytes_written, msg_with_eol.as_bytes().len());

            const ACK: u8 = 0x06;
            let reply = rh.read_u8().await.unwrap();
            assert_eq!(reply, ACK);
        }
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

    pub fn allowed_clients(&self) -> &BTreeSet<NodeId> {
        match self.allowed_clients.nodes() {
            SomeOrAllNodes::Some(nodes) => nodes,
            SomeOrAllNodes::All => unimplemented!(),
        }
    }
}
