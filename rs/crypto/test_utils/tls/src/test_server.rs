#![allow(clippy::unwrap_used)]
use crate::registry::REG_V1;
use crate::temp_crypto_component_with_tls_keys;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::{AuthenticatedPeer, SomeOrAllNodes, TlsConfig};
use ic_crypto_utils_tls::node_id_from_certificate_der;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_types::NodeId;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

pub struct ServerBuilder {
    node_id: NodeId,
    msg_for_client: Option<String>,
    msg_expected_from_client: Option<String>,
    allowed_nodes: Option<SomeOrAllNodes>,
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

    pub fn build(self, registry: Arc<FakeRegistryClient>) -> Server {
        let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).expect("failed to bind");
        let (crypto, cert) = temp_crypto_component_with_tls_keys(registry, self.node_id);
        let allowed_clients = self
            .allowed_nodes
            .unwrap_or_else(|| SomeOrAllNodes::Some(BTreeSet::new()));
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
    allowed_clients: SomeOrAllNodes,
    msg_for_client: Option<String>,
    msg_expected_from_client: Option<String>,
    cert: TlsPublicKeyCert,
}

#[derive(Debug)]
pub struct TlsTestServerRunError(pub String);

impl Server {
    pub fn builder(node_id: NodeId) -> ServerBuilder {
        ServerBuilder {
            node_id,
            msg_for_client: None,
            msg_expected_from_client: None,
            allowed_nodes: None,
        }
    }

    pub async fn run(&self) -> Result<AuthenticatedPeer, TlsTestServerRunError> {
        let tcp_stream = self.accept_connection_on_listener().await;

        let server_config = self
            .crypto
            .server_config(self.allowed_clients.clone(), REG_V1)
            .map_err(|e| {
                TlsTestServerRunError(format!("handshake error when creating config: {e}"))
            })?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
        let tls_stream = tls_acceptor
            .accept(tcp_stream)
            .await
            .map_err(|e| TlsTestServerRunError(format!("handshake error when accepting: {e}")))?;

        let peer_cert = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first()
            .unwrap();

        let authenticated_node =
            AuthenticatedPeer::Node(node_id_from_certificate_der(peer_cert.as_ref()).unwrap());

        let (mut rh, mut wh) = tokio::io::split(tls_stream);

        self.send_msg_to_client_if_configured(&mut wh, &mut rh)
            .await;
        self.expect_msg_from_client_if_configured(&mut rh, &mut wh)
            .await;
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

    async fn expect_msg_from_client_if_configured<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        rd: &mut R,
        wr: &mut W,
    ) {
        if let Some(msg_expected_from_client) = &self.msg_expected_from_client {
            let reader = BufReader::new(rd);
            let msg = reader.lines().next_line().await.unwrap().unwrap();
            assert_eq!(&msg, msg_expected_from_client);

            const ACK: u8 = 0x06;
            wr.write_u8(ACK).await.unwrap();
        }
    }

    async fn send_msg_to_client_if_configured<W: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
        &self,
        wr: &mut W,
        rd: &mut R,
    ) {
        if let Some(msg_for_client) = &self.msg_for_client {
            // Append a newline (end of line, EOL, 0xA) so the peer knows where the msg ends
            let msg_with_eol = format!("{}\n", msg_for_client);
            #[allow(clippy::disallowed_methods)]
            let num_bytes_written = wr.write(msg_with_eol.as_bytes()).await.unwrap();
            assert_eq!(num_bytes_written, msg_with_eol.as_bytes().len());

            const ACK: u8 = 0x06;
            let reply = rd.read_u8().await.unwrap();
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
        match &self.allowed_clients {
            SomeOrAllNodes::Some(nodes) => nodes,
            SomeOrAllNodes::All => unimplemented!(),
        }
    }
}
