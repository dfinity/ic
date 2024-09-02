#![allow(clippy::unwrap_used)]
use crate::registry::REG_V1;
use crate::temp_crypto_component_with_tls_keys;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_types::NodeId;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub struct ClientBuilder {
    node_id: NodeId,
    server_node_id: NodeId,
    msg_expected_from_server: Option<String>,
    msg_for_server: Option<String>,
    expected_error_substring_when_reading_stream: Option<String>,
}

impl ClientBuilder {
    pub fn expect_msg_from_server(mut self, msg: &str) -> Self {
        self.msg_expected_from_server = Some(msg.to_string());
        self
    }

    pub fn expect_error_when_reading_stream_contains(mut self, msg: &str) -> Self {
        self.expected_error_substring_when_reading_stream = Some(msg.to_string());
        self
    }

    pub fn with_message_for_server(mut self, msg: &str) -> Self {
        self.msg_for_server = Some(msg.to_string());
        self
    }

    pub fn build(self, registry: Arc<FakeRegistryClient>) -> Client {
        let (crypto, cert) = temp_crypto_component_with_tls_keys(registry, self.node_id);
        Client {
            crypto,
            server_node_id: self.server_node_id,
            msg_expected_from_server: self.msg_expected_from_server,
            msg_for_server: self.msg_for_server,
            expected_error_substring_when_reading_stream: self
                .expected_error_substring_when_reading_stream,
            cert,
        }
    }
}

#[derive(Debug)]
pub struct TlsTestClientRunError(pub String);

/// A wrapper around the crypto TLS client implementation under test. Allows for
/// easy testing.
pub struct Client {
    crypto: TempCryptoComponent,
    server_node_id: NodeId,
    msg_expected_from_server: Option<String>,
    msg_for_server: Option<String>,
    expected_error_substring_when_reading_stream: Option<String>,
    cert: TlsPublicKeyCert,
}

impl Client {
    pub fn builder(node_id: NodeId, server_node_id: NodeId) -> ClientBuilder {
        ClientBuilder {
            node_id,
            server_node_id,
            msg_expected_from_server: None,
            msg_for_server: None,
            expected_error_substring_when_reading_stream: None,
        }
    }

    pub async fn run(&self, server_port: u16) -> Result<(), TlsTestClientRunError> {
        let tcp_stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .expect("failed to connect");

        let tls_client_config = self
            .crypto
            .client_config(self.server_node_id, REG_V1)
            .map_err(|e| {
                TlsTestClientRunError(format!("handshake error when creating config: {e}"))
            })?;

        let tls_connector = TlsConnector::from(Arc::new(tls_client_config));
        let irrelevant_domain = "domain.is-irrelevant-as-hostname-verification-is.disabled";
        let tls_stream = tls_connector
            .connect(
                irrelevant_domain
                    .try_into()
                    .expect("failed to create domain"),
                tcp_stream,
            )
            .await
            .map_err(|e| TlsTestClientRunError(format!("handshake error when connecting: {e}")))?;

        let (mut rh, mut wh) = tokio::io::split(tls_stream);

        self.expect_msg_from_server_if_configured(&mut rh, &mut wh)
            .await;
        self.send_msg_to_server_if_configured(&mut wh, &mut rh)
            .await;
        self.expect_error_substring_when_reading_stream_if_configured(&mut rh)
            .await;
        Ok(())
    }

    async fn send_msg_to_server_if_configured<W: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
        &self,
        wr: &mut W,
        rd: &mut R,
    ) {
        if let Some(msg_for_server) = &self.msg_for_server {
            // Append a newline (end of line, EOL, 0xA) so the peer knows where the msg ends
            let msg_for_server_with_eol = format!("{}\n", msg_for_server);
            #[allow(clippy::disallowed_methods)]
            let num_bytes_written = wr.write(msg_for_server_with_eol.as_bytes()).await.unwrap();
            assert_eq!(num_bytes_written, msg_for_server_with_eol.as_bytes().len());

            const ACK: u8 = 0x06;
            let reply = rd.read_u8().await.unwrap();
            assert_eq!(reply, ACK);
        }
    }

    async fn expect_msg_from_server_if_configured<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        rd: &mut R,
        wr: &mut W,
    ) {
        if let Some(msg_expected_from_server) = &self.msg_expected_from_server {
            let reader = BufReader::new(rd);
            let msg = reader.lines().next_line().await.unwrap().unwrap();
            assert_eq!(&msg, msg_expected_from_server);

            const ACK: u8 = 0x06;
            wr.write_u8(ACK).await.unwrap();
        }
    }

    async fn expect_error_substring_when_reading_stream_if_configured<R: AsyncRead + Unpin>(
        &self,
        rd: &mut R,
    ) {
        if let Some(expected_error_substring_when_reading_stream) =
            &self.expected_error_substring_when_reading_stream
        {
            let mut bytes_from_server = Vec::new();
            let error = rd
                .read_to_end(&mut bytes_from_server)
                .await
                .expect_err("expected error on read_to_end");
            assert!(error
                .to_string()
                .contains(expected_error_substring_when_reading_stream));
        }
    }

    pub fn cert(&self) -> X509PublicKeyCert {
        self.cert.to_proto()
    }
}
