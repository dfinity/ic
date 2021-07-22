#![allow(clippy::unwrap_used)]
use crate::tls_utils::{temp_crypto_component_with_tls_keys, REG_V1};
use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::{TlsClientHandshakeError, TlsHandshake, TlsReadHalf, TlsWriteHalf};
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client::fake::FakeRegistryClient;
use ic_types::NodeId;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct ClientBuilder {
    node_id: NodeId,
    server_node_id: NodeId,
    msg_expected_from_server: Option<String>,
    msg_for_server: Option<String>,
    expected_error_substring_when_reading_stream: Option<String>,
}

impl ClientBuilder {
    pub fn expect_msg_from_server(mut self, msg: &str) -> ClientBuilder {
        self.msg_expected_from_server = Some(msg.to_string());
        self
    }

    pub fn expect_error_when_reading_stream_contains(mut self, msg: &str) -> ClientBuilder {
        self.expected_error_substring_when_reading_stream = Some(msg.to_string());
        self
    }

    pub fn with_message_for_server(mut self, msg: &str) -> ClientBuilder {
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

    pub async fn run(self, server_port: u16) -> Result<(), TlsClientHandshakeError> {
        let tcp_stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .expect("failed to connect");

        let tls_stream = self
            .crypto
            .perform_tls_client_handshake(tcp_stream, self.server_node_id, REG_V1)
            .await?;
        let (mut tls_read_half, tls_write_half) = tls_stream.split();

        self.expect_msg_from_server_if_configured(&mut tls_read_half)
            .await;
        self.send_msg_to_server_if_configured(tls_write_half).await;
        self.expect_error_substring_when_reading_stream_if_configured(&mut tls_read_half)
            .await;
        Ok(())
    }

    async fn send_msg_to_server_if_configured(&self, mut tls_write_half: TlsWriteHalf) {
        if let Some(msg_for_server) = &self.msg_for_server {
            let num_bytes_written = tls_write_half
                .write(&msg_for_server.as_bytes())
                .await
                .unwrap();
            assert_eq!(num_bytes_written, msg_for_server.as_bytes().len());
        }
    }

    async fn expect_msg_from_server_if_configured(&self, tls_read_half: &mut TlsReadHalf) {
        if let Some(msg_expected_from_server) = &self.msg_expected_from_server {
            let mut bytes_from_server = Vec::new();
            tls_read_half
                .read_to_end(&mut bytes_from_server)
                .await
                .expect("error in read_to_end");
            let msg_from_server = String::from_utf8(bytes_from_server.to_vec()).unwrap();
            assert_eq!(msg_from_server, msg_expected_from_server.clone());
        }
    }

    async fn expect_error_substring_when_reading_stream_if_configured(
        &self,
        tls_read_half: &mut TlsReadHalf,
    ) {
        if let Some(expected_error_substring_when_reading_stream) =
            &self.expected_error_substring_when_reading_stream
        {
            let mut bytes_from_server = Vec::new();
            let error = tls_read_half
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
