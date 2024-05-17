use async_trait::async_trait;
use ic_crypto_tls_interfaces::{
    AuthenticatedPeer, SomeOrAllNodes, TlsClientHandshakeError, TlsHandshake,
    TlsServerHandshakeError, TlsStream,
};
use ic_types::{NodeId, RegistryVersion};
use tokio::net::TcpStream;

/// This implementation of TlsHandshake is so fake that it panics if
/// you try to call any of the methods.
pub struct FakeTlsHandshake;

impl FakeTlsHandshake {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FakeTlsHandshake {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TlsHandshake for FakeTlsHandshake {
    async fn perform_tls_server_handshake(
        &self,
        _tcp_stream: TcpStream,
        _allowed_clients: SomeOrAllNodes,
        _registry_version: RegistryVersion,
    ) -> Result<(Box<dyn TlsStream>, AuthenticatedPeer), TlsServerHandshakeError> {
        unimplemented!()
    }

    async fn perform_tls_client_handshake(
        &self,
        _tcp_stream: TcpStream,
        _server: NodeId,
        _registry_version: RegistryVersion,
    ) -> Result<Box<dyn TlsStream>, TlsClientHandshakeError> {
        unimplemented!()
    }
}
