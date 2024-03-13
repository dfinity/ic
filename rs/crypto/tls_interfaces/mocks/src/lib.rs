use async_trait::async_trait;
use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_tls_interfaces::{
    AuthenticatedPeer, SomeOrAllNodes, TlsClientHandshakeError, TlsConfig, TlsConfigError,
    TlsHandshake, TlsServerHandshakeError, TlsStream,
};
use mockall::*;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, ServerConfig};

mock! {
    pub TlsHandshake {}

    #[async_trait]
    impl TlsHandshake for TlsHandshake {
        async fn perform_tls_server_handshake(
            &self,
            tcp_stream: TcpStream,
            allowed_clients: SomeOrAllNodes,
            registry_version: RegistryVersion,
        ) -> Result<(Box<dyn TlsStream>, AuthenticatedPeer), TlsServerHandshakeError>;

        async fn perform_tls_server_handshake_without_client_auth(
            &self,
            tcp_stream: TcpStream,
            registry_version: RegistryVersion,
        ) -> Result<Box<dyn TlsStream>, TlsServerHandshakeError>;

        async fn perform_tls_client_handshake(
            &self,
            tcp_stream: TcpStream,
            server: NodeId,
            registry_version: RegistryVersion,
        ) -> Result<Box<dyn TlsStream>, TlsClientHandshakeError>;
    }
}

mock! {

    pub TlsConfig {}

    impl TlsConfig for TlsConfig {
        fn server_config(
            &self,
            allowed_clients: SomeOrAllNodes,
            registry_version: RegistryVersion,
        ) -> Result<ServerConfig, TlsConfigError>;

        fn server_config_without_client_auth(
            &self,
            registry_version: RegistryVersion,
        ) -> Result<ServerConfig, TlsConfigError>;

        fn client_config(
            &self,
            server: NodeId,
            registry_version: RegistryVersion,
        ) -> Result<ClientConfig, TlsConfigError>;
    }
}
