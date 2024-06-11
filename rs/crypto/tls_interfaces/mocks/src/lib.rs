use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_tls_interfaces::{SomeOrAllNodes, TlsConfig, TlsConfigError};
use mockall::*;
use rustls::{ClientConfig, ServerConfig};

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
