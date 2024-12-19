use std::{
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
};

use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_tls_interfaces::{TlsConfig, TlsConfigError};
use ic_p2p_test_utils::{temp_crypto_component_with_tls_keys, RegistryConsensusHandle};
use rustls::{ClientConfig, ServerConfig};

pub struct FailingTlsConfig {
    should_fail: AtomicBool,
    crypto: Arc<dyn TlsConfig + Send + Sync>,
}

impl FailingTlsConfig {
    pub fn new(node_id: NodeId, registry_handler: &RegistryConsensusHandle) -> Self {
        let crypto = temp_crypto_component_with_tls_keys(registry_handler, node_id);
        Self {
            should_fail: AtomicBool::new(true),
            crypto,
        }
    }

    pub fn set_should_fail(&self, should_fail: bool) {
        self.should_fail.store(should_fail, Ordering::Relaxed);
    }
}

impl TlsConfig for FailingTlsConfig {
    fn server_config(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<ServerConfig, TlsConfigError> {
        if self.should_fail.load(Ordering::Relaxed) {
            return Err(TlsConfigError::MalformedSelfCertificate {
                internal_error: "".to_string(),
            });
        }
        self.crypto.server_config(registry_version)
    }

    fn server_config_without_client_auth(
        &self,
        _registry_version: RegistryVersion,
    ) -> Result<ServerConfig, TlsConfigError> {
        todo!()
    }

    fn client_config(
        &self,
        server: NodeId,
        registry_version: RegistryVersion,
    ) -> Result<ClientConfig, TlsConfigError> {
        self.crypto.client_config(server, registry_version)
    }
}
