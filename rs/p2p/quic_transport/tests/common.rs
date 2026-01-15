use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_tls_interfaces::{SomeOrAllNodes, TlsConfig, TlsConfigError};
use ic_p2p_test_utils::{RegistryConsensusHandle, temp_crypto_component_with_tls_keys};
use rustls::{ClientConfig, ServerConfig};

pub struct PeerRestrictedTlsConfig {
    allowed_peers: Arc<Mutex<Vec<NodeId>>>,
    crypto: Arc<dyn TlsConfig>,
}

impl PeerRestrictedTlsConfig {
    pub fn new(node_id: NodeId, registry_handler: &RegistryConsensusHandle) -> Self {
        let crypto = temp_crypto_component_with_tls_keys(registry_handler, node_id);
        Self {
            allowed_peers: Arc::new(Mutex::new(Vec::new())),
            crypto,
        }
    }

    pub fn set_allowed_peers(&self, peers: Vec<NodeId>) {
        *self.allowed_peers.lock().unwrap() = peers;
    }
}

impl TlsConfig for PeerRestrictedTlsConfig {
    fn server_config(
        &self,
        _allowed_clients: SomeOrAllNodes,
        registry_version: RegistryVersion,
    ) -> Result<ServerConfig, TlsConfigError> {
        let allowed_clients = SomeOrAllNodes::Some(BTreeSet::from_iter(
            self.allowed_peers.lock().unwrap().clone(),
        ));
        self.crypto.server_config(allowed_clients, registry_version)
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
