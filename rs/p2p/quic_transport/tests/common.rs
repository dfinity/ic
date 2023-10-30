use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_tls_interfaces::{SomeOrAllNodes, TlsConfig, TlsConfigError};
use ic_icos_sev_interfaces::{ValidateAttestationError, ValidateAttestedStream};
use ic_p2p_test_utils::{temp_crypto_component_with_tls_keys, RegistryConsensusHandle};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};

pub struct PeerRestrictedSevHandshake {
    allowed_peers: Arc<Mutex<Vec<NodeId>>>,
}

impl Default for PeerRestrictedSevHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRestrictedSevHandshake {
    pub fn new() -> Self {
        Self {
            allowed_peers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn set_allowed_peers(&self, peers: Vec<NodeId>) {
        println!("STE {peers:?}");
        *self.allowed_peers.lock().unwrap() = peers;
    }
}

#[async_trait::async_trait]
impl<S> ValidateAttestedStream<S> for PeerRestrictedSevHandshake
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    async fn perform_attestation_validation(
        &self,
        stream: S,
        peer: NodeId,
        _registry_version: RegistryVersion,
    ) -> Result<S, ValidateAttestationError> {
        let peers = self.allowed_peers.lock().unwrap();
        if peers.contains(&peer) {
            Ok(stream)
        } else {
            Err(ValidateAttestationError::HandshakeError {
                description: "Peer rejected".to_string(),
            })
        }
    }
}

pub struct PeerRestrictedTlsConfig {
    allowed_peers: Arc<Mutex<Vec<NodeId>>>,
    crypto: Arc<dyn TlsConfig + Send + Sync>,
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
            self.allowed_peers.lock().unwrap().clone().into_iter(),
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
