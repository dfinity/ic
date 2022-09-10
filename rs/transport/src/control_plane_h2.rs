//! Control plane - Transport connection management.
//!
//! The control plane handles tokio/TLS related details of connection
//! management. This component establishes/accepts connections to/from subnet
//! peers. The component also manages re-establishment of severed connections.

use crate::types::TransportImplH2;
use ic_base_types::{NodeId, RegistryVersion};
use ic_interfaces_transport::TransportError;
use std::net::SocketAddr;

/// Implementation for the transport control plane
impl TransportImplH2 {
    /// Stops connection to a peer
    pub(crate) fn stop_peer_connection(&self, peer_id: &NodeId) {
        self.allowed_clients.blocking_write().remove(peer_id);
        self.peer_map.blocking_write().remove(peer_id);
    }

    /// Starts connection(s) to a peer and initializes the corresponding data
    /// structures and tasks
    pub(crate) fn start_peer_connection(
        &self,
        _peer_id: &NodeId,
        _peer_addr: SocketAddr,
        _registry_version: RegistryVersion,
    ) -> Result<(), TransportError> {
        // TODO(NET-1173): fill out implementation
        Ok(())
    }
}
