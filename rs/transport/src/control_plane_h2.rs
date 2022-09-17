//! Control plane - Transport connection management.
//!
//! The control plane handles tokio/TLS related details of connection
//! management. This component establishes/accepts connections to/from subnet
//! peers. The component also manages re-establishment of severed connections.

use crate::{
    types::{Connecting, ServerPortState, TransportImplH2},
    utils::{get_peer_label, start_listener},
};
use ic_base_types::{NodeId, RegistryVersion};
use ic_interfaces_transport::{TransportChannelId, TransportError, TransportEventHandler};
use std::net::SocketAddr;
use tokio::{net::TcpListener, task::JoinHandle};

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
        peer_id: &NodeId,
        peer_addr: SocketAddr,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportError> {
        self.allowed_clients.blocking_write().insert(*peer_id);
        *self.registry_version.blocking_write() = registry_version;
        let peer_map = self.peer_map.blocking_write();
        if peer_map.get(peer_id).is_some() {
            return Err(TransportError::AlreadyExists);
        }

        let _peer_label = get_peer_label(&peer_addr.ip().to_string(), peer_id);
        // TODO: P2P-514
        let channel_id = TransportChannelId::from(self.config.legacy_flow_tag);

        let connecting_task = self.spawn_connect_task(channel_id, *peer_id, peer_addr);
        let _connecting_state = Connecting {
            peer_addr,
            connecting_task,
        };

        self.create_peer_state();
        Ok(())
    }

    fn create_peer_state(&self) {
        // TODO NET-1196: Implement
    }

    pub(crate) fn init_client(&self, event_handler: TransportEventHandler) {
        // Creating the listeners requres that we are within a tokio runtime context.
        let _rt_enter_guard = self.rt_handle.enter();
        let server_addr = SocketAddr::new(self.node_ip, self.config.listening_port);
        let tcp_listener = start_listener(server_addr).unwrap_or_else(|err| {
            panic!(
                "Failed to init listener: local_addr = {:?}, error = {:?}",
                server_addr, err
            )
        });

        let channel_id = TransportChannelId::from(self.config.legacy_flow_tag);
        let accept_task = self.spawn_accept_task(channel_id, tcp_listener);
        *self.accept_port.blocking_lock() = Some(ServerPortState { accept_task });
        *self.event_handler.blocking_lock() = Some(event_handler);
    }

    /// Starts the async task to accept the incoming TcpStreams in server mode.
    fn spawn_accept_task(
        &self,
        _channel_id: TransportChannelId,
        _tcp_listener: TcpListener,
    ) -> JoinHandle<()> {
        // TODO NET-1196: Implement
        self.rt_handle.spawn(async move {})
    }

    /// Spawn a task that tries to connect to a peer (forever, or until
    /// connection is established or peer is removed)
    fn spawn_connect_task(
        &self,
        _channel_id: TransportChannelId,
        _peer_id: NodeId,
        _peer_addr: SocketAddr,
    ) -> JoinHandle<()> {
        // TODO NET-1196: Implement
        self.rt_handle.spawn(async move {})
    }
}
