use ic_interfaces::transport::{AsyncTransportEventHandler, Transport};
use ic_logger::{info, ReplicaLogger};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_types::transport::{
    FlowId, FlowTag, TransportClientType, TransportErrorCode, TransportPayload,
};
use ic_types::{NodeId, RegistryVersion};

use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::{Arc, Mutex, RwLock, Weak};

#[derive(Default)]
struct Deferred {
    // messages that cannot be delivered until client is registered
    // and gossip calls start nodes.
    stash: Vec<(TransportClientType, TransportPayload)>,
    started: bool,
}

pub struct ThreadPort {
    id: NodeId,
    // Access to full hub to route messages across threads
    hub_access: HubAccess,
    client_map: RwLock<HashMap<TransportClientType, ClientState>>,
    log: ReplicaLogger,
    deferred: Mutex<HashMap<NodeId, Deferred>>,
    weak_self: RwLock<Weak<ThreadPort>>,
}

impl Debug for ThreadPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:?}, {:?})", self.id, self.hub_access)
    }
}

#[allow(dead_code)]
impl ThreadPort {
    pub fn new(id: NodeId, hub_access: HubAccess, log: ReplicaLogger) -> Arc<Self> {
        let thread_port = Arc::new(Self {
            id,
            hub_access,
            client_map: RwLock::new(HashMap::new()),
            log,
            deferred: Default::default(),
            weak_self: RwLock::new(Weak::new()),
        });
        *thread_port.weak_self.write().unwrap() = Arc::downgrade(&thread_port);
        thread_port
    }

    fn replay_deferred(&self, client_type: TransportClientType, node_id: NodeId) {
        let replay = {
            let mut deferred_guard = self.deferred.lock().unwrap();
            let deferred_map = &mut *deferred_guard;
            let mut replay = Vec::new();
            let mut i = 0;
            let mut deferred = deferred_map.entry(node_id).or_default();
            while i != deferred.stash.len() {
                let elt = &mut deferred.stash[i];
                if elt.0 == client_type {
                    replay.push(deferred.stash.swap_remove(i));
                } else {
                    i += 1;
                }
            }
            deferred.started = true;
            replay
        };

        let weak_self = self.weak_self.read().unwrap().clone();
        let arc_self = weak_self.upgrade().unwrap();
        for elt in replay.into_iter() {
            info!(
                self.log,
                "Replaying deferred message {:?}: From node {:?} to node {:?}",
                elt.1.clone(),
                node_id,
                self.id
            );

            let arc_self = arc_self.clone();
            let id = self.id;
            tokio::task::spawn(async move {
                if arc_self
                    .send_helper(client_type, node_id, id, elt.1.clone())
                    .await
                    .is_err()
                {
                    println!("!!! Send failed !!!");
                }
            });
        }
    }

    // More expressive send helper,  Allows to explicitly specify send and receive
    // node ids
    async fn send_helper(
        &self,
        client_type: TransportClientType,
        src_node_id: NodeId,
        dest_node_id: NodeId,
        message: TransportPayload,
    ) -> Result<(), TransportErrorCode> {
        // Dispatch  or defer send a message to a node.
        // Dispatch happens only if all 3 conditions are met
        //.
        // 1. Destination  node has installed a port. i.e. destination node has created
        // Thread port.
        //
        // 2. Destination port has registered the client event handler.
        //
        // 3. Destination node has called start connections.
        //
        // For any other case the message processing deferred until
        // the conditions are met.

        // 1.
        let destination_node = {
            let hub_access = self.hub_access.lock().unwrap();
            // All node ports must be connected  to hub before test start.
            hub_access.ports[&dest_node_id].clone()
        };

        // 2.
        let event_handler = {
            let client_map = destination_node.client_map.write().unwrap();
            client_map
                .get(&client_type)
                .map(|s| s.event_handler.clone())
        };

        // 3.
        let event_handler = {
            let mut deferred = destination_node.deferred.lock().unwrap();
            let deferred = deferred.entry(src_node_id).or_default();

            // Stash
            if !deferred.started || event_handler.is_none() {
                println!(
                    "Node {} has no client of type {:?} registered",
                    destination_node.id, client_type
                );
                deferred.stash.push((client_type, message));
                return Ok(());
            } else {
                event_handler.unwrap()
            }
        };

        event_handler
            .send_message(
                FlowId {
                    client_type,
                    peer_id: src_node_id,
                    flow_tag: FlowTag::from(0),
                },
                message,
            )
            .await
            .expect("send message failed");
        Ok(())
    }
}

struct ClientState {
    event_handler: Arc<dyn AsyncTransportEventHandler>,
}

#[derive(Debug)]
pub struct Hub {
    ports: BTreeMap<NodeId, Arc<ThreadPort>>,
}
pub type HubAccess = Arc<Mutex<Hub>>;

impl Default for Hub {
    fn default() -> Self {
        Self {
            ports: Default::default(),
        }
    }
}

impl Hub {
    pub fn insert(&mut self, node: NodeId, port: Arc<ThreadPort>) -> Option<Arc<ThreadPort>> {
        self.ports.insert(node, port)
    }
    pub fn get(&self, node: &NodeId) -> Arc<ThreadPort> {
        self.ports[node].clone()
    }
}

impl Transport for ThreadPort {
    fn register_client(
        &self,
        client_type: TransportClientType,
        event_handler: Arc<dyn AsyncTransportEventHandler>,
    ) -> Result<(), TransportErrorCode> {
        info!(self.log, "Node{} -> Client Registered", self.id);
        let mut client_map = self.client_map.write().unwrap();
        client_map.insert(client_type, ClientState { event_handler });
        Ok(())
    }

    fn start_connections(
        &self,
        client_type: TransportClientType,
        node_id: &NodeId,
        _record: &NodeRecord,
        _registry_version: RegistryVersion,
    ) -> Result<(), TransportErrorCode> {
        info!(
            self.log,
            "Node{} -> Connections to peer {} started", self.id, node_id
        );
        self.replay_deferred(client_type, *node_id);
        Ok(())
    }

    /// Remove the peer from the set of valid neighbors, and tear down the
    /// queues and connections for the peer. Any messages in the Tx and Rx
    /// queues for the peer will be discarded.
    fn stop_connections(
        &self,
        _client_type: TransportClientType,
        peer_id: &NodeId,
        _registry_version: RegistryVersion,
    ) -> Result<(), TransportErrorCode> {
        info!(
            self.log,
            "Node{} -> Connections to peer {} stopped", self.id, *peer_id
        );
        Ok(())
    }

    /// Send the message to the specified peer. The message will be en-queued
    /// into the appropriate TxQ based on the TransportQueueConfig.
    fn send(
        &self,
        client_type: TransportClientType,
        peer_id: &NodeId,
        _flow_tag: FlowTag,
        message: TransportPayload,
    ) -> Result<(), TransportErrorCode> {
        let peer_id = *peer_id;
        let id = self.id;
        let weak_self = self.weak_self.read().unwrap().clone();
        let arc_self = weak_self.upgrade().unwrap();
        tokio::task::spawn(async move {
            arc_self
                .send_helper(client_type, id, peer_id, message)
                .await
        });
        Ok(())
    }

    fn clear_send_queues(&self, _client_type: TransportClientType, _peer_id: &NodeId) {}

    fn clear_send_queue(
        &self,
        _client_type: TransportClientType,
        _peer_id: &NodeId,
        _flow_tag: FlowTag,
    ) {
    }
}
