//! The replica config store.
use ic_types::replica_config::ReplicaConfig;
use ic_types::NodeId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Errors that ReplicaConfigStore can return.
#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
pub enum ReplicaConfigStoreError {
    /// The node ID is already set.
    NodeIdExists(NodeId),
}

impl fmt::Display for ReplicaConfigStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplicaConfigStoreError::NodeIdExists(node_id) => {
                write!(f, "Node ID is already set: {}.", node_id)
            }
        }
    }
}

impl std::error::Error for ReplicaConfigStoreError {}

/// An API for storing a `ReplicaConfig`.
pub trait ReplicaConfigStore {
    /// Note: This is a write once interface.  Write twice and this will return
    /// an error.
    fn set_node_id(&mut self, node_id: Option<NodeId>) -> Result<NodeId, ReplicaConfigStoreError>;
    fn replica_config(&self) -> ReplicaConfig;
}
