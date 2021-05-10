//! Defines the [`ReplicaConfig`].
use crate::{NodeId, PrincipalId, SubnetId};
use serde::{Deserialize, Serialize};

pub const NODE_INDEX_DEFAULT: u64 = 0;
pub const SUBNET_ID_DEFAULT: u64 = 0;

/// The replica config.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReplicaConfig {
    pub node_id: NodeId,
    pub subnet_id: SubnetId,
}

impl ReplicaConfig {
    pub fn new(node_id: NodeId, subnet_id: SubnetId) -> ReplicaConfig {
        Self { node_id, subnet_id }
    }
}

impl Default for ReplicaConfig {
    fn default() -> Self {
        ReplicaConfig::new(
            NodeId::from(PrincipalId::new_node_test_id(NODE_INDEX_DEFAULT)),
            SubnetId::from(PrincipalId::new_subnet_test_id(SUBNET_ID_DEFAULT)),
        )
    }
}
