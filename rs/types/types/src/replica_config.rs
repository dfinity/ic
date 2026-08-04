//! Defines the [`ReplicaConfig`].
use crate::{NodeId, PlatformVersion, PrincipalId, SubnetId};
use serde::{Deserialize, Serialize};

pub const NODE_INDEX_DEFAULT: u64 = 0;
pub const SUBNET_ID_DEFAULT: u64 = 0;

/// The replica config.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ReplicaConfig {
    pub node_id: NodeId,
    pub subnet_id: SubnetId,
    pub platform_version: PlatformVersion,
}


impl Default for ReplicaConfig {
    fn default() -> Self {
        ReplicaConfig {
            node_id: NodeId::from(PrincipalId::new_node_test_id(NODE_INDEX_DEFAULT)),
            subnet_id: SubnetId::from(PrincipalId::new_subnet_test_id(SUBNET_ID_DEFAULT)),
            platform_version: PlatformVersion::default(),
        }
    }
}
