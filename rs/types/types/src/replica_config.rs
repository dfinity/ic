//! Defines the [`ReplicaConfig`].
use crate::{NodeId, ReplicaVersion, SubnetId};
use serde::{Deserialize, Serialize};

pub const NODE_INDEX_DEFAULT: u64 = 0;
pub const SUBNET_ID_DEFAULT: u64 = 0;

/// The replica config.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ReplicaConfig {
    pub node_id: NodeId,
    pub subnet_id: SubnetId,
    pub replica_version: ReplicaVersion,
}
