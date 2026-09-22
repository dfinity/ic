//! Defines the [`ReplicaConfig`].
use crate::{NodeId, PlatformVersion, ReplicaVersion, SubnetId};
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

impl ReplicaConfig {
    pub fn replica_version(&self) -> &ReplicaVersion {
        &self.platform_version.replica_version
    }

    pub fn guestos_version(&self) -> &ReplicaVersion {
        &self.platform_version.guestos_version
    }
}
