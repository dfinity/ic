//! Defines the [`ReplicaConfig`].
use crate::{NodeId, PrincipalId, ReplicaVersion, SubnetId};
use serde::{Deserialize, Serialize};

pub const NODE_INDEX_DEFAULT: u64 = 0;
pub const SUBNET_ID_DEFAULT: u64 = 0;

/// The replica config.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ReplicaConfig {
    pub node_id: NodeId,
    pub subnet_id: SubnetId,
    /// The GuestOS version the node booted from.
    pub guestos_version: ReplicaVersion,
    /// The replica binary version, possibly hot-swapped by a fast upgrade.
    pub replica_version: ReplicaVersion,
}

impl ReplicaConfig {
    /// True while a fast upgrade swapped the binaries but the node has not
    /// yet rebooted into the target GuestOS.
    pub fn needs_reboot(&self) -> bool {
        self.guestos_version != self.replica_version
    }
}

impl Default for ReplicaConfig {
    fn default() -> Self {
        ReplicaConfig {
            node_id: NodeId::from(PrincipalId::new_node_test_id(NODE_INDEX_DEFAULT)),
            subnet_id: SubnetId::from(PrincipalId::new_subnet_test_id(SUBNET_ID_DEFAULT)),
            guestos_version: ReplicaVersion::default(),
            replica_version: ReplicaVersion::default(),
        }
    }
}
