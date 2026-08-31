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
