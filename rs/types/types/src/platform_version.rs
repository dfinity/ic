//! [`PlatformVersion`]: the node's GuestOS and binary versions.
//!
//! During a fast upgrade, the GuestOS version (boot partition) and the binary
//! version (replica binary, potentially replaced by an overlay) differ.

use serde::{Deserialize, Serialize};

use crate::ReplicaVersion;

/// The node's platform versions.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct PlatformVersion {
    /// The GuestOS version the node booted from.
    pub guestos_version: ReplicaVersion,
    /// The replica binary version. Under normal conditions, this is the same as
    /// `guestos_version`. During a GuestOS fast upgrade, binaries from the target (new) GuestOS
    /// are hot-swapped in the running (old) GuestOS to allow the subnet to continue running
    /// without downtime. Eventually the node reboots into the target GuestOS, at which point
    /// the binary and GuestOS versions will be the same again.
    pub binary_version: ReplicaVersion,
}

impl Default for PlatformVersion {
    fn default() -> Self {
        Self {
            guestos_version: ReplicaVersion::default(),
            binary_version: ReplicaVersion::default(),
        }
    }
}
