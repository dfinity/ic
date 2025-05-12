use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, Default)]
pub struct GuestOsUpgradeConfig {
    /// The IP address of the default (active) VM. None if the process is running in the default VM.
    default_vm_ip: Option<String>,
}
