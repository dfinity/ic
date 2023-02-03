use crate::driver::test_env::TestEnvAttribute;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::ic::VmResources;
use crate::driver::new::constants::GROUP_TTL;

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct GroupSetup {
    pub farm_group_name: String,
    /// For now, the group timeout strictly translates to the corresponding group
    /// TTL.
    pub group_timeout: Duration,
    pub default_vm_resources: Option<VmResources>,
}

impl GroupSetup {
    // CI
    // old: hourly__node_reassignment_pot-3099270401
    // new: hourly__node_reassignment-3099270401

    // Local
    // old: boundary_nodes_pre_master__boundary_nodes_pot-username-zh1-spm99_zh7_dfinity_network-2784039865
    // new:
    pub fn from_bazel_env() -> Self {
        // binary_name-timestamp
        let mut res = Self::default();
        let exec_path = std::env::current_exe().expect("could not acquire parent process path");
        let fname = exec_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .strip_suffix("_bin")
            .expect("Expected the binary to have a '_bin' suffix!");
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("bad things")
            .as_millis();
        res.farm_group_name = format!("{}--{:?}", fname, time);
        // GROUP_TTL should be enough for the setup task to allocate the group on Farm
        // Afterwards, the group's TTL should be bumped via a keepalive task
        res.group_timeout = GROUP_TTL;
        res
    }
}

impl TestEnvAttribute for GroupSetup {
    fn attribute_name() -> String {
        "group_setup".to_string()
    }
}
