use crate::driver::test_env::TestEnvAttribute;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::ic::VmResources;

#[derive(Deserialize, Serialize, Default)]
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
        let fname = exec_path.file_name().unwrap().to_str().unwrap();
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("bad things")
            .as_millis();
        res.farm_group_name = format!("{}--{:?}", fname, time);
        res.group_timeout = Duration::from_secs(15 * 60);
        res
    }
}

impl TestEnvAttribute for GroupSetup {
    fn attribute_name() -> String {
        "group_setup".to_string()
    }
}
