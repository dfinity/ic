use crate::driver::test_env::TestEnvAttribute;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::driver::constants::GROUP_TTL;
use crate::driver::ic::VmResources;

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct GroupSetup {
    pub group_base_name: String,
    pub infra_group_name: String,
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
    pub fn new(group_base_name: String) -> Self {
        // binary_name-timestamp
        let mut res = GroupSetup {
            group_base_name: group_base_name.clone(),
            ..Default::default()
        };
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("bad things")
            .as_millis();
        res.infra_group_name = format!("{}--{:?}", group_base_name, time).replace('_', "-");
        // GROUP_TTL should be enough for the setup task to allocate the group on InfraProvider
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

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
pub enum InfraProvider {
    Farm,
    K8s,
}

impl TestEnvAttribute for InfraProvider {
    fn attribute_name() -> String {
        "infra_provider".to_string()
    }
}
