use crate::driver::ic::VmResources;
use crate::driver::test_env::TestEnvAttribute;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GroupSetup {
    pub group_base_name: String,
    pub infra_group_name: String,
    /// For now, the group timeout strictly translates to the corresponding group
    /// TTL.
    pub group_timeout: Option<Duration>,
    pub default_vm_resources: Option<VmResources>,
}

impl GroupSetup {
    pub fn new(group_base_name: String, timeout: Option<Duration>) -> Self {
        // binary_name-timestamp
        let mut res = GroupSetup {
            group_base_name: group_base_name.clone(),
            ..Default::default()
        };
        let time = Utc::now().format("%Y-%m-%dT%H-%M-%S-%6f");

        res.infra_group_name = format!("{group_base_name}--{time}").replace('_', "-");
        res.group_timeout = timeout;
        res
    }
}

impl TestEnvAttribute for GroupSetup {
    fn attribute_name() -> String {
        "group_setup".to_string()
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum InfraProvider {
    Farm,
}

impl TestEnvAttribute for InfraProvider {
    fn attribute_name() -> String {
        "infra_provider".to_string()
    }
}
