use crate::driver::driver_setup::IcSetup;
use crate::driver::test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute};
use crate::driver::test_env_api::*;
use anyhow::{bail, Result};
use ic_fondue::ic_manager::{FarmInfo, IcEndpoint, IcHandle, IcSubnet, RuntimeDescriptor};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::time::Instant;

#[derive(Deserialize, Serialize)]
pub struct PotSetup {
    pub farm_group_name: String,
    pub pot_timeout: Duration,
}

impl TestEnvAttribute for PotSetup {
    fn attribute_name() -> String {
        "pot_setup".to_string()
    }
}

pub trait IcHandleConstructor {
    fn ic_handle(&self) -> Result<IcHandle>;
}

impl IcHandleConstructor for TestEnv {
    fn ic_handle(&self) -> Result<IcHandle> {
        let pot_setup = PotSetup::read_attribute(self);
        let ic_setup = IcSetup::read_attribute(self);
        let ts = self.topology_snapshot();

        let mut nodes = vec![];
        for s in ts.subnets() {
            for n in s.nodes() {
                nodes.push((n, Some(s.clone())));
            }
        }
        for n in ts.unassigned_nodes() {
            nodes.push((n, None));
        }

        let mut public_api_endpoints = vec![];
        let started_at = Instant::now();
        let root_subnet_id = ts.root_subnet_id();
        for (n, s) in nodes {
            public_api_endpoints.push(IcEndpoint {
                node_id: n.node_id,
                url: n.get_public_url(),
                metrics_url: n.get_metrics_url(),
                subnet: s.clone().map(|s| IcSubnet {
                    id: s.subnet_id,
                    type_of: s.subnet_type(),
                }),
                started_at,
                runtime_descriptor: RuntimeDescriptor::Vm(FarmInfo {
                    group_name: pot_setup.farm_group_name.clone(),
                    vm_name: n.node_id.to_string(),
                    url: ic_setup.farm_base_url.clone(),
                }),
                is_root_subnet: s.map_or(false, |s| Some(s.subnet_id) == root_subnet_id),
            });
        }

        let prep_dir = match self.prep_dir("") {
            Some(p) => p,
            None => bail!("No prep dir specified for no-name IC"),
        };
        Ok(IcHandle {
            public_api_endpoints,
            malicious_public_api_endpoints: vec![],
            ic_prep_working_dir: Some(prep_dir),
        })
    }
}
