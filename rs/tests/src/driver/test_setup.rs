use crate::driver::driver_setup::IcSetup;
use crate::driver::test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute};
use crate::driver::test_env_api::*;
use anyhow::{bail, Result};
use ic_fondue::ic_manager::{FarmInfo, IcEndpoint, IcHandle, IcSubnet, RuntimeDescriptor};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use super::ic::VmResources;

#[derive(Deserialize, Serialize, Default)]
pub struct GroupSetup {
    pub farm_group_name: String,
    /// For now, the group timeout strictly translates to the corresponding group
    /// TTL.
    pub group_timeout: Duration,
    pub artifact_path: Option<PathBuf>,
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

pub trait IcHandleConstructor {
    fn ic_handle(&self) -> Result<IcHandle>;
}

impl IcHandleConstructor for TestEnv {
    fn ic_handle(&self) -> Result<IcHandle> {
        let group_setup = GroupSetup::read_attribute(self);
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
                    canister_ranges: ts.subnet_canister_ranges(s.subnet_id),
                }),
                started_at,
                runtime_descriptor: RuntimeDescriptor::Vm(FarmInfo {
                    group_name: group_setup.farm_group_name.clone(),
                    vm_name: n.node_id.to_string(),
                    url: ic_setup.farm_base_url.clone(),
                }),
                is_root_subnet: s.map_or(false, |s| s.subnet_id == root_subnet_id),
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
