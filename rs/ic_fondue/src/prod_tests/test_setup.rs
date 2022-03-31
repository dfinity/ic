use crate::ic_manager::{FarmInfo, IcEndpoint, IcHandle, IcSubnet, RuntimeDescriptor};
use crate::prod_tests::cli::AuthorizedSshAccount;
use crate::prod_tests::driver_setup::{AUTHORIZED_SSH_ACCOUNTS, FARM_BASE_URL, FARM_GROUP_NAME};
use crate::prod_tests::test_env::{HasIcPrepDir, TestEnv};
use crate::prod_tests::test_env_api::*;
use anyhow::{bail, Result};
use std::time::Instant;
use url::Url;

pub trait IcHandleConstructor {
    fn ic_handle(&self) -> Result<IcHandle>;
}

impl IcHandleConstructor for TestEnv {
    fn ic_handle(&self) -> Result<IcHandle> {
        let group_name: String = self.read_object(FARM_GROUP_NAME)?;
        let farm_url: Url = self.read_object(FARM_BASE_URL)?;
        let ssh_key_pairs: Vec<AuthorizedSshAccount> = self.read_object(AUTHORIZED_SSH_ACCOUNTS)?;
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
                ssh_key_pairs: ssh_key_pairs.clone(),
                runtime_descriptor: RuntimeDescriptor::Vm(FarmInfo {
                    group_name: group_name.clone(),
                    vm_name: n.node_id.to_string(),
                    url: farm_url.clone(),
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
