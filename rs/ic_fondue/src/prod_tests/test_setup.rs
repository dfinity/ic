use super::driver_setup::DriverContext;
use crate::ic_manager::{FarmInfo, IcEndpoint, IcHandle, IcSubnet, RuntimeDescriptor};
use ic_prep_lib::{
    initialized_subnet::InitializedSubnet, internet_computer::InitializedIc, node::InitializedNode,
    prep_state_directory::IcPrepStateDir,
};
use std::time::Instant;

pub fn create_ic_handle(
    ctx: &DriverContext,
    init_ic: &InitializedIc,
    group_name: &str,
) -> IcHandle {
    let mut public_api_endpoints = vec![];
    for s in init_ic.initialized_topology.values() {
        for n in s.initialized_nodes.values() {
            public_api_endpoints.push(node_to_endpoint(n, Some(s), ctx, group_name));
        }
    }
    for n in init_ic.unassigned_nodes.values() {
        public_api_endpoints.push(node_to_endpoint(n, None, ctx, group_name));
    }
    IcHandle {
        public_api_endpoints,
        malicious_public_api_endpoints: vec![],
        ic_prep_working_dir: Some(IcPrepStateDir::new(&init_ic.target_dir)),
    }
}

fn node_to_endpoint(
    node: &InitializedNode,
    subnet: Option<&InitializedSubnet>,
    ctx: &DriverContext,
    group_name: &str,
) -> IcEndpoint {
    let url = node
        .node_config
        .public_api
        .first()
        .expect("No public API endpoint specified")
        .clone()
        .into();
    let metrics_url = node
        .node_config
        .prometheus_metrics
        .first()
        .expect("No metrics address specified")
        .clone()
        .into();

    IcEndpoint {
        runtime_descriptor: RuntimeDescriptor::Vm(FarmInfo {
            group_name: group_name.to_string(),
            vm_name: node.node_id.to_string(),
            url: ctx.farm.base_url.clone(),
        }),
        url,
        metrics_url: Some(metrics_url),
        subnet: subnet.map(|s| IcSubnet {
            id: s.subnet_id,
            type_of: s.subnet_config.subnet_type,
        }),
        is_root_subnet: subnet.map(|s| s.subnet_index) == Some(0),
        started_at: Instant::now(),
        ssh_key_pairs: ctx.authorized_ssh_accounts.clone(),
        node_id: node.node_id,
    }
}
