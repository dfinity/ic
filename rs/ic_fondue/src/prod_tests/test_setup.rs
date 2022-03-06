use super::bootstrap::NodeVms;
use super::driver_setup::DriverContext;
use crate::ic_manager::{FarmInfo, IcEndpoint, IcHandle, IcSubnet, RuntimeDescriptor};
use ic_base_types::NodeId;
use ic_prep_lib::{
    initialized_subnet::InitializedSubnet, internet_computer::InitializedIc, node::InitializedNode,
    prep_state_directory::IcPrepStateDir,
};
use std::time::Instant;

pub fn create_ic_handle(
    ctx: &DriverContext,
    init_ic: &InitializedIc,
    vm_nodes: &NodeVms,
) -> IcHandle {
    let mut public_api_endpoints = vec![];

    vm_nodes.iter().for_each(|(node_id, vm)| {
        let (subnet, node) = node_id_to_subnet(init_ic, *node_id);
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

        let endpoint = IcEndpoint {
            runtime_descriptor: RuntimeDescriptor::Vm(FarmInfo {
                group_name: vm.group_name.clone(),
                vm_name: vm.name.clone(),
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
            node_id: *node_id,
        };
        public_api_endpoints.push(endpoint);
    });

    let ic_prep_working_dir = Some(IcPrepStateDir::new(&init_ic.target_dir));
    IcHandle {
        public_api_endpoints,
        malicious_public_api_endpoints: Vec::new(),
        ic_prep_working_dir,
    }
}

fn node_id_to_subnet(
    init_ic: &InitializedIc,
    node_id: NodeId,
) -> (Option<&InitializedSubnet>, &InitializedNode) {
    if let Some((s, n)) = init_ic
        .initialized_topology
        .values()
        .filter_map(|subnet| {
            subnet
                .initialized_nodes
                .values()
                .find(|n| n.node_id == node_id)
                .map(|n| (subnet, n))
        })
        .next()
    {
        (Some(s), n)
    } else {
        (
            None,
            init_ic
                .unassigned_nodes
                .values()
                .find(|n| n.node_id == node_id)
                .expect("node with given ID not included in topology"),
        )
    }
}
