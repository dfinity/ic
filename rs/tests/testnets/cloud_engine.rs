// Set up a testnet containing:
//   one 4-node System/NNS subnet, one 4-node CloudEngine subnet (1 node per DC in 4 datacenters),
//   4 unassigned nodes (1 per DC), one API boundary node, one ic-gateway, and a p8s (with grafana) VM.
// All replica nodes use the following resources: 6 vCPUs, 24GiB of RAM, and 50 GiB disk.
//
// You can setup this testnet by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ ict testnet create cloud_engine --output-dir=./cloud_engine -- --test_tmpdir=./cloud_engine
//
// The --output-dir=./cloud_engine will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./cloud_engine will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i cloud_engine/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@
//
// Note that you can get the  address of the IC node from the ict console output:
//
//   {
//     "nodes": [
//       {
//         "id": "...",
//         "ipv6": "..."
//       }
//     ],
//     "subnet_id": "...",
//     "subnet_type": "cloud_engine"
//   }
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.cloud_engine--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.cloud_engine--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.cloud_engine--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy testing!

use anyhow::Result;

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_protobuf::registry::dc::v1::{DataCenterRecord, Gps};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    ic::{InternetComputer, Node, NodeOperatorConfig, Subnet},
    ic_gateway_vm::{HasIcGatewayVm, IC_GATEWAY_VM_NAME, IcGatewayVm},
    test_env::TestEnv,
    test_env_api::HasTopologySnapshot,
};
use ic_types::PrincipalId;
use ic_types_cycles::CanisterCyclesCostSchedule;
use nns_dapp::{
    install_ii_nns_dapp_and_subnet_rental, nns_dapp_customizations, set_authorized_subnets,
};
use std::collections::BTreeMap;

struct DcConfig {
    id: &'static str,
    region: &'static str,
    owner: &'static str,
    latitude: f32,
    longitude: f32,
}

const DATA_CENTERS: &[DcConfig] = &[
    DcConfig {
        id: "Fremont",
        region: "North America,US,California",
        owner: "Hurricane Electric",
        latitude: 37.549,
        longitude: -121.989,
    },
    DcConfig {
        id: "Brussels",
        region: "Europe,BE,Brussels Capital",
        owner: "Digital Realty",
        latitude: 50.839,
        longitude: 4.348,
    },
    DcConfig {
        id: "HongKong 1",
        region: "Asia,HK,HongKong",
        owner: "Unicom",
        latitude: 22.284,
        longitude: 114.269,
    },
    DcConfig {
        id: "Sterling",
        region: "North America,US,Virginia",
        owner: "CyrusOne",
        latitude: 39.004,
        longitude: -77.408,
    },
];

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    let mut ic = InternetComputer::new().add_subnet(Subnet::new(SubnetType::System).add_nodes(4));

    // Build CloudEngine subnet and unassigned nodes distributed across 4 datacenters.
    // Each datacenter gets its own node operator with 1 CloudEngine node + 1 unassigned node.
    let mut cloud_engine_subnet =
        Subnet::new(SubnetType::CloudEngine).with_cost_schedule(CanisterCyclesCostSchedule::Free);
    for (i, dc) in DATA_CENTERS.iter().enumerate() {
        let operator_principal = PrincipalId::new_user_test_id(1000 + i as u64);
        let provider_principal = PrincipalId::new_user_test_id(2000 + i as u64);

        ic = ic
            .add_data_center(DataCenterRecord {
                id: dc.id.to_string(),
                region: dc.region.to_string(),
                owner: dc.owner.to_string(),
                gps: Some(Gps {
                    latitude: dc.latitude,
                    longitude: dc.longitude,
                }),
            })
            .add_node_operator(NodeOperatorConfig {
                name: format!("operator_{}", dc.id),
                principal_id: operator_principal,
                node_provider_principal_id: Some(provider_principal),
                node_allowance: 2,
                dc_id: dc.id.to_string(),
                rewardable_nodes: BTreeMap::from([("type4.1".to_string(), 2)]),
            });

        // 1 CloudEngine node per DC
        cloud_engine_subnet = cloud_engine_subnet
            .add_node(Node::new().with_node_operator_principal_id(operator_principal));

        // 1 unassigned node per DC
        ic = ic
            .with_unassigned_node(Node::new().with_node_operator_principal_id(operator_principal));
    }

    ic = ic
        .add_subnet(cloud_engine_subnet)
        .with_api_boundary_nodes(1);

    ic.setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        nns_dapp_customizations(),
    );
    // deploy ic-gateway
    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(&env)
        .expect("failed to setup ic-gateway");
    let ic_gateway = env.get_deployed_ic_gateway(IC_GATEWAY_VM_NAME).unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();

    // sets the application subnets as "authorized" for canister creation by CMC
    set_authorized_subnets(&env);

    // install II, NNS dapp, and Subnet Rental Canister
    install_ii_nns_dapp_and_subnet_rental(&env, &ic_gateway_url, None);
}
