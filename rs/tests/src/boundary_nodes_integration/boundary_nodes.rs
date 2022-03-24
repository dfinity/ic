/* tag::catalog[]
Title:: Boundary nodes integration test
end::catalog[] */

use ic_fondue::prod_tests::boundary_node::{BoundaryNode, BoundaryNodeVm};
use ic_fondue::prod_tests::ic::{InternetComputer, Subnet};
use ic_fondue::prod_tests::test_env::TestEnv;
use ic_fondue::prod_tests::test_setup::{DefaultIC, HasPublicApiUrl, IcNodeContainer};

use ic_registry_subnet_type::SubnetType;
use slog::{info, Logger};

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(4))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
        .with_nns_urls(vec![/* TODO: fill with the NNS URLs of the IC created above */])
        .start(&env)
        .expect("failed to setup universal VM");
}

pub fn test(env: TestEnv, logger: Logger) {
    let boundary_node_vm = env.get_boundary_node_vm(BOUNDARY_NODE_NAME).unwrap();

    info!(&logger, "Boundary node IPv6: {:?}", boundary_node_vm.ipv6);

    info!(&logger, "Checking readiness of all nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy().unwrap();
        }
    }
}
