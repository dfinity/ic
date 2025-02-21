use ic_system_test_driver::{
    driver::{
        boundary_node::BoundaryNode,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            await_boundary_node_healthy, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            NnsInstallationBuilder,
        },
    },
    util::timeit,
};
use std::str::FromStr;

use ic_base_types::PrincipalId;
use ic_registry_subnet_type::SubnetType;

use slog::info;

use crate::helpers::BoundaryNodeHttpsConfig;

pub const TEST_PRINCIPAL: &str = "imx2d-dctwe-ircfz-emzus-bihdn-aoyzy-lkkdi-vi5vw-npnik-noxiy-mae";
pub const TEST_PRIVATE_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIBzyyJ32Kdjixx+ZJvNeUWsqAzSQZfLsOyXKgxc7aH9oAcGBSuBBAAK
oUQDQgAECWc6ZRn9bBP96RM1G6h8ZAtbryO65dKg6cw0Oij2XbnAlb6zSPhU+4hh
gc2Q0JiGrqKks1AVi+8wzmZ+2PQXXA==
-----END EC PRIVATE KEY-----";

pub fn setup_ic_with_bn(bn_name: &str, bn_https_config: BoundaryNodeHttpsConfig, env: TestEnv) {
    let cloned_env = env.clone();
    timeit(cloned_env.logger(), "deploying IC", move || {
        InternetComputer::new()
            .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
            .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
            .setup_and_start(&cloned_env)
            .expect("failed to setup IC under test");
    });

    let cloned_env: TestEnv = env.clone();
    timeit(
        cloned_env.logger(),
        "installing NNS & starting BN concurrently",
        move || {
            std::thread::scope(|s| {
                s.spawn(|| {
                    let nns_node = cloned_env
                        .topology_snapshot()
                        .root_subnet()
                        .nodes()
                        .next()
                        .unwrap();
                    NnsInstallationBuilder::new()
                        .install(&nns_node, &cloned_env)
                        .expect("NNS canisters not installed");
                    info!(cloned_env.logger(), "NNS canisters are installed.");
                });
                s.spawn(|| {
                    let mut bn = BoundaryNode::new(bn_name.to_string())
                        .allocate_vm(&cloned_env)
                        .unwrap()
                        .for_ic(&cloned_env, "");
                    if let BoundaryNodeHttpsConfig::UseRealCertsAndDns = bn_https_config {
                        bn = bn.use_real_certs_and_dns();
                    }
                    bn.start(&cloned_env)
                        .expect("failed to setup BoundaryNode VM");
                });
            });
        },
    );

    let cloned_env = env.clone();
    timeit(
        cloned_env.logger(),
        "waiting until all IC nodes are healthy",
        move || {
            cloned_env.topology_snapshot().subnets().for_each(|subnet| {
                subnet.nodes().for_each(|node| {
                    node.await_status_is_healthy()
                        .expect("Replica did not come up healthy.")
                })
            });
        },
    );

    let cloned_env = env.clone();
    timeit(
        cloned_env.logger(),
        "waiting until Boundary Node is healthy",
        move || {
            await_boundary_node_healthy(&cloned_env, bn_name);
        },
    );
}

pub fn setup_ic(env: TestEnv) {
    let log = env.logger();
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .with_node_provider(PrincipalId::from_str(TEST_PRINCIPAL).unwrap())
        .with_node_operator(PrincipalId::from_str(TEST_PRINCIPAL).unwrap())
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .with_unassigned_nodes(4)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("could not install NNS canisters");
    info!(&log, "Checking readiness of all replica nodes ...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Replica did not come up healthy.");
        }
    }
}
