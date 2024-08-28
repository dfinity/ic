use ic_system_test_driver::{
    driver::{
        boundary_node::{BoundaryNode, BoundaryNodeVm},
        ic::{InternetComputer, Subnet},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
            RetrieveIpv4Addr, SshSession, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    util::block_on,
};
use std::{convert::TryFrom, str::FromStr};

use anyhow::Context;

use ic_base_types::PrincipalId;
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;

use slog::{debug, info};

use crate::boundary_nodes::helpers::BoundaryNodeHttpsConfig;

pub(crate) const TEST_PRINCIPAL: &str =
    "imx2d-dctwe-ircfz-emzus-bihdn-aoyzy-lkkdi-vi5vw-npnik-noxiy-mae";
pub(crate) const TEST_PRIVATE_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIBzyyJ32Kdjixx+ZJvNeUWsqAzSQZfLsOyXKgxc7aH9oAcGBSuBBAAK
oUQDQgAECWc6ZRn9bBP96RM1G6h8ZAtbryO65dKg6cw0Oij2XbnAlb6zSPhU+4hh
gc2Q0JiGrqKks1AVi+8wzmZ+2PQXXA==
-----END EC PRIVATE KEY-----";

pub fn setup_ic_with_bn(bn_name: &str, bn_https_config: BoundaryNodeHttpsConfig, env: TestEnv) {
    let log = env.logger();
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
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
    let nns_node_urls = {
        let mut bn = BoundaryNode::new(bn_name.to_string())
            .allocate_vm(&env)
            .unwrap()
            .for_ic(&env, "");
        if let BoundaryNodeHttpsConfig::UseRealCertsAndDns = bn_https_config {
            bn = bn.use_real_certs_and_dns();
        }
        bn.start(&env).expect("failed to setup BoundaryNode VM");
        bn.nns_node_urls
    };
    info!(&log, "Checking readiness of all replica nodes ...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Replica did not come up healthy.");
        }
    }
    info!(log, "Polling registry ...");
    let registry = RegistryCanister::new(nns_node_urls);
    let (latest, routes) = block_on(ic_system_test_driver::retry_with_msg_async!(
        "polling registry",
        &log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let (bytes, latest) = registry
                .get_value(make_routing_table_record_key().into(), None)
                .await
                .context("Failed to `get_value` from registry")?;
            let routes = PbRoutingTable::decode(bytes.as_slice())
                .context("Failed to decode registry routes")?;
            let routes =
                RoutingTable::try_from(routes).context("Failed to convert registry routes")?;
            Ok((latest, routes))
        }
    ))
    .unwrap_or_else(|_| panic!("Failed to poll registry. This is not an Boundary Node error. It is a test environment issue."));
    info!(log, "Latest registry {latest}: {routes:?}");
    let bn = env
        .get_deployed_boundary_node(bn_name)
        .unwrap()
        .get_snapshot()
        .unwrap();
    info!(log, "Boundary node {bn_name} has IPv6 {:?}", bn.ipv6());
    info!(
        log,
        "Boundary node {bn_name} has IPv4 {:?}",
        bn.block_on_ipv4().unwrap()
    );
    info!(log, "Checking BN health");
    bn.await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");
    let list_dependencies = bn
        .block_on_bash_script(
            "systemctl list-dependencies systemd-sysusers.service --all --reverse --no-pager",
        )
        .unwrap();
    debug!(log, "systemctl {bn_name} = '{list_dependencies}'");
    env.sync_with_prometheus();
}

pub fn setup_ic(env: TestEnv) {
    let log = env.logger();
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");
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
    env.sync_with_prometheus();
}
