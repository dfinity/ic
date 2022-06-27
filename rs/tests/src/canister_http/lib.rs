use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::util::{self};
use canister_test::Canister;
use canister_test::Runtime;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
pub use ic_types::{CanisterId, PrincipalId};
use slog::info;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(3),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn await_nodes_healthy(env: &TestEnv) {
    info!(&env.logger(), "Checking readiness of all nodes...");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn install_nns_canisters(env: &TestEnv) {
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    nns_node
        .install_nns_canisters()
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");
}

pub fn get_node_snapshots(env: &TestEnv) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet")
        .nodes()
}

pub fn get_runtime_from_node(node: &IcNodeSnapshot) -> Runtime {
    util::runtime_from_url(node.get_public_url())
}

pub fn create_proxy_canister<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    node: &IcNodeSnapshot,
) -> Canister<'a> {
    info!(&env.logger(), "Installing proxy_canister.");
    let proxy_canister_id = node.create_and_install_canister_with_arg("proxy_canister.wasm", None);
    info!(
        &env.logger(),
        "proxy_canister {} installed", proxy_canister_id
    );
    Canister::new(
        runtime,
        CanisterId::new(PrincipalId::from(proxy_canister_id)).unwrap(),
    )
}
