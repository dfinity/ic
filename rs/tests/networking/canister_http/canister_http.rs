use canister_test::Canister;
use canister_test::Runtime;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_tests::driver::ic::{InternetComputer, Subnet};
use ic_tests::driver::test_env_api::{HasTopologySnapshot, IcNodeContainer, RetrieveIpv4Addr};
use ic_tests::driver::universal_vm::*;
use ic_tests::driver::{test_env::TestEnv, test_env_api::*};
use ic_tests::util::{self, create_and_install};
pub use ic_types::{CanisterId, PrincipalId};
use slog::info;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub const UNIVERSAL_VM_NAME: &str = "httpbin";
pub const EXPIRATION: Duration = Duration::from_secs(120);
pub const BACKOFF_DELAY: Duration = Duration::from_secs(5);

pub enum PemType {
    PemCert,
    PemKey,
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
    NnsInstallationBuilder::new()
        .install(&nns_node, env)
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");
}

// WIP [NNS1-2157]
pub fn install_mainnet_nns_canisters(env: &TestEnv) {
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    NnsInstallationBuilder::new()
        .use_mainnet_nns_canisters()
        .install(&nns_node, env)
        .expect("Mainnet NNS canisters not installed");
    info!(&env.logger(), "Mainnet NNS canisters installed");
}

// WIP [NNS1-2157]
pub fn install_qualifying_nns_canisters(env: &TestEnv) {
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    NnsInstallationBuilder::new()
        .use_qualifying_nns_canisters()
        .install(&nns_node, env)
        .expect("Qualifying NNS canisters not installed");
    info!(&env.logger(), "Qualifying NNS canisters installed");
}

pub fn setup(env: TestEnv) {
    // Set up Universal VM with HTTP Bin testing service
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(
            env.get_dependency_path("rs/tests/networking/canister_http/http_uvm_config_image.zst"),
        )
        .enable_ipv4()
        .start(&env)
        .expect("failed to set up universal VM");

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    await_nodes_healthy(&env);
    install_nns_canisters(&env);
}

pub fn get_pem_content(test_env: &TestEnv, typ: &PemType) -> String {
    match typ {
        PemType::PemCert => test_env
            .get_canister_http_test_ca_cert()
            .expect("Did find test CA file"),
        PemType::PemKey => test_env
            .get_canister_http_test_ca_key()
            .expect("Did not find test CA key file"),
    }
}

pub fn get_universal_vm_address(env: &TestEnv) -> Ipv6Addr {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let webserver_ipv6: Ipv6Addr = universal_vm.ipv6;
    info!(&env.logger(), "Webserver has IPv6 {:?}", webserver_ipv6);
    webserver_ipv6
}

pub fn get_universal_vm_ipv4_address(env: &TestEnv) -> Ipv4Addr {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let webserver_ipv4 = deployed_universal_vm
        .block_on_ipv4()
        .expect("Universal VM IPv4 not found.");
    info!(&env.logger(), "Webserver has IPv4 {:?}", webserver_ipv4);
    webserver_ipv4
}

pub fn get_node_snapshots(env: &TestEnv) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet")
        .nodes()
}

pub fn get_system_subnet_node_snapshots(env: &TestEnv) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::System)
        .expect("there is no system subnet")
        .nodes()
}

pub fn get_runtime_from_node(node: &IcNodeSnapshot) -> Runtime {
    util::runtime_from_url(node.get_public_url(), node.effective_canister_id())
}

pub fn create_proxy_canister<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    node: &IcNodeSnapshot,
) -> Canister<'a> {
    info!(&env.logger(), "Installing proxy_canister.");

    // Create proxy canister with maximum canister cycles.
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let proxy_canister_id = rt.block_on(create_and_install(
        &node.build_default_agent(),
        node.effective_canister_id(),
        &env.load_wasm("rs/rust_canisters/proxy_canister/proxy_canister.wasm"),
    ));
    info!(
        &env.logger(),
        "proxy_canister {} installed", proxy_canister_id
    );
    Canister::new(
        runtime,
        CanisterId::unchecked_from_principal(PrincipalId::from(proxy_canister_id)),
    )
}
