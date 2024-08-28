use anyhow::Result;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    boundary_node::{BoundaryNode, BoundaryNodeVm},
    group::SystemTestGroup,
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, RetrieveIpv4Addr},
};
use ic_system_test_driver::systest;
use ic_tests::nns_dapp::nns_dapp_customizations;
use sdk_system_tests::{
    asset::get_asset_as_string,
    config::configure_local_network,
    dfx::{BackendType, DfxCommandContext, FrontendType},
    project,
};
use slog::info;
use std::fs;

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    let logger = env.logger();

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    info!(env.logger(), "Waiting for nodes to become healthy ...");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .await_all_nodes_healthy()
            .expect("Failed waiting for all nodes to become healthy")
    });

    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        nns_dapp_customizations(),
    );

    BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
        .allocate_vm(&env)
        .expect("Allocation of BoundaryNode failed.")
        .for_ic(&env, "")
        .use_real_certs_and_dns()
        .start(&env)
        .expect("failed to setup BoundaryNode VM");

    let boundary_node_vm = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    info!(
        &logger,
        "Boundary node {BOUNDARY_NODE_NAME} has IPv4 {:?} and IPv6 {:?}",
        boundary_node_vm.block_on_ipv4().unwrap(),
        boundary_node_vm.ipv6()
    );

    info!(&logger, "Checking BN health");
    boundary_node_vm
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");
}

fn test(env: TestEnv) {
    let log = env.logger();

    configure_local_network(&env);

    let dfx = DfxCommandContext::new(&env);

    dfx.ping();

    dfx.new_project("hello", FrontendType::SimpleAssets, BackendType::Motoko);

    let project_dir = fs::canonicalize(env.base_path()).unwrap().join("hello");

    let dfx = dfx.with_working_dir(&project_dir);

    dfx.deploy();

    let greeting = dfx.canister_call("hello_backend", "greet", r#"("foobar")"#);
    assert_eq!(greeting, "(\"Hello, foobar!\")\n");

    let frontend_canister_id = dfx.canister_id("hello_frontend");

    let asset_body = get_asset_as_string(
        &env,
        BOUNDARY_NODE_NAME,
        &frontend_canister_id,
        "/sample-asset.txt",
    );
    assert_eq!(asset_body, "This is a sample asset!\n");

    project::add_counter_canister(&log, &project_dir);
    dfx.deploy();

    let v = dfx.canister_call("counter", "read", "()");
    assert_eq!(v, "(0 : nat)\n");

    let v = dfx.canister_call("counter", "write", "(63)");
    assert_eq!(v, "()\n");

    let v = dfx.canister_call("counter", "inc_read", "()");
    assert_eq!(v, "(64 : nat)\n");
}
