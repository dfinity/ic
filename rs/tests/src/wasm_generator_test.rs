use candid::Encode;
use ic_agent::export::Principal;
use ic_agent::Agent;
use ic_base_types::PrincipalId;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::util;
use ic_utils::interfaces::ManagementCanister;
use slog::info;
use std::env;
use std::fs;
use std::path::Path;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    let app_node = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();
    let app_agent = app_node.with_default_agent(|agent| async move { agent });
    util::block_on(async move {
        info!(log, "Reading canister paths ...");
        // A path of a directory containing canisters has to be passed in to the test
        // through an env variable named `RANDOM_CANISTERS_BASE_DIR`.
        let canisters_base_dir = env::var("RANDOM_CANISTERS_BASE_DIR")
            .expect("RANDOM_CANISTERS_BASE_DIR env variable not set");
        let can_paths =
            fs::read_dir(canisters_base_dir).expect("directory with random canisters is incorrect");

        for p in can_paths {
            info!(log, "Installing canister {:?} ...", p);
            let cid = install_random_canister(
                &app_agent,
                app_node.effective_canister_id(),
                &p.expect("canister path incorrect").path(),
            )
            .await;
            info!(log, "Send query to canister");
            // Verify that the compute function exported by the installed canister can be
            // called.
            let arg = Encode!().unwrap();
            app_agent
                .query(&cid, "compute")
                .with_arg(arg)
                .call()
                .await
                .expect("compute returned error");
        }
    });
}

async fn install_random_canister(
    agent: &Agent,
    effective_canister_id: PrincipalId,
    canister_path: &Path,
) -> Principal {
    let random_canister: Vec<u8> = fs::read(canister_path).expect("could not load random canister");

    let mgr = ManagementCanister::create(agent);
    let cid = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .expect("failed to create a canister")
        .0;
    mgr.install_code(&cid, random_canister.as_slice())
        .call_and_wait()
        .await
        .expect("failed to install canister");
    cid
}
