use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::{get_dependency_path, HasTopologySnapshot, IcNodeContainer},
};
use ic_system_test_driver::systest;
use sdk_system_tests::{config::configure_local_network, dfx::DfxCommandContext};
use slog::info;
use std::fs;
use std::path::PathBuf;

const WALLET_CANISTER_0_7_2_WASM: &str = "external/wallet_canister_0.7.2/file/wallet.wasm";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
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
}

// dfx should be able to install and query an old wallet.  The absence of the
// wallet_api_version() method means it is API version 0.
// A replica update changed the way the replica reports errors, and this test
// would have failed.
// https://dfinity.slack.com/archives/C020G13AS4F/p1711437311103869
//
// This test will fail with the following in dfx.bzl:
//    VERSION = "0.18.0"
//    SHA256 = {
//        "linux": "117a9c6a9b39e01e7363d5c8021bbfb007fb48be1448efa993329eec0fce7f09",
//        "darwin": "d13deffe47dfd4a190424c0cb963447cf787edd05818c312df77ac2f9b8d24d7",
//    }

fn test(env: TestEnv) {
    let log = env.logger();

    configure_local_network(&env);

    let dfx = DfxCommandContext::new(&env);

    dfx.version();

    let wallet_wasm_path: PathBuf =
        fs::canonicalize(get_dependency_path(WALLET_CANISTER_0_7_2_WASM)).unwrap();

    info!(
        log,
        "Getting wallet principal (which will create the wallet) ..."
    );
    dfx.with_wallet_wasm(&wallet_wasm_path)
        .identity_get_wallet();

    dfx.wallet_balance();
}
