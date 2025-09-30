use std::time::Duration;

use anyhow::Result;

use ic_consensus_system_test_upgrade_common::{start_node, stop_node};
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasTopologySnapshot,
};
use ic_system_test_driver::systest;
use slog::info;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn test(env: TestEnv) {
    let log = env.logger();
    let nns_node = env.get_first_healthy_system_node_snapshot();
    stop_node(&log, &nns_node);
    info!(log, "Sleeping for 120 seconds...");
    std::thread::sleep(Duration::from_secs(120));
    start_node(&log, &nns_node);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
