// This is a regression test that checks if killing an IC node does not corrupt the filesystems of its data partitions.
// The test deploys a single node IC, kills the node, waits a bit, and then starts the node again and checks if it comes back up healthy.
use anyhow::Result;
use ic_consensus_system_test_upgrade_common::{start_node, stop_node};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use ic_system_test_driver::systest;
use slog::info;
use std::time::Duration;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn test(env: TestEnv) {
    let log = env.logger();
    let node = env.get_first_healthy_system_node_snapshot();
    stop_node(&log, &node);
    info!(log, "Sleeping for 10 seconds...");
    std::thread::sleep(Duration::from_secs(10));
    start_node(&log, &node);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
