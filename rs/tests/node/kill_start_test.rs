// This is a regression test introduced in https://github.com/dfinity/ic/pull/7025.
// It checks if killing an IC node does not corrupt the filesystems of its data partitions.
// The test deploys a single node IC and then in a loop (to increase the probability of corruption):
// * kills the node,
// * waits a bit,
// * starts it back up again,
// * checks if it comes back up healthy
//   and if the data partitions are mounted correctly.

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::*;
use ic_system_test_driver::systest;
use slog::info;
use std::time::Duration;

const POST_KILL_SLEEP_DURATION: Duration = Duration::from_secs(5);

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn test(env: TestEnv) {
    let log = env.logger();
    let node = env.get_first_healthy_system_node_snapshot();
    let node_id = node.node_id;
    let vm = node.vm();
    let num_kill_start_iterations = std::env::var("NUM_KILL_START_ITERATIONS")
        .expect("NUM_KILL_START_ITERATIONS not set")
        .parse::<usize>()
        .unwrap();
    for i in 1..=num_kill_start_iterations {
        info!(
            log,
            "Kill start iteration: {i}/{num_kill_start_iterations} ..."
        );

        // node.await_status_is_healthy().expect("Node not healthy");
        std::thread::sleep(Duration::from_secs(30));
        info!(log, "Killing node: {node_id} ...");
        vm.kill();
        node.await_status_is_unavailable()
            .expect("Node still healthy");

        info!(log, "Sleeping for {POST_KILL_SLEEP_DURATION:?}...");
        std::thread::sleep(POST_KILL_SLEEP_DURATION);

        info!(log, "Starting node: {node_id} ...");
        vm.start();
        node.await_status_is_healthy().expect("Node not healthy");

        let cmd =
            "findmnt /var/lib/ic/backup && findmnt /var/lib/ic/crypto && findmnt /var/lib/ic/data";
        let out = node.block_on_bash_script(cmd).unwrap();
        info!(log, "{cmd}:\n{out}");
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
