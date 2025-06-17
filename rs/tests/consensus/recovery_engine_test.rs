/* tag::catalog[]

Title:: NNS recovery engine

Goal::
The test ensures that a subnet can be recovered via recovery artifacts using the recovery image.

Runbook:: ...

Success:: ...

end::catalog[] */

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use ic_system_test_driver::systest;

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .use_recovery_image()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    slog::info!(log, "Running recovery engine test...");

    let node = env.get_first_healthy_node_snapshot();
    slog::info!(log, "Node {} is available.", node.node_id);

    std::thread::sleep(std::time::Duration::from_secs(3600)); // Sleep for 1 hour

    // TODO: Verify successful recovery

    slog::info!(log, "Recovery engine test finished.");
}

pub fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()
}
