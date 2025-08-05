use ic_consensus_system_test_liveness_test_common::test;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;
use ic_types::malicious_behavior::MaliciousBehavior;

use anyhow::Result;

fn setup(env: TestEnv) {
    let malicious_behavior =
        MaliciousBehavior::new(true).set_maliciously_propose_equivocating_blocks();
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(3)
                .add_malicious_nodes(1, malicious_behavior),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
