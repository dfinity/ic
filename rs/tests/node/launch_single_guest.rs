use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{group::SystemTestGroup, ic::InternetComputer, test_env::TestEnv},
    systest,
};
use slog::info;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn test(env: TestEnv) {
    let logger = env.logger();
    info!(logger, "VM has launched!");
}
