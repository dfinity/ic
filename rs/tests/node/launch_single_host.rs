use anyhow::Result;
use ic_system_test_driver::driver::{
    group::SystemTestGroup, nested::NestedNodes, test_env::TestEnv,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;

    Ok(())
}

fn setup(env: TestEnv) {
    NestedNodes::new(&["Host"])
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}
