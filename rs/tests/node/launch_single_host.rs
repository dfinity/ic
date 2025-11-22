use anyhow::Result;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup, nested::HasNestedVms, nested::NestedNodes, test_env::TestEnv,
        test_env_api::SshSession,
    },
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
    NestedNodes::new(&["Host"])
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn test(env: TestEnv) {
    let host = env
        .get_nested_vm("Host")
        .expect("Unable to find HostOS node.");

    info!(env.logger(), "Waiting for HostOS to launch");
    host.await_can_login_as_admin_via_ssh().unwrap();
    info!(env.logger(), "HostOS has launched!");
}
