use anyhow::Result;
use ic_system_test_driver::driver::test_env::{TestEnv, TestEnvAttribute};
use ic_system_test_driver::driver::test_env_api::*;
use ic_system_test_driver::driver::test_setup::GroupSetup;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use slog::info;

fn log_instructions(env: TestEnv) {
    let logger = env.logger();

    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.infra_group_name;
    let host_vm_name = nested::HOST_VM_NAME;

    info!(logger, "To reboot the host VM run the following command:");
    info!(
        logger,
        "curl -X PUT '{farm_url}group/{group_name}/vm/{host_vm_name}/reboot'"
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(|env| nested::config(env, 1, None))
        .add_test(systest!(nested::registration))
        .add_test(systest!(log_instructions))
        .execute_from_args()?;
    Ok(())
}
