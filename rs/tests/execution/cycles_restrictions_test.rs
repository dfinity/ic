use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::execution::canister_lifecycle::controller_and_controllee_on_different_subnets;
use ic_tests::execution::config_system_verified_application_subnets;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_system_verified_application_subnets)
        .add_test(systest!(controller_and_controllee_on_different_subnets))
        .execute_from_args()?;

    Ok(())
}
