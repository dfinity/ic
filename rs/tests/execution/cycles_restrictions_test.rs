use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::execution::canister_lifecycle::controller_and_controllee_on_different_subnets;
use ic_tests::execution::config_system_verified_application_subnets;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_system_verified_application_subnets)
        .add_test(systest!(controller_and_controllee_on_different_subnets))
        .execute_from_args()?;

    Ok(())
}
