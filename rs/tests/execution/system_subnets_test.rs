#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::execution;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(execution::config_many_system_subnets)
        .add_test(systest!(execution::nns_shielding::non_nns_canister_attempt_to_create_canister_on_another_subnet_fails))
        .add_test(systest!(execution::nns_shielding::nns_canister_attempt_to_create_canister_on_another_subnet_succeeds))
        .execute_from_args()?;
    Ok(())
}
