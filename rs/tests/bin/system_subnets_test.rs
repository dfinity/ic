#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::execution;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(execution::config_many_system_subnets)
        .add_test(systest!(execution::nns_shielding::non_nns_canister_attempt_to_create_canister_on_another_subnet_fails))
        .add_test(systest!(execution::nns_shielding::nns_canister_attempt_to_create_canister_on_another_subnet_succeeds))
        .execute_from_args()?;
    Ok(())
}
