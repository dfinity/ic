use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::execution::canister_lifecycle::config_compute_allocation;
use ic_tests::execution::canister_lifecycle::total_compute_allocation_cannot_be_exceeded;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_compute_allocation)
        .add_test(systest!(total_compute_allocation_cannot_be_exceeded))
        .execute_from_args()?;

    Ok(())
}
