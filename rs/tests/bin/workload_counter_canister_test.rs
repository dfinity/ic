#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;
use ic_tests::workload_counter_canister_test;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(workload_counter_canister_test::config)
        .add_test(systest!(workload_counter_canister_test::short_test))
        .execute_from_args()?;
    Ok(())
}
