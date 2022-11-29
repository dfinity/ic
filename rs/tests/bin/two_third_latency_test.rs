#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;
use ic_tests::workload_counter_canister_test::{two_third_latency_config, two_third_latency_test};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(two_third_latency_config)
        .add_test(systest!(two_third_latency_test))
        .execute_from_args()?;

    Ok(())
}
