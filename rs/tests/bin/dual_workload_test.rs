#[rustfmt::skip]

use anyhow::Result;

use ic_tests::consensus::payload_builder_test::{dual_workload_config, dual_workload_test};
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(dual_workload_config)
        .add_test(systest!(dual_workload_test))
        .execute_from_args()?;
    Ok(())
}
