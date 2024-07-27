#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::consensus::payload_builder_test::{dual_workload_config, dual_workload_test};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(dual_workload_config)
        .add_test(systest!(dual_workload_test))
        .execute_from_args()?;
    Ok(())
}
