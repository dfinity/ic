#[rustfmt::skip]

use anyhow::Result;

use ic_tests::consensus::catch_up_test::{config_catch_up_impossible, test_catch_up_impossible};
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(15 * 60);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_catch_up_impossible)
        .add_test(systest!(test_catch_up_impossible))
        .with_timeout_per_test(TIMEOUT)
        .with_overall_timeout(TIMEOUT)
        .execute_from_args()?;

    Ok(())
}
