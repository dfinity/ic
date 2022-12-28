use anyhow::Result;
use std::time::Duration;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::nns_tests::create_subnet;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(15 * 60))
        // expected to take 250..450 seconds
        .with_setup(create_subnet::hourly_config)
        // expected to take up to 200 seconds
        .add_test(systest!(create_subnet::test))
        .execute_from_args()?;
    Ok(())
}
