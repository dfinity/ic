use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::orchestrator::backup_manager::{config, test};
use ic_tests::systest;
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .with_timeout_per_test(Duration::from_secs(15 * 60))
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
