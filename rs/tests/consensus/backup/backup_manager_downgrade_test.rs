use anyhow::Result;

use ic_consensus_system_test_backup_common::{setup_downgrade, test_downgrade};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_downgrade)
        .with_timeout_per_test(Duration::from_secs(25 * 60))
        .add_test(systest!(test_downgrade))
        .execute_from_args()?;

    Ok(())
}
