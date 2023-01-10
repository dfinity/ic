use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::orchestrator::downgrade_with_ecdsa::{config, downgrade_app_subnet};
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(downgrade_app_subnet))
        .execute_from_args()?;

    Ok(())
}
