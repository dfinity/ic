use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::orchestrator::upgrade_downgrade::{
    config, upgrade_downgrade_nns_subnet, UP_DOWNGRADE_OVERALL_TIMEOUT,
    UP_DOWNGRADE_PER_TEST_TIMEOUT,
};
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(UP_DOWNGRADE_OVERALL_TIMEOUT)
        .with_timeout_per_test(UP_DOWNGRADE_PER_TEST_TIMEOUT)
        .with_setup(config)
        .add_test(systest!(upgrade_downgrade_nns_subnet))
        .execute_from_args()?;

    Ok(())
}
