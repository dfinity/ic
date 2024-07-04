use anyhow::Result;

use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::orchestrator::upgrade_downgrade::{
    config, upgrade_downgrade_nns_subnet, UP_DOWNGRADE_OVERALL_TIMEOUT,
    UP_DOWNGRADE_PER_TEST_TIMEOUT,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(UP_DOWNGRADE_OVERALL_TIMEOUT)
        .with_timeout_per_test(UP_DOWNGRADE_PER_TEST_TIMEOUT)
        .with_setup(|env| config(env, SubnetType::System, true))
        .add_test(systest!(upgrade_downgrade_nns_subnet))
        .execute_from_args()?;

    Ok(())
}
