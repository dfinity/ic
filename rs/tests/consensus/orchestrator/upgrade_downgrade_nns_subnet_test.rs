use anyhow::Result;

use ic_registry_subnet_type::SubnetType;
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::orchestrator::upgrade_downgrade::{config, upgrade_downgrade_nns_subnet};
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(|env| config(env, SubnetType::System, true))
        .add_test(systest!(upgrade_downgrade_nns_subnet))
        .execute_from_args()?;

    Ok(())
}
