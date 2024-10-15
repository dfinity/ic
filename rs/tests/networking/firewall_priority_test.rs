#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_networking_system_test_utils::firewall_priority::{config, override_firewall_rules_with_priority};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(override_firewall_rules_with_priority))
        .execute_from_args()?;

    Ok(())
}
