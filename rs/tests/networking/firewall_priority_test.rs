#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(ic_tests::networking::firewall_priority::config)
        .add_test(systest!(
            ic_tests::networking::firewall_priority::override_firewall_rules_with_priority
        ))
        .execute_from_args()?;

    Ok(())
}
