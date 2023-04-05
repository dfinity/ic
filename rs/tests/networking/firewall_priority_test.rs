#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(ic_tests::networking::firewall_priority::config)
        .add_test(systest!(
            ic_tests::networking::firewall_priority::override_firewall_rules_with_priority
        ))
        .execute_from_args()?;

    Ok(())
}
