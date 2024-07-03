#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::orchestrator;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(orchestrator::rotate_ecdsa_idkg_key::setup)
        .add_test(systest!(orchestrator::rotate_ecdsa_idkg_key::test))
        .execute_from_args()?;

    Ok(())
}
