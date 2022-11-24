#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::orchestrator;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(orchestrator::rotate_ecdsa_idkg_key::setup)
        .add_test(systest!(orchestrator::rotate_ecdsa_idkg_key::test))
        .execute_from_args()?;

    Ok(())
}
