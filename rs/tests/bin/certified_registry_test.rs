use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::execution::registry_authentication_test::{setup, test};
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
