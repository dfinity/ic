use anyhow::Result;

use ic_system_test_driver::{
    driver::group::SystemTestGroup,
    systest,
};
use ic_tests::nns_tests::nns_uninstall_canister_by_proposal::{config, test};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
