use anyhow::Result;

use ic_consensus_system_test_subnet_recovery::common::{
    setup_same_nodes as setup, test_no_upgrade_without_chain_keys_local as test,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
