use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::nns_tests::node_removal_from_registry::{config, test};
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
