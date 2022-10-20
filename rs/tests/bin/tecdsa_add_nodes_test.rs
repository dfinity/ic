use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;
use ic_tests::tecdsa;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(tecdsa::tecdsa_add_nodes_test::config)
        .add_test(systest!(tecdsa::tecdsa_add_nodes_test::test))
        .execute_from_args()?;
    Ok(())
}
