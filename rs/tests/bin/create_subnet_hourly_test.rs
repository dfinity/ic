#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::nns_tests::create_subnet;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(create_subnet::hourly_config)
        .add_test(systest!(create_subnet::test))
        .execute_from_args()?;
    Ok(())
}
