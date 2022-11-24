#[rustfmt::skip]

use anyhow::Result;

use ic_tests::basic_health_test::{config_single_host, test};
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_single_host)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
