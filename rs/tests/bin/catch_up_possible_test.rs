#[rustfmt::skip]

use anyhow::Result;

use ic_tests::consensus::catch_up_test::{config_catch_up_possible, test_catch_up_possible};
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_catch_up_possible)
        .add_test(systest!(test_catch_up_possible))
        .execute_from_args()?;

    Ok(())
}
