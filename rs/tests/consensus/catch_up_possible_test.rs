#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::consensus::catch_up_test::{no_catch_up_loop, test_catch_up_possible};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(no_catch_up_loop)
        .add_test(systest!(test_catch_up_possible))
        .execute_from_args()?;

    Ok(())
}
