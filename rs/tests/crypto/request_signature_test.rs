#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::crypto::{config, request_signature_test::request_signature_test};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(request_signature_test))
        .execute_from_args()?;
    Ok(())
}
