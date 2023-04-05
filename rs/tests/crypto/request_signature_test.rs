#[rustfmt::skip]

use anyhow::Result;

use ic_tests::crypto::{config, request_signature_test::request_signature_test};
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(request_signature_test))
        .execute_from_args()?;
    Ok(())
}
