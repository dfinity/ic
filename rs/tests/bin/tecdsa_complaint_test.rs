#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;
use ic_tests::tecdsa::tecdsa_complaint_test;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(tecdsa_complaint_test::config)
        .add_test(systest!(tecdsa_complaint_test::test))
        .execute_from_args()?;
    Ok(())
}
