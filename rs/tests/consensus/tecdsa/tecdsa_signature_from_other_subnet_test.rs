#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::tecdsa::tecdsa_signature_test::{
    config, test_threshold_ecdsa_signature_from_other_subnet,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test_threshold_ecdsa_signature_from_other_subnet))
        .execute_from_args()?;
    Ok(())
}
