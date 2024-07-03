#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::tecdsa::tecdsa_signature_test::{
    config, test_threshold_ecdsa_signature_from_nns_without_cycles,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(
            test_threshold_ecdsa_signature_from_nns_without_cycles
        ))
        .execute_from_args()?;
    Ok(())
}
