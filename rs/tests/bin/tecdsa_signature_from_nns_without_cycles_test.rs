#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;
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
