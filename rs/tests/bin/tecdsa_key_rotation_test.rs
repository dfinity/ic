#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;
use ic_tests::tecdsa::tecdsa_signature_test::{
    config_without_ecdsa_on_nns, test_threshold_ecdsa_key_rotation,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_without_ecdsa_on_nns)
        .add_test(systest!(test_threshold_ecdsa_key_rotation))
        .execute_from_args()?;
    Ok(())
}
