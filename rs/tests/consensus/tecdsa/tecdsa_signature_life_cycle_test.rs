#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::tecdsa::tecdsa_signature_test::{
    config_without_ecdsa_on_nns, test_threshold_ecdsa_life_cycle, LIFE_CYCLE_OVERALL_TIMEOUT,
    LIFE_CYCLE_PER_TEST_TIMEOUT,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_without_ecdsa_on_nns)
        .with_overall_timeout(LIFE_CYCLE_OVERALL_TIMEOUT)
        .with_timeout_per_test(LIFE_CYCLE_PER_TEST_TIMEOUT)
        .add_test(systest!(test_threshold_ecdsa_life_cycle))
        .execute_from_args()?;
    Ok(())
}
