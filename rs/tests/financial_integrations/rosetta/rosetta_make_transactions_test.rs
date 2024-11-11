#[rustfmt::skip]
use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;
use ic_tests::rosetta_tests;
use rosetta_tests::setup::{ROSETTA_TESTS_OVERALL_TIMEOUT, ROSETTA_TESTS_PER_TEST_TIMEOUT};
use rosetta_tests::tests;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(group_setup)
        .with_overall_timeout(ROSETTA_TESTS_OVERALL_TIMEOUT)
        .with_timeout_per_test(ROSETTA_TESTS_PER_TEST_TIMEOUT)
        .add_test(systest!(tests::make_transaction::test))
        .execute_from_args()?;
    Ok(())
}

fn group_setup(_env: TestEnv) {}
