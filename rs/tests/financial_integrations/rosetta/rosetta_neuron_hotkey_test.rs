#[rustfmt::skip]
use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::{rosetta_tests, systest};
use rosetta_tests::setup::{ROSETTA_TESTS_OVERALL_TIMEOUT, ROSETTA_TESTS_PER_TEST_TIMEOUT};
use rosetta_tests::tests;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(group_setup)
        .with_overall_timeout(ROSETTA_TESTS_OVERALL_TIMEOUT)
        .with_timeout_per_test(ROSETTA_TESTS_PER_TEST_TIMEOUT)
        .add_test(systest!(tests::neuron_hotkey::test))
        .execute_from_args()?;
    Ok(())
}

fn group_setup(_env: TestEnv) {}
