#[rustfmt::skip]
use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::{rosetta_tests, systest};
use rosetta_tests::tests;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(group_setup)
        .add_test(systest!(tests::neuron_disburse::test))
        .execute_from_args()?;
    Ok(())
}

fn group_setup(_env: TestEnv) {}
