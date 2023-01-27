#[rustfmt::skip]
use anyhow::Result;

use ic_tests::driver::new::group::{SystemTestGroup, SystemTestSubGroup};
use ic_tests::driver::test_env::{SshKeyGen, TestEnv};
use ic_tests::driver::test_env_api::{HasGroupSetup, ADMIN};
use ic_tests::{rosetta_tests, systest};
use rosetta_tests::tests;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(group_setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(tests::network::test))
                .add_test(systest!(tests::derive::test))
                .add_test(systest!(tests::make_transaction::test))
                .add_test(systest!(tests::neuron_disburse::test))
                .add_test(systest!(tests::neuron_hotkey::test))
                .add_test(systest!(tests::neuron_dissolve::test))
                .add_test(systest!(tests::neuron_spawn::test))
                .add_test(systest!(tests::neuron_staking::test))
                .add_test(systest!(tests::neuron_follow::test))
                .add_test(systest!(tests::neuron_info::test))
                .add_test(systest!(tests::neuron_maturity::test))
                .add_test(systest!(tests::neuron_voting::test)),
        )
        .execute_from_args()?;
    Ok(())
}

fn group_setup(env: TestEnv) {
    env.ensure_group_setup_created();
    env.ssh_keygen(ADMIN).expect("ssh-keygen failed");
}
