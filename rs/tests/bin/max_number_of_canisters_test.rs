use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::execution::canister_lifecycle::creating_canisters_fails_if_limit_of_allowed_canisters_is_reached;
use ic_tests::execution::config_max_number_of_canisters;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_max_number_of_canisters)
        .add_test(systest!(
            creating_canisters_fails_if_limit_of_allowed_canisters_is_reached
        ))
        .execute_from_args()?;

    Ok(())
}
