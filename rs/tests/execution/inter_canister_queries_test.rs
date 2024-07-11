#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::group::SystemTestSubGroup;
use ic_system_test_driver::systest;
use ic_tests::execution::call_on_cleanup::*;
use ic_tests::execution::config_system_verified_subnets;
use ic_tests::execution::inter_canister_queries::*;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_system_verified_subnets)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(intermediate_canister_does_not_reply))
                .add_test(systest!(cannot_query_xnet_canister))
                .add_test(systest!(simple_query))
                .add_test(systest!(self_loop_succeeds))
                .add_test(systest!(canisters_loop_succeeds))
                .add_test(systest!(query_two_canisters))
                .add_test(systest!(query_three_canisters))
                .add_test(systest!(canister_queries_non_existent))
                .add_test(systest!(canister_queries_does_not_reply))
                .add_test(systest!(
                    inter_canister_query_first_canister_multiple_request
                ))
                .add_test(systest!(is_called_if_reply_traps))
                .add_test(systest!(is_called_if_reject_traps))
                .add_test(systest!(changes_are_discarded_if_trapped))
                .add_test(systest!(changes_are_discarded_in_query))
                .add_test(systest!(is_called_in_query)),
        )
        .execute_from_args()?;

    Ok(())
}
