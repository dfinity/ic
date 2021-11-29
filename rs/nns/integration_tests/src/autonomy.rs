//! Some simple tests that verify that the NNS is set up in a way that makes it
//! truly an autonomous system.

use assert_matches::assert_matches;
use dfn_candid::candid_multi_arity;
use ic_error_types::ErrorCode;
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder,
};
use ic_types::ic00::CanisterIdRecord;

#[test]
fn test_that_the_anonymous_user_cannot_stop_any_nns_canister() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_canisters =
            NnsCanisters::set_up(&runtime, NnsInitPayloadsBuilder::new().build()).await;

        for canister in &nns_canisters.all_canisters() {
            let res: Result<(), String> = runtime
                .get_management_canister()
                .update_(
                    "stop_canister",
                    candid_multi_arity,
                    (CanisterIdRecord::from(canister.canister_id()),),
                )
                .await;
            assert_matches!(res, Err(msg) if msg.contains(&ErrorCode::CanisterInvalidController.to_string()));
        }

        Ok(())
    });
}
