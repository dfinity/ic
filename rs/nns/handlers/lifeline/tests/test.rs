use dfn_candid::candid;
use ic_ic00_types::CanisterIdRecord;
use ic_nns_common::init::LifelineCanisterInitPayloadBuilder;
use ic_nns_handler_root::common::CanisterStatusResult;
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, set_up_lifeline_canister, set_up_universal_canister,
};

/// Verifies that an anonymous user can get the status of a lifeline-owned
/// canister through the lifeline.
#[test]
fn test_get_status() {
    local_test_on_nns_subnet(|runtime| async move {
        let lifeline =
            set_up_lifeline_canister(&runtime, LifelineCanisterInitPayloadBuilder::new().build())
                .await;

        // Create some NNS canister to be owned by the lifeline
        let universal = set_up_universal_canister(&runtime).await;
        universal
            .set_controller(lifeline.canister_id().get())
            .await
            .unwrap();

        // Get the status of an NNS canister
        let status: CanisterStatusResult = lifeline
            .update_(
                "canister_status",
                candid,
                (CanisterIdRecord::from(universal.canister_id()),),
            )
            .await
            .unwrap();
        assert_eq!(status.controller(), lifeline.canister_id().get());

        Ok(())
    });
}
