use assert_matches::assert_matches;
use candid::{Decode, Encode};
use canister_test::{local_test_e, Canister, Runtime, Wasm};
use ic_error_types::ErrorCode;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_test_utilities::universal_canister::{
    wasm as universal_canister_argument_builder, CallArgs,
};
use ic_types::ic00::{self, CanisterIdRecord, CanisterStatusResult, IC_00};
use on_wire::bytes;

async fn set_up_universal_canister(runtime: &'_ Runtime) -> Canister<'_> {
    Wasm::from_bytes(UNIVERSAL_CANISTER_WASM)
        .install(runtime)
        .bytes(Vec::new())
        .await
        .unwrap()
}

/// Verifies that calling Canister::set_controller has the expected effect.
#[test]
fn test_set_controller() {
    local_test_e(|runtime| async move {
        let universal_canister = set_up_universal_canister(&runtime).await;

        universal_canister
            .set_controller(universal_canister.canister_id().get())
            .await
            .unwrap();

        // Can't use "query_": we get "IC0301: Could not find subnet for canister
        // aaaaa-aa"
        //
        // The anonymous user is not allowed to do a "canister_status"
        let res: Result<CanisterStatusResult, String> = runtime
            .get_management_canister()
            .update_(
                ic00::Method::CanisterStatus.to_string(),
                dfn_candid::candid,
                (CanisterIdRecord::from(universal_canister.canister_id()),),
            )
            .await;

        assert_matches!(res, Err(msg) if msg.contains(&ErrorCode::CanisterInvalidController.to_string()));

        // Now call canister_status from the controller
        let arg = universal_canister_argument_builder()
            .call_simple(
                IC_00,
                ic00::Method::CanisterStatus.to_string(),
                CallArgs::default().other_side(
                    Encode!(&CanisterIdRecord::from(universal_canister.canister_id())).unwrap(),
                ),
            )
            .build();
        let status_bytes: Vec<u8> = universal_canister
            .update_("update", bytes, arg)
            .await
            .unwrap();
        let status = Decode!(&status_bytes, CanisterStatusResult).unwrap();
        assert_eq!(status.controller(), universal_canister.canister_id().get());

        Ok(())
    })
}
