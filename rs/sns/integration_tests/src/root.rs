use dfn_candid::{candid, candid_one};

use ic_base_types::PrincipalId;
use ic_nervous_system_root::{CanisterIdRecord, CanisterStatusResult, CanisterStatusType};
use ic_sns_root::pb::v1::{
    RegisterDappCanisterRequest, RegisterDappCanisterResponse, SnsRootCanister,
};
use ic_sns_swap::pb::v1::Init;
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, set_up_root_canister, set_up_swap_canister, SnsCanisters,
    SnsTestsInitPayloadBuilder,
};

#[test]
fn test_get_status() {
    local_test_on_sns_subnet(|runtime| async move {
        // Step 1: Prepare: Create root canister.
        let root = set_up_root_canister(
            &runtime,
            SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(42)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(43)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(44)),
                dapp_canister_ids: vec![],
            },
        )
        .await;

        // To get the status of a canister A from canister B, B must control A.
        // In this case, we only have one canister, root. So we make it play
        // both roles by making it a controller of itself.
        root.set_controller_with_retries(root.canister_id().get())
            .await
            .unwrap();

        // Step 2: Execute: Send canister_status request.
        let response: CanisterStatusResult = root
            .update_(
                "canister_status",
                candid,
                (CanisterIdRecord::from(root.canister_id()),),
            )
            .await
            .unwrap();

        // Step 3: Inspect the response. We're not looking for anything in
        // particular, but since root has replied, it must be in the running
        // state, so we might as well assert that the response reflects this.
        assert_eq!(
            response.status,
            CanisterStatusType::Running,
            "response: {:?}",
            response
        );

        Ok(())
    });
}

#[test]
fn test_get_sns_canisters_summary() {
    local_test_on_sns_subnet(|runtime| async move {
        // Create and setup a basic SNS
        let sns_init_payload = SnsTestsInitPayloadBuilder::new().build();
        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Get the status of the SNS using get_sns_canisters_summary
        let response = sns_canisters.get_sns_canisters_summary().await;

        // Assert that all the canisters returned a canister summary
        assert!(response.root.is_some());
        assert!(response.governance.is_some());
        assert!(response.ledger.is_some());
        assert!(response.swap.is_some());

        // Assert that the canister_ids match what was set up
        assert_eq!(
            response.root_canister_summary().canister_id(),
            sns_canisters.root.canister_id().get()
        );
        assert_eq!(
            response.governance_canister_summary().canister_id(),
            sns_canisters.governance.canister_id().get()
        );
        assert_eq!(
            response.ledger_canister_summary().canister_id(),
            sns_canisters.ledger.canister_id().get()
        );
        assert_eq!(
            response.swap_canister_summary().canister_id(),
            sns_canisters.swap.canister_id().get()
        );

        // Create a random dapp canister to register with root. Use the swap canister for this purpose
        let dapp_canister = set_up_swap_canister(&runtime, Init::default()).await;
        dapp_canister
            .set_controller_with_retries(sns_canisters.root.canister_id().get())
            .await
            .expect("Error setting the controller of the dapp_canister");

        // Register the dapp canister with root
        let _response: RegisterDappCanisterResponse = sns_canisters
            .root
            .update_(
                "register_dapp_canister",
                candid_one,
                RegisterDappCanisterRequest {
                    canister_id: Some(dapp_canister.canister_id().get()),
                },
            )
            .await
            .expect("Error calling the register_dapp_canister API");

        // Get the status of the SNS using get_sns_canisters_summary
        let response = sns_canisters.get_sns_canisters_summary().await;

        // Assert that the newly registered dapp is present in the response and that it's canister
        // id matches
        assert!(!response.dapps.is_empty());
        assert_eq!(
            response.dapps[0].canister_id(),
            dapp_canister.canister_id().get()
        );

        // The API needs to respond with statuses even if the swap canister is stopped due to the
        // swap completing.
        sns_canisters
            .swap
            .stop()
            .await
            .expect("Expected the Swap canister to stop");

        // Get the status of the SNS using get_sns_canisters_summary
        let response = sns_canisters.get_sns_canisters_summary().await;
        assert!(response.swap.is_some());
        assert!(response.swap_canister_summary().status.is_none());
        assert_eq!(
            response.swap_canister_summary().canister_id(),
            sns_canisters.swap.canister_id().get()
        );

        Ok(())
    });
}
