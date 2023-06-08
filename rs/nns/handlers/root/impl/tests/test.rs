use assert_matches::assert_matches;
use candid::Encode;
use dfn_candid::candid;
use ic_base_types::PrincipalId;
use ic_ic00_types::CanisterInstallMode::Upgrade;
use ic_nervous_system_root::{
    canister_status::CanisterStatusResult, change_canister::ChangeCanisterProposal,
    CanisterIdRecord,
};
use ic_nns_handler_root::init::RootCanisterInitPayloadBuilder;
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_root_canister,
    set_up_universal_canister,
};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use maplit::btreeset;
use std::collections::BTreeSet;

/// Verifies that an anonymous user can get the status of any NNS canister
/// through the root handler.
#[test]
fn test_get_status() {
    local_test_on_nns_subnet(|runtime| async move {
        let root =
            set_up_root_canister(&runtime, RootCanisterInitPayloadBuilder::new().build()).await;

        // Create some NNS canister to be own by the root
        let universal = set_up_universal_canister(&runtime).await;
        universal
            .set_controller(root.canister_id().get())
            .await
            .unwrap();

        // Get the status of an NNS canister
        let status: CanisterStatusResult = root
            .update_(
                "canister_status",
                candid,
                (CanisterIdRecord::from(universal.canister_id()),),
            )
            .await
            .unwrap();
        assert_eq!(status.settings.controllers, vec![root.canister_id().get()]);

        Ok(())
    });
}

/// Verifies that an anonymous user can get the status of any canister controlled by root, and
/// this supports multiple controllers.
#[test]
fn test_get_status_multiple_controllers() {
    local_test_on_nns_subnet(|runtime| async move {
        let root =
            set_up_root_canister(&runtime, RootCanisterInitPayloadBuilder::new().build()).await;
        let other_controller = PrincipalId::new_user_test_id(1000);

        // Create some NNS canister to be own by the root and another controller
        let universal = set_up_universal_canister(&runtime).await;
        universal
            .set_controllers(vec![root.canister_id().get(), other_controller])
            .await
            .unwrap();

        // Get the status of an NNS canister
        let status: CanisterStatusResult = root
            .update_(
                "canister_status",
                candid,
                (CanisterIdRecord::from(universal.canister_id()),),
            )
            .await
            .unwrap();
        let actual_controllers: BTreeSet<PrincipalId> =
            status.settings.controllers.iter().cloned().collect();
        let expected_controllers = btreeset! {other_controller, root.canister_id().get()};

        assert_eq!(actual_controllers, expected_controllers);

        Ok(())
    });
}

#[test]
fn test_the_anonymous_user_cannot_change_an_nns_canister() {
    local_test_on_nns_subnet(|runtime| async move {
        let mut root =
            set_up_root_canister(&runtime, RootCanisterInitPayloadBuilder::new().build()).await;

        // Create some NNS canister to be own by the root
        let universal = set_up_universal_canister(&runtime).await;
        universal
            .set_controller(root.canister_id().get())
            .await
            .unwrap();

        let proposal = ChangeCanisterProposal::new(false, Upgrade, universal.canister_id())
            .with_wasm(UNIVERSAL_CANISTER_WASM.to_vec());

        // The anonymous end-user tries to upgrade an NNS canister a subnet, bypassing
        // the proposals This should be rejected.
        let response: Result<(), String> = root
            .update_("change_nns_canister", candid, (proposal.clone(),))
            .await;
        assert_matches!(response,
                            Err(s) if s.contains("Only the Governance canister is allowed to call this method"));

        // Go through an upgrade cycle, and verify that it still works the same
        root.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = root
            .update_("change_nns_canister", candid, (proposal.clone(),))
            .await;
        assert_matches!(response,
                            Err(s) if s.contains("Only the Governance canister is allowed to call this method"));

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_change_an_nns_canister() {
    local_test_on_nns_subnet(|runtime| async move {
        let root =
            set_up_root_canister(&runtime, RootCanisterInitPayloadBuilder::new().build()).await;

        // Create some NNS canister to be own by the root
        let universal = set_up_universal_canister(&runtime).await;
        universal
            .set_controller(root.canister_id().get())
            .await
            .unwrap();

        // An attacker got a canister that is trying to pass for the governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );
        let proposal = ChangeCanisterProposal::new(false, Upgrade, universal.canister_id())
            .with_wasm(UNIVERSAL_CANISTER_WASM.to_vec());

        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &root,
                "change_nns_canister",
                Encode!(&proposal).unwrap()
            )
            .await
        );

        Ok(())
    });
}
