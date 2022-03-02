//! Tests were we try to reinstall/upgrade a canister with invalid wasm.

use candid::Encode;
use canister_test::Runtime;
use dfn_candid::candid;

use ic_base_types::CanisterInstallMode::{self, Reinstall, Upgrade};
use ic_nervous_system_root::{
    CanisterIdRecord, CanisterStatusResult, CanisterStatusType, ChangeNnsCanisterProposalPayload,
};
use ic_nns_handler_root::init::RootCanisterInitPayloadBuilder;
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_root_canister,
    set_up_universal_canister,
};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM_SHA256;

fn assert_is_running_universal_canister(status: &CanisterStatusResult) {
    let hash = status
        .module_hash
        .as_ref()
        .expect("This is not the universal canister: it has no wasm module.");
    assert_eq!(
        hash,
        &UNIVERSAL_CANISTER_WASM_SHA256,
        "This is not the universal canister: its wasm hash is {} instead of {}.",
        hex::encode(hash),
        hex::encode(UNIVERSAL_CANISTER_WASM_SHA256)
    );
    assert_eq!(status.status, CanisterStatusType::Running);
}

/// Test template in which we try to upgrade or reinstall an NNS canister
/// with invalid wasm. Verifies that we leave the previous one,
/// unchanged, still running.
async fn install_invalid_wasm(
    runtime: &'_ Runtime,
    mode: CanisterInstallMode,
    stop_before_installing: bool,
) {
    let root = set_up_root_canister(runtime, RootCanisterInitPayloadBuilder::new().build()).await;
    // Install the universal canister in place of the proposals canister
    let fake_proposal_canister = set_up_universal_canister(runtime).await;
    // Since it takes the id reserved for the governance canister, it can
    // impersonate it
    assert_eq!(
        fake_proposal_canister.canister_id(),
        ic_nns_constants::GOVERNANCE_CANISTER_ID
    );

    // Create some NNS canister to be owned by the root
    let universal = set_up_universal_canister(runtime).await;
    universal
        .set_controller(root.canister_id().get())
        .await
        .unwrap();

    let proposal_payload = ChangeNnsCanisterProposalPayload::new(
        stop_before_installing,
        mode,
        universal.canister_id(),
    )
    .with_wasm(b"This is not legal wasm binary.".to_vec());

    // Due to the self-call, the initial call succeeds
    assert!(
        forward_call_via_universal_canister(
            &fake_proposal_canister,
            &root,
            "change_nns_canister",
            Encode!(&proposal_payload).unwrap()
        )
        .await
    );

    // Wait for a fixpoint.
    // This is a trick to be able to be sure that the proposal execution is
    // complete: stop the handler, wait for it to be stopped, then restart it.
    root.stop_then_restart().await.unwrap();

    // The canister is still running, and it's wasm is still the one from the
    // universal canister
    let status: CanisterStatusResult = root
        .update_(
            "canister_status",
            candid,
            (CanisterIdRecord::from(universal.canister_id()),),
        )
        .await
        .unwrap();
    assert_is_running_universal_canister(&status);
}

#[test]
fn test_try_to_upgrade_to_invalid_does_nothing_reinstall_dont_stop() {
    local_test_on_nns_subnet(|runtime| async move {
        install_invalid_wasm(&runtime, Reinstall, false).await;
        Ok(())
    });
}

#[test]
fn test_try_to_upgrade_to_invalid_does_nothing_upgrade_dont_stop() {
    local_test_on_nns_subnet(|runtime| async move {
        install_invalid_wasm(&runtime, Upgrade, false).await;
        Ok(())
    });
}

#[test]
fn test_try_to_upgrade_to_invalid_does_nothing_reinstall_stop() {
    local_test_on_nns_subnet(|runtime| async move {
        install_invalid_wasm(&runtime, Reinstall, true).await;
        Ok(())
    });
}

#[test]
fn test_try_to_upgrade_to_invalid_does_nothing_upgrade_stop() {
    local_test_on_nns_subnet(|runtime| async move {
        install_invalid_wasm(&runtime, Upgrade, true).await;
        Ok(())
    });
}
