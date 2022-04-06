use assert_matches::assert_matches;
use candid::Encode;
use canister_test::{Project, Runtime};
use dfn_candid::candid;

use ic_ic00_types::CanisterInstallMode::{self, Install, Reinstall, Upgrade};
use ic_nervous_system_root::{
    CanisterIdRecord, CanisterStatusResult, CanisterStatusType::Running, ChangeCanisterProposal,
};
use ic_nns_handler_root::init::RootCanisterInitPayload;
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_root_canister,
    set_up_universal_canister,
};
use ic_test_utilities::stable_memory_reader::{
    STABLE_MEMORY_READER_SHA256, STABLE_MEMORY_READER_WASM,
};
use ic_test_utilities::universal_canister::wasm as universal_canister_argument_builder;
use on_wire::bytes;

/// A message to be store in stable memory
const MSG: &[u8] = b"Oh my, what a beautiful test";

/// Test template in which we try to reinstall or upgrade an NNS canister
/// to the canister defined by `STABLE_MEMORY_READER_WAT`.
///
/// The reinstall/upgrade should work, and we should be able to retrieve the
/// stable memory if it was an upgrade.
async fn install_stable_memory_reader(
    runtime: &'_ Runtime,
    mode: CanisterInstallMode,
    stop_before_installing: bool,
) {
    let root = set_up_root_canister(runtime, RootCanisterInitPayload {}).await;

    // Install the universal canister in place of the proposals canister
    let fake_proposal_canister = set_up_universal_canister(runtime).await;
    // Since it takes the id reserved for the proposal canister, it can impersonate
    // it
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

    // Let's record something in stable memory
    universal
        .update_(
            "update",
            bytes,
            universal_canister_argument_builder()
                .stable_grow(1)
                .stable_write(0, MSG)
                .reply()
                .build(),
        )
        .await
        .unwrap();

    let proposal =
        ChangeCanisterProposal::new(stop_before_installing, mode, universal.canister_id())
            .with_wasm(STABLE_MEMORY_READER_WASM.clone());

    // The upgrade should work
    assert!(
        forward_call_via_universal_canister(
            &fake_proposal_canister,
            &root,
            "change_nns_canister",
            Encode!(&proposal).unwrap()
        )
        .await
    );

    // Now let's wait for the upgrade to complete
    loop {
        let status: CanisterStatusResult = root
            .update_(
                "canister_status",
                candid,
                (CanisterIdRecord::from(universal.canister_id()),),
            )
            .await
            .unwrap();
        if status.module_hash.unwrap() == *STABLE_MEMORY_READER_SHA256 && status.status == Running {
            break;
        }
    }

    match mode {
        Install => panic!("There should be a test for Install"),
        Upgrade =>
        // The stable memory should have ben preserved
        {
            assert_eq!(
                universal
                    .query_("read_10_bytes_from_stable", bytes, Vec::new())
                    .await
                    .unwrap(),
                &MSG[..10],
            )
        }
        Reinstall => {
            // The stable memory should have been wiped out: trying to read it should fail
            let res: Result<Vec<u8>, String> = universal
                .query_("read_10_bytes_from_stable", bytes, Vec::new())
                .await;
            assert_matches ! (res, Err(msg) if msg.to_lowercase().contains("out of bounds"));
        }
    }
}

#[test]
fn test_upgrade_preserves_stable_memory_dont_stop() {
    local_test_on_nns_subnet(|runtime| async move {
        install_stable_memory_reader(&runtime, Upgrade, false).await;
        Ok(())
    });
}

#[test]
fn test_upgrade_preserves_stable_memory_stop() {
    local_test_on_nns_subnet(|runtime| async move {
        install_stable_memory_reader(&runtime, Upgrade, true).await;
        Ok(())
    });
}

#[test]
fn test_reinstall_loses_stable_memory_dont_stop() {
    local_test_on_nns_subnet(|runtime| async move {
        install_stable_memory_reader(&runtime, Reinstall, false).await;
        Ok(())
    });
}

#[test]
fn test_reinstall_loses_stable_memory_stop() {
    local_test_on_nns_subnet(|runtime| async move {
        install_stable_memory_reader(&runtime, Reinstall, true).await;
        Ok(())
    });
}

#[test]
fn test_init_payload_is_passed_through_upgrades() {
    let proj = Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let test_wasm = proj.cargo_bin("upgrade-test-canister", &[]).bytes();
    let test_wasm_sha256 = ic_crypto_sha::Sha256::hash(&test_wasm);
    let test_byte_array = b"just_testing";

    local_test_on_nns_subnet(move |runtime| async move {
        let root = set_up_root_canister(&runtime, RootCanisterInitPayload {}).await;

        // Install the universal canister in place of the proposals canister
        let fake_proposal_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the proposal canister, it can impersonate
        // it
        assert_eq!(
            fake_proposal_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // Create some NNS canister to be owned by the root
        let universal = set_up_universal_canister(&runtime).await;
        universal
            .set_controller(root.canister_id().get())
            .await
            .unwrap();

        let proposal = ChangeCanisterProposal::new(false, Upgrade, universal.canister_id())
            .with_wasm(test_wasm)
            .with_arg(test_byte_array.to_vec());

        // The upgrade should work
        assert!(
            forward_call_via_universal_canister(
                &fake_proposal_canister,
                &root,
                "change_nns_canister",
                Encode!(&proposal).unwrap()
            )
            .await
        );

        // Now let's wait for the upgrade to complete
        loop {
            let status: CanisterStatusResult = root
                .update_(
                    "canister_status",
                    candid,
                    (CanisterIdRecord::from(universal.canister_id()),),
                )
                .await
                .unwrap();
            if status.module_hash.unwrap() == test_wasm_sha256 && status.status == Running {
                break;
            }
        }

        assert_eq!(
            universal
                .query_("read_stable", bytes, Vec::new())
                .await
                .unwrap(),
            test_byte_array,
        );

        Ok(())
    });
}
