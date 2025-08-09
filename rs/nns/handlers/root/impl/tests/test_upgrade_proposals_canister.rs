use candid::Encode;
use dfn_candid::candid;
use ic_management_canister_types::CanisterInstallMode::Upgrade;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{CanisterStatusResult, CanisterStatusType::Running},
};
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_handler_root::init::RootCanisterInitPayloadBuilder;
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_root_canister,
    set_up_universal_canister,
};
use ic_test_utilities::{
    stable_memory_reader::{STABLE_MEMORY_READER_SHA256, STABLE_MEMORY_READER_WASM},
    universal_canister::wasm as universal_canister_argument_builder,
};
use on_wire::bytes;

/// A message to be store in stable memory
const MSG: &[u8] = b"yeah NNS !";

/// Tests that the root can upgrade the governance canister. The reason it
/// deserves a special test is because the governance canister plays here
/// 2 roles simultaneously:
/// - it calls the `change_nns_canister` method
/// - it's the canister that must be upgraded by `change_nns_canister`
///
/// Hence this test verifies that the process works even in the presence of
/// this loop.
#[test]
fn test_upgrade_governance_canister() {
    local_test_on_nns_subnet(|runtime| async move {
        let root =
            set_up_root_canister(&runtime, RootCanisterInitPayloadBuilder::new().build()).await;

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can impersonate
        // it
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );
        fake_governance_canister
            .set_controller(root.canister_id().get())
            .await
            .unwrap();

        // Let's record something in stable memory
        fake_governance_canister
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

        let change_canister_request =
            ChangeCanisterRequest::new(true, Upgrade, fake_governance_canister.canister_id())
                .with_wasm(STABLE_MEMORY_READER_WASM.clone());

        // The upgrade should work
        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &root,
                "change_nns_canister",
                Encode!(&change_canister_request).unwrap(),
            )
            .await
        );

        // Now let's wait for the upgrade to complete
        loop {
            let status: CanisterStatusResult = root
                .update_(
                    "canister_status",
                    candid,
                    (CanisterIdRecord::from(
                        fake_governance_canister.canister_id(),
                    ),),
                )
                .await
                .unwrap();
            if status.module_hash.unwrap() == *STABLE_MEMORY_READER_SHA256
                && status.status == Running
            {
                break;
            }
        }

        // The stable memory should have ben preserved
        assert_eq!(
            fake_governance_canister
                .query_("read_10_bytes_from_stable", bytes, Vec::new())
                .await
                .unwrap(),
            &MSG[..10],
        );
        Ok(())
    });
}
