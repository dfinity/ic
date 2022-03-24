use dfn_candid::candid;

use ic_base_types::PrincipalId;
use ic_nervous_system_root::{CanisterIdRecord, CanisterStatusResult, CanisterStatusType};
use ic_sns_root::pb::v1::SnsRootCanister;
use ic_sns_test_utils::itest_helpers::{local_test_on_sns_subnet, set_up_root_canister};

#[test]
fn test_get_status() {
    local_test_on_sns_subnet(|runtime| async move {
        // Step 1: Prepare: Create root canister.
        let root = set_up_root_canister(
            &runtime,
            SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(42)),
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
