use super::*;
use ic_nervous_system_clients::{
    canister_status::{
        CanisterStatusResultFromManagementCanister, CanisterStatusResultV2, CanisterStatusType,
        DefiniteCanisterSettingsArgs, DefiniteCanisterSettingsFromManagementCanister,
        LogVisibility,
    },
    management_canister_client::{MockManagementCanisterClient, MockManagementCanisterClientReply},
};

/// A test that fails if the API was updated but the candid definition was not.
#[test]
fn check_swap_candid_file() {
    let did_path = format!(
        "{}/canister/swap.did",
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set")
    );
    let did_contents = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if did_contents != expected {
        panic!(
            "Generated candid definition does not match canister/swap.did. \
             Run `bazel run :generate_did > canister/swap.did` (no nix and/or direnv) or \
             `cargo run --bin sns-swap-canister > canister/swap.did` in \
             rs/sns/swap to update canister/swap.did."
        )
    }
}

#[tokio::test]
async fn test_get_canister_status() {
    let expected_canister_status_result = CanisterStatusResultV2 {
        status: CanisterStatusType::Running,
        module_hash: Some(vec![0_u8]),
        settings: DefiniteCanisterSettingsArgs {
            controllers: vec![PrincipalId::new_user_test_id(0)],
            compute_allocation: candid::Nat::from(0_u32),
            memory_allocation: candid::Nat::from(0_u32),
            freezing_threshold: candid::Nat::from(0_u32),
            wasm_memory_limit: Some(candid::Nat::from(0_u32)),
        },
        memory_size: candid::Nat::from(0_u32),
        cycles: candid::Nat::from(0_u32),
        idle_cycles_burned_per_day: candid::Nat::from(0_u32),
    };

    let management_canister_client =
        MockManagementCanisterClient::new(vec![MockManagementCanisterClientReply::CanisterStatus(
            Ok(CanisterStatusResultFromManagementCanister {
                status: CanisterStatusType::Running,
                module_hash: Some(vec![0_u8]),
                memory_size: candid::Nat::from(0_u32),
                settings: DefiniteCanisterSettingsFromManagementCanister {
                    controllers: vec![PrincipalId::new_user_test_id(0_u64)],
                    compute_allocation: candid::Nat::from(0_u32),
                    memory_allocation: candid::Nat::from(0_u32),
                    freezing_threshold: candid::Nat::from(0_u32),
                    reserved_cycles_limit: candid::Nat::from(0_u32),
                    wasm_memory_limit: candid::Nat::from(0_u32),
                    log_visibility: LogVisibility::Controllers,
                },
                cycles: candid::Nat::from(0_u32),
                idle_cycles_burned_per_day: candid::Nat::from(0_u32),
                reserved_cycles: candid::Nat::from(0_u32),
            }),
        )]);

    let actual_canister_status_result =
        do_get_canister_status(CanisterId::from_u64(1), &management_canister_client).await;
    assert_eq!(
        actual_canister_status_result,
        expected_canister_status_result
    );
}
