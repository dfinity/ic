use super::*;
use candid_parser::utils::{service_equal, CandidSource};
use ic_nervous_system_clients::{
    canister_status::{
        CanisterStatusResultFromManagementCanister, CanisterStatusResultV2, CanisterStatusType,
        DefiniteCanisterSettingsArgs, DefiniteCanisterSettingsFromManagementCanister,
        LogVisibility,
    },
    management_canister_client::{MockManagementCanisterClient, MockManagementCanisterClientReply},
};

/// This is NOT affected by
///
///   1. comments (in ./registry.did)
///   2. whitespace
///   3. order of type definitions
///   4. names of types
///   5. etc.
///
/// Whereas, this test fails in the following cases
///
///   1. extra (or missing) fields
///   2. differences in field names
///   3. etc.
///
/// If this test passes, that does NOT mean that the API has evolved safely;
/// there is a different test for that (namely,
/// candid_changes_are_backwards_compatible). This test does not compare the
/// current working copy against master. Rather, it only compares ./canister.rs
/// to swap.did.
#[test]
fn test_implemented_interface_matches_declared_interface_exactly() {
    let declared_interface = CandidSource::Text(include_str!("swap.did"));

    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    let implemented_interface_str = __export_service();
    let implemented_interface = CandidSource::Text(&implemented_interface_str);

    let result = service_equal(declared_interface, implemented_interface);
    assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
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
